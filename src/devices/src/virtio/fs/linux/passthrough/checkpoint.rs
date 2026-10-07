// SPDX-License-Identifier: Apache-2.0
//! Rebuild host file descriptors while retaining guest inode and handle numbers.

use super::*;
use serde::{Deserialize, Serialize};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct DirectoryEntry {
    pub inode: u64,
    pub kind: u32,
    pub name: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct SavedInode {
    inode: u64,
    guest_ino: u64,
    location: InodeLocation,
    kind: u32,
    refcount: u64,
}

#[derive(Serialize, Deserialize)]
enum InodeLocation {
    Path(Vec<u8>),
    Unlinked {
        length: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        atime: (i64, i64),
        mtime: (i64, i64),
        xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    },
}

#[derive(Serialize, Deserialize)]
struct SavedHandle {
    handle: u64,
    inode: u64,
    flags: i32,
    directory: Option<Vec<DirectoryEntry>>,
}

#[derive(Serialize, Deserialize)]
pub struct FilesystemState {
    inodes: Vec<SavedInode>,
    handles: Vec<SavedHandle>,
    next_inode: u64,
    next_handle: u64,
    writeback: bool,
    announce_submounts: bool,
    supplementary_group_extension: bool,
}

fn pinned_path(file: &File) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

// A saved pathname must stay below the pinned root even when intermediate path
// components are symlinks. The final symlink is an inode, never followed here.
fn open_beneath(root: &File, path: &[u8]) -> io::Result<File> {
    let relative = PathBuf::from(std::ffi::OsString::from_vec(path.to_vec()));
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err(io::Error::other(
            "checkpoint inode path escapes filesystem root",
        ));
    }
    let path = CString::new(if path.is_empty() { b"." } else { path }).map_err(|_| einval())?;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: 0x08 | 0x02, // RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS
    };
    // SAFETY: pointers are valid for their specified sizes and the returned fd
    // is checked before transferring its ownership to File.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

impl PassthroughFs {
    /// Call only after the filesystem worker has joined at its pause boundary.
    pub fn capture_state(&self, directory: &Path) -> io::Result<FilesystemState> {
        if self.dax_used.load(Ordering::Relaxed) {
            return Err(io::Error::other(
                "filesystem has used DAX mappings; checkpoint is unsupported",
            ));
        }
        let inodes = self.inodes.read().unwrap();
        let root = inodes.get(&fuse::ROOT_ID).ok_or_else(ebadf)?;
        let root_path = pinned_path(&root.file)?;
        let mut saved_inodes = Vec::new();
        for inode in inodes.values() {
            // FUSE may retain the pre-unlink attribute cache even though the
            // pinned dentry is already deleted. Capture needs authoritative
            // link counts to preserve open unlinked files as sidecar payloads.
            let (source, source_mount) = statx_with_flags(&inode.file, libc::AT_STATX_FORCE_SYNC)?;
            let location = (|| -> io::Result<InodeLocation> {
                Ok(if source.st_nlink == 0 {
                    let kind = source.st_mode & libc::S_IFMT;
                    if kind != libc::S_IFREG && kind != libc::S_IFDIR {
                        return Err(io::Error::other(
                            "checkpoint only supports regular files and directories after unlink",
                        ));
                    }
                    let mut input = self.open_inode(inode.inode, libc::O_RDONLY)?;
                    let length = if kind == libc::S_IFREG {
                        let mut output = std::fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(directory.join(format!("unlinked-{}", inode.inode)))?;
                        let length = io::copy(&mut input, &mut output)?;
                        if length != source.st_size as u64 {
                            return Err(io::Error::other("unlinked file changed during capture"));
                        }
                        output.set_permissions(std::fs::Permissions::from_mode(0o400))?;
                        output.sync_all()?;
                        length
                    } else {
                        0
                    };
                    let attr = stat(&inode.file, self.my_uid, self.my_gid)?;
                    let mut xattrs = Vec::new();
                    for name in list_host_xattrs(&FileOrLink::File(inode.file.try_clone()?))?
                        .split(|byte| *byte == 0)
                        .filter(|name| !name.is_empty())
                    {
                        let name_c = CString::new(name).map_err(|_| einval())?;
                        let size = unsafe {
                            libc::fgetxattr(
                                input.as_raw_fd(),
                                name_c.as_ptr(),
                                std::ptr::null_mut(),
                                0,
                            )
                        };
                        if size < 0 {
                            return Err(io::Error::last_os_error());
                        }
                        let mut value = vec![0u8; size as usize];
                        let copied = unsafe {
                            libc::fgetxattr(
                                input.as_raw_fd(),
                                name_c.as_ptr(),
                                value.as_mut_ptr().cast(),
                                value.len(),
                            )
                        };
                        if copied != size {
                            return Err(io::Error::other(
                                "unlinked file xattr changed during capture",
                            ));
                        }
                        xattrs.push((name.to_vec(), value));
                    }
                    InodeLocation::Unlinked {
                        length,
                        uid: attr.st_uid,
                        gid: attr.st_gid,
                        mode: attr.st_mode,
                        atime: (attr.st_atime, attr.st_atime_nsec),
                        mtime: (attr.st_mtime, attr.st_mtime_nsec),
                        xattrs,
                    }
                } else {
                    let path = pinned_path(&inode.file)?;
                    let relative = path.strip_prefix(&root_path).map_err(|_| {
                        io::Error::other("checkpoint inode is outside filesystem root")
                    })?;
                    let file = open_beneath(&root.file, relative.as_os_str().as_bytes())?;
                    let (reopened, mount) = statx(&file)?;
                    if (source.st_ino, source.st_dev, source_mount)
                        != (reopened.st_ino, reopened.st_dev, mount)
                    {
                        return Err(io::Error::other(
                            "filesystem changed during checkpoint capture",
                        ));
                    }
                    InodeLocation::Path(relative.as_os_str().as_bytes().to_vec())
                })
            })()
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "capture inode {} (links {}, path {:?}): {error}",
                        inode.inode,
                        source.st_nlink,
                        pinned_path(&inode.file)
                    ),
                )
            })?;
            saved_inodes.push(SavedInode {
                inode: inode.inode,
                guest_ino: inode.guest_ino,
                location,
                kind: source.st_mode & libc::S_IFMT,
                refcount: inode.refcount.load(Ordering::Relaxed),
            });
        }
        let mut handles = Vec::new();
        for (&handle, data) in self.handles.read().unwrap().iter() {
            if data.exported.load(Ordering::Relaxed) {
                return Err(io::Error::other(
                    "exported filesystem handles cannot be checkpointed",
                ));
            }
            let file = data.file.read().unwrap();
            let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            handles.push(SavedHandle {
                handle,
                inode: data.inode,
                flags,
                directory: data.directory.read().unwrap().clone(),
            });
        }
        Ok(FilesystemState {
            inodes: saved_inodes,
            handles,
            next_inode: self.next_inode.load(Ordering::Relaxed),
            next_handle: self.next_handle.load(Ordering::Relaxed),
            writeback: self.writeback.load(Ordering::Relaxed),
            announce_submounts: self.announce_submounts.load(Ordering::Relaxed),
            supplementary_group_extension: self
                .supplementary_group_extension
                .load(Ordering::Relaxed),
        })
    }

    /// Restore into a newly constructed backend; never overlay a live filesystem.
    pub fn restore_state(&self, state: FilesystemState, directory: &Path) -> io::Result<()> {
        if self.inodes.read().unwrap().values().next().is_some()
            || !self.handles.read().unwrap().is_empty()
        {
            return Err(io::Error::other(
                "filesystem restore requires a fresh backend",
            ));
        }
        let root = std::fs::OpenOptions::new()
            .read(true)
            .open(Path::new(&self.cfg.root_dir))?;
        let mut inodes = MultikeyBTreeMap::new();
        // O_PATH pins a kernel dentry but does not issue FUSE_OPEN. Keep a real
        // open reference until guest handles have been reopened; otherwise a
        // FUSE server may reclaim the unlinked inode when `output` closes.
        let mut unlinked_files = Vec::new();
        for saved in state.inodes {
            if saved.inode == 0
                || saved.inode >= state.next_inode
                || inodes.get(&saved.inode).is_some()
            {
                return Err(io::Error::other("invalid checkpoint inode identity"));
            }
            let file = match &saved.location {
                InodeLocation::Path(path) => open_beneath(&root, path)?,
                InodeLocation::Unlinked {
                    length,
                    uid,
                    gid,
                    mode,
                    atime,
                    mtime,
                    xattrs,
                } => {
                    let is_directory = saved.kind == libc::S_IFDIR;
                    let temporary = format!(".krun-restore-{}-{}", std::process::id(), saved.inode);
                    let path = Path::new(&self.cfg.root_dir).join(&temporary);
                    let mut output = if is_directory {
                        use std::os::unix::fs::DirBuilderExt;
                        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
                        File::open(&path)?
                    } else {
                        std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .create_new(true)
                            .mode(0o600)
                            .open(&path)?
                    };
                    let pinned = open_beneath(&root, temporary.as_bytes())?;
                    if is_directory {
                        std::fs::remove_dir(&path)?;
                    } else {
                        std::fs::remove_file(&path)?;
                    }
                    if !is_directory {
                        let mut input = std::fs::OpenOptions::new()
                            .read(true)
                            .custom_flags(libc::O_NOFOLLOW)
                            .open(directory.join(format!("unlinked-{}", saved.inode)))?;
                        if input.metadata()?.len() != *length {
                            return Err(io::Error::other("unlinked file payload length differs"));
                        }
                        if io::copy(&mut input, &mut output)? != *length {
                            return Err(io::Error::other("unlinked payload copy was incomplete"));
                        }
                    }
                    for (name, value) in xattrs {
                        let name = CString::new(name.as_slice()).map_err(|_| einval())?;
                        if unsafe {
                            libc::fsetxattr(
                                output.as_raw_fd(),
                                name.as_ptr(),
                                value.as_ptr().cast(),
                                value.len(),
                                0,
                            )
                        } < 0
                        {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    set_override_xattr(
                        output.as_raw_fd(),
                        Some((*uid, *gid)),
                        Some(*mode & 0o7777),
                    )?;
                    let times = [
                        libc::timespec {
                            tv_sec: atime.0,
                            tv_nsec: atime.1,
                        },
                        libc::timespec {
                            tv_sec: mtime.0,
                            tv_nsec: mtime.1,
                        },
                    ];
                    if unsafe { libc::futimens(output.as_raw_fd(), times.as_ptr()) } < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    unlinked_files.push(output);
                    pinned
                }
            };
            let (st, mnt_id) = statx(&file)?;
            if st.st_mode & libc::S_IFMT != saved.kind {
                return Err(io::Error::other("checkpoint filesystem inode type changed"));
            }
            let alt = InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
                mnt_id,
            };
            if inodes.get_alt(&alt).is_some() {
                return Err(io::Error::other(
                    "checkpoint maps two guest inodes to one host inode",
                ));
            }
            inodes.insert(
                saved.inode,
                alt,
                Arc::new(InodeData {
                    inode: saved.inode,
                    guest_ino: saved.guest_ino,
                    file,
                    dev: st.st_dev,
                    mnt_id,
                    refcount: AtomicU64::new(saved.refcount),
                }),
            );
        }
        if inodes.get(&fuse::ROOT_ID).is_none() {
            return Err(io::Error::other("checkpoint filesystem root is missing"));
        }
        *self.inodes.write().unwrap() = inodes;
        self.writeback.store(state.writeback, Ordering::Relaxed);
        let mut handles = BTreeMap::new();
        for saved in state.handles {
            if saved.handle == self.init_handle
                || saved.handle >= state.next_handle
                || handles.contains_key(&saved.handle)
            {
                return Err(io::Error::other("invalid checkpoint handle identity"));
            }
            // F_GETFL does not return creation flags, but reject them explicitly
            // so a malformed snapshot cannot truncate a restored file.
            if saved.flags
                & (libc::O_CREAT
                    | libc::O_TRUNC
                    | libc::O_EXCL
                    | (libc::O_TMPFILE & !libc::O_DIRECTORY))
                != 0
            {
                return Err(io::Error::other("destructive open flags in checkpoint"));
            }
            let file = self.open_inode(saved.inode, saved.flags)?;
            handles.insert(
                saved.handle,
                Arc::new(HandleData {
                    inode: saved.inode,
                    file: RwLock::new(file),
                    exported: AtomicBool::new(false),
                    directory: RwLock::new(saved.directory),
                }),
            );
        }
        *self.handles.write().unwrap() = handles;
        self.next_inode.store(state.next_inode, Ordering::Relaxed);
        self.next_handle.store(state.next_handle, Ordering::Relaxed);
        self.announce_submounts
            .store(state.announce_submounts, Ordering::Relaxed);
        self.supplementary_group_extension
            .store(state.supplementary_group_extension, Ordering::Relaxed);
        Ok(())
    }
}

pub(crate) fn read_directory(file: &File) -> io::Result<Vec<DirectoryEntry>> {
    if unsafe { libc::lseek64(file.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut entries = Vec::new();
    let mut bytes = 0usize;
    let mut buffer = vec![0u8; 32768];
    loop {
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                file.as_raw_fd(),
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count == 0 {
            break;
        }
        let mut remaining = &buffer[..count as usize];
        while !remaining.is_empty() {
            if remaining.len() < size_of::<LinuxDirent64>() {
                return Err(einval());
            }
            let (header, tail) = remaining.split_at(size_of::<LinuxDirent64>());
            let entry = LinuxDirent64::from_slice(header).ok_or_else(einval)?;
            let length = entry.d_reclen as usize;
            if length <= header.len() || length > remaining.len() {
                return Err(einval());
            }
            let name = &tail[..length - header.len()];
            let end = name.iter().position(|b| *b == 0).ok_or_else(einval)?;
            let name = &name[..end];
            if name != b"." && name != b".." {
                bytes += name.len() + size_of::<DirectoryEntry>();
                if bytes > 16 * 1024 * 1024 {
                    return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
                }
                entries.push(DirectoryEntry {
                    inode: entry.d_ino,
                    kind: u32::from(entry.d_ty),
                    name: name.to_vec(),
                });
            }
            remaining = &remaining[length..];
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn renamed_open_file_and_directory_survive_backend_replacement() {
        let base = std::env::temp_dir().join(format!("krun-fs-checkpoint-{}", std::process::id()));
        let source = base.join("source");
        let target = base.join("target");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(source.join("before"), b"initialized state").unwrap();
        std::fs::write(source.join("second"), b"second").unwrap();
        let fs = PassthroughFs::new(Config {
            root_dir: source.to_str().unwrap().into(),
            checkpoint_enabled: true,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let inode = fs.do_lookup(fuse::ROOT_ID, c"before").unwrap().inode;
        let original_ino = fs.do_getattr(inode).unwrap().0.st_ino;
        let (handle, _) = fs.do_open(inode, false, libc::O_RDONLY as u32).unwrap();
        let handle = handle.unwrap();
        let (directory, _) = fs
            .do_open(fuse::ROOT_ID, false, libc::O_DIRECTORY as u32)
            .unwrap();
        let directory = directory.unwrap();
        let mut first_name = Vec::new();
        fs.do_readdir(fuse::ROOT_ID, directory, 4096, 0, |entry| {
            if first_name.is_empty() {
                first_name = entry.name.to_vec();
                Ok(1)
            } else {
                Ok(0)
            }
        })
        .unwrap();
        std::fs::rename(source.join("before"), source.join("after")).unwrap();
        let payloads = base.join("payloads");
        std::fs::create_dir(&payloads).unwrap();
        let state = fs.capture_state(&payloads).unwrap();
        std::fs::copy(source.join("after"), target.join("after")).unwrap();
        std::fs::copy(source.join("second"), target.join("second")).unwrap();
        drop(fs);
        std::fs::remove_dir_all(&source).unwrap();

        let restored = PassthroughFs::new(Config {
            root_dir: target.to_str().unwrap().into(),
            checkpoint_enabled: true,
            ..Config::default()
        })
        .unwrap();
        restored.restore_state(state, &payloads).unwrap();
        let mut body = String::new();
        restored
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .unwrap()
            .file
            .write()
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert_eq!(body, "initialized state");
        assert_eq!(restored.do_getattr(inode).unwrap().0.st_ino, original_ino);
        assert_eq!(
            restored
                .do_lookup(fuse::ROOT_ID, c"after")
                .unwrap()
                .attr
                .st_ino,
            original_ino
        );
        let mut remaining = Vec::new();
        restored
            .do_readdir(fuse::ROOT_ID, directory, 4096, 1, |entry| {
                remaining.push(entry.name.to_vec());
                Ok(1)
            })
            .unwrap();
        assert_eq!(remaining.len(), 1);
        assert_ne!(remaining[0], first_name);
        assert_eq!(
            restored.do_lookup(fuse::ROOT_ID, c"after").unwrap().inode,
            inode
        );
        drop(restored);
        std::fs::remove_dir_all(base).unwrap();
    }
}
