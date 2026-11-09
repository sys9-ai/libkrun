// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::collections::btree_map;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::{self, size_of, MaybeUninit};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use super::fd_budget::{FdBudget, FdPermit, GuestFile};
use std::time::Duration;

use caps::{has_cap, CapSet, Capability};
use nix::{request_code_none, request_code_read};

use vm_memory::ByteValued;

use super::super::filesystem::{
    Context, DirEntry, Entry, ExportTable, Extensions, FileSystem, FsOptions, GetxattrReply,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::super::fuse;
use super::super::multikey::MultikeyBTreeMap;

const EMPTY_CSTR: &[u8] = b"\0";
const PROC_CSTR: &[u8] = b"/proc/self/fd\0";
const INIT_CSTR: &[u8] = b"init.krun\0";
const XATTR_KEY: &[u8] = b"user.containers.override_stat\0";
const SPECIAL_XATTR_KEY: &[u8] = b"system.containers.override_stat\0";
const GUEST_XATTR_PREFIX: &[u8] = b"user.containers.guest_xattr.";
const UID_MAX: u32 = u32::MAX - 1;

static INIT_BINARY: &[u8] = include_bytes!(env!("KRUN_INIT_BINARY_PATH"));

pub mod checkpoint;
#[cfg(test)]
mod fd_budget_tests;

type Inode = u64;
type Handle = u64;

#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq)]
struct InodeAltKey {
    ino: libc::ino64_t,
    dev: libc::dev_t,
    mnt_id: u64,
}

struct InodeData {
    inode: Inode,
    // Guest stat identity survives reopening on a different host filesystem.
    guest_ino: u64,
    // Most of these aren't actually files but ¯\_(ツ)_/¯.
    file: GuestFile,
    dev: u64,
    mnt_id: u64,
    refcount: AtomicU64,
    // Used only when `Config::cache_guest_metadata` declares this server the
    // only writer of the override xattr (guest xattr names are remapped). One
    // read per inode then replaces a host getxattr on every lookup, getattr
    // and create.
    override_stat: Mutex<Option<OverrideStat>>,
}

impl InodeData {
    fn cached_override_stat(&self) -> io::Result<OverrideStat> {
        let mut cached = self.override_stat.lock().unwrap();
        if let Some(value) = *cached {
            return Ok(value);
        }
        let value = read_override_stat(self.file.as_raw_fd())?;
        *cached = Some(value);
        Ok(value)
    }

    fn set_cached_override_stat(
        &self,
        owner: Option<(u32, u32)>,
        mode: Option<u32>,
    ) -> io::Result<()> {
        let mut cached = self.override_stat.lock().unwrap();
        let current = match *cached {
            Some(value) => value,
            None => read_override_stat_for_update(self.file.as_raw_fd(), owner, mode)?,
        };
        *cached = Some(write_override_stat(
            self.file.as_raw_fd(),
            owner,
            mode,
            current,
        )?);
        Ok(())
    }
}

struct HandleData {
    inode: Inode,
    file: RwLock<GuestFile>,
    exported: Mutex<Option<FdPermit>>,
    directory: RwLock<Option<Vec<checkpoint::DirectoryEntry>>>,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Debug, Default)]
struct LinuxDirent64 {
    d_ino: libc::ino64_t,
    d_off: libc::off64_t,
    d_reclen: libc::c_ushort,
    d_ty: libc::c_uchar,
}
unsafe impl ByteValued for LinuxDirent64 {}

#[must_use]
pub struct ScopedCaps {
    cap: Capability,
}

impl ScopedCaps {
    fn new(cap: Capability) -> io::Result<Option<Self>> {
        if has_cap(None, CapSet::Effective, cap).map_err(|e| {
            error!("couldn't check {cap:?} capability: {e}");
            einval()
        })? {
            caps::drop(None, CapSet::Effective, cap).map_err(|e| {
                error!("couldn't drop {cap:?} capability: {e}");
                einval()
            })?;
            Ok(Some(Self { cap }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::FromRawFd;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn stat_with_owner(uid: libc::uid_t, gid: libc::gid_t, mode: libc::mode_t) -> libc::stat64 {
        let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };
        st.st_uid = uid;
        st.st_gid = gid;
        st.st_mode = libc::S_IFREG | mode;
        st
    }

    #[test]
    fn override_stat_maps_host_owner_to_guest_root_by_default() {
        let st = stat_with_owner(1000, 1000, 0o644);

        let got = apply_override_stat(st, None, None, None, Some(1000), Some(1000));

        assert_eq!(got.st_uid, 0);
        assert_eq!(got.st_gid, 0);
        assert_eq!(got.st_mode & 0o777, 0o644);
    }

    #[test]
    fn override_stat_uses_xattr_owner_and_octal_mode() {
        let st = stat_with_owner(1000, 1000, 0o644);

        let got = apply_override_stat(st, Some(33), Some(44), Some(0o755), Some(1000), Some(1000));

        assert_eq!(got.st_uid, 33);
        assert_eq!(got.st_gid, 44);
        assert_eq!(got.st_mode & libc::S_IFMT, libc::S_IFREG);
        assert_eq!(got.st_mode & 0o777, 0o755);
    }

    #[test]
    fn writeback_reports_a_ctime_delayed_by_write_back_as_mtime() {
        let mut st = stat_with_owner(0, 0, 0o644);
        (st.st_mtime, st.st_mtime_nsec) = (100, 973_605_846);
        (st.st_ctime, st.st_ctime_nsec) = (101, 161_242_772);

        let got = writeback_ctime(st);

        assert_eq!((got.st_ctime, got.st_ctime_nsec), (100, 973_605_846));
    }

    #[test]
    fn writeback_keeps_a_ctime_beyond_the_slack_or_before_mtime() {
        let mut changed_later = stat_with_owner(0, 0, 0o644);
        (changed_later.st_mtime, changed_later.st_ctime) = (100, 161);
        let mut mtime_in_future = stat_with_owner(0, 0, 0o644);
        (mtime_in_future.st_mtime, mtime_in_future.st_ctime) = (200, 100);

        assert_eq!(writeback_ctime(changed_later).st_ctime, 161);
        assert_eq!(writeback_ctime(mtime_in_future).st_ctime, 100);
    }

    #[test]
    fn writeback_keeps_a_directory_ctime() {
        let mut st = stat_with_owner(0, 0, 0o755);
        st.st_mode = libc::S_IFDIR | 0o755;
        (st.st_mtime, st.st_ctime) = (100, 101);

        assert_eq!(writeback_ctime(st).st_ctime, 101);
    }

    #[test]
    fn writeback_share_reports_the_ctime_the_guest_assigned() {
        let dir = unique_tmp_dir("writeback-ctime");
        // As after a guest write-back: the mtime is the guest's, and the host
        // stamps the ctime when it applies it.
        let file = File::create(dir.join("file")).unwrap();
        file.set_modified(SystemTime::now() - Duration::from_secs(1))
            .unwrap();
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            writeback: true,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::WRITEBACK_CACHE).unwrap();

        let attr = fs.lookup(root_ctx(), fuse::ROOT_ID, c"file").unwrap().attr;

        assert_eq!(
            (attr.st_ctime, attr.st_ctime_nsec),
            (attr.st_mtime, attr.st_mtime_nsec)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn override_xattr_parser_reads_mode_as_octal() {
        let (uid, gid, mode) = get_xattr_common(b"0:0:0755");

        assert_eq!(uid, Some(0));
        assert_eq!(gid, Some(0));
        assert_eq!(mode, Some(0o755));
    }

    #[test]
    fn override_xattr_mode_update_keeps_existing_owner() {
        let dir = unique_tmp_dir("override-mode-keeps-owner");
        let path = dir.join("file");
        let file = File::create(&path).unwrap();

        set_override_xattr(file.as_raw_fd(), Some((33, 44)), None).unwrap();
        set_override_xattr(file.as_raw_fd(), None, Some(0o4755)).unwrap();
        let (uid, gid, mode) = get_override_xattr(file.as_raw_fd()).unwrap();

        assert_eq!(uid, Some(33));
        assert_eq!(gid, Some(44));
        assert_eq!(mode, Some(0o4755));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn override_xattr_stores_inherited_setgid_metadata() {
        let dir = unique_tmp_dir("override-setgid-metadata");
        let file = File::open(&dir).unwrap();

        set_override_xattr(file.as_raw_fd(), Some((1000, 2000)), Some(0o2750)).unwrap();
        let (uid, gid, mode) = get_override_xattr(file.as_raw_fd()).unwrap();

        assert_eq!(uid, Some(1000));
        assert_eq!(gid, Some(2000));
        assert_eq!(mode, Some(0o2750));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn clear_suid_sgid_removes_only_setid_bits() {
        assert_eq!(clear_suid_sgid(0o6755), 0o0755);
        assert_eq!(
            clear_suid_sgid(libc::S_IFREG | 0o6755),
            libc::S_IFREG | 0o0755
        );
        assert_eq!(
            clear_suid_sgid(libc::S_IFDIR | 0o1777),
            libc::S_IFDIR | 0o1777
        );
    }

    #[test]
    fn setattr_mode_fallback_is_limited_to_metadata_backend_errors() {
        assert!(should_store_override_stat_for_setattr_error(
            &io::Error::from_raw_os_error(libc::EINVAL)
        ));
        assert!(should_store_override_stat_for_setattr_error(
            &io::Error::from_raw_os_error(libc::EPERM)
        ));
        assert!(should_store_override_stat_for_setattr_error(
            &io::Error::from_raw_os_error(libc::ENOTSUP)
        ));
        assert!(!should_store_override_stat_for_setattr_error(
            &io::Error::from_raw_os_error(libc::ENOENT)
        ));
        assert!(!should_store_override_stat_for_setattr_error(
            &io::Error::from_raw_os_error(libc::EIO)
        ));
    }

    #[test]
    fn create_existing_file_preserves_owner_and_mode() {
        let dir = unique_tmp_dir("create-existing");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let (first, _, _) = fs
            .create(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                fuse::ROOT_ID,
                c"file",
                0o600,
                false,
                libc::O_RDWR as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let (existing, _, _) = fs
            .create(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                fuse::ROOT_ID,
                c"file",
                0o666,
                false,
                libc::O_RDWR as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(first.inode, existing.inode);
        assert_eq!(existing.attr.st_mode & 0o777, 0o600);
        let exclusive = fs
            .create(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                fuse::ROOT_ID,
                c"file",
                0o666,
                false,
                (libc::O_RDWR | libc::O_EXCL) as u32,
                0,
                Extensions::default(),
            )
            .err()
            .unwrap();
        assert_eq!(exclusive.raw_os_error(), Some(libc::EEXIST));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn root_can_create_socket_and_fifo_without_override_xattrs() {
        let dir = unique_tmp_dir("native-special-inodes");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let socket = fs
            .mknod(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                fuse::ROOT_ID,
                c"socket",
                libc::S_IFSOCK | 0o600,
                0,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(socket.attr.st_mode, libc::S_IFSOCK | 0o600);
        assert_eq!(socket.attr.st_uid, 0);
        assert_eq!(socket.attr.st_gid, 0);
        let absent = fs
            .getxattr(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                socket.inode,
                c"security.capability",
                0,
            )
            .err()
            .unwrap();
        assert_eq!(absent.raw_os_error(), Some(libc::ENODATA));
        let attrs = fs
            .listxattr(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                socket.inode,
                0,
            )
            .unwrap();
        assert!(matches!(attrs, ListxattrReply::Count(0)));
        let fifo = fs
            .mknod(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                },
                fuse::ROOT_ID,
                c"fifo",
                libc::S_IFIFO | 0o600,
                0,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert_eq!(fifo.attr.st_mode, libc::S_IFIFO | 0o600);
        assert_eq!(fifo.attr.st_uid, 0);
        assert_eq!(fifo.attr.st_gid, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn root_can_search_mode_zero_directory() {
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let mut st = stat_with_owner(1000, 1000, 0);
        st.st_mode = libc::S_IFDIR;
        check_stat_access(&ctx, &st, (libc::W_OK | libc::X_OK) as u32, &[]).unwrap();
    }

    #[test]
    fn root_cannot_execute_file_without_execute_bits() {
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        let st = stat_with_owner(0, 0, 0o600);
        let err = check_stat_access(&ctx, &st, libc::X_OK as u32, &[]).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn supplementary_group_grants_directory_create_access() {
        let ctx = Context {
            uid: 1000,
            gid: 1001,
            pid: 1,
        };
        let mut st: libc::stat64 = unsafe { mem::zeroed() };
        st.st_uid = 0;
        st.st_gid = 2000;
        st.st_mode = libc::S_IFDIR | 0o2770;

        check_stat_access(&ctx, &st, (libc::W_OK | libc::X_OK) as u32, &[2000]).unwrap();
        let err = check_stat_access(&ctx, &st, (libc::W_OK | libc::X_OK) as u32, &[]).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn owner_permissions_do_not_fall_through_to_supplementary_group() {
        let ctx = Context {
            uid: 1000,
            gid: 1001,
            pid: 1,
        };
        let mut st: libc::stat64 = unsafe { mem::zeroed() };
        st.st_uid = 1000;
        st.st_gid = 2000;
        st.st_mode = libc::S_IFDIR | 0o070;

        let err =
            check_stat_access(&ctx, &st, (libc::W_OK | libc::X_OK) as u32, &[2000]).unwrap_err();

        assert_eq!(err.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn setgid_parent_selects_inherited_guest_group() {
        let ctx = Context {
            uid: 1000,
            gid: 1001,
            pid: 1,
        };
        let mut st: libc::stat64 = unsafe { mem::zeroed() };
        st.st_gid = 2000;
        st.st_mode = libc::S_IFDIR | libc::S_ISGID;

        assert_eq!(guest_create_gid(&ctx, &st), 2000);

        st.st_mode = libc::S_IFDIR | 0o770;
        assert_eq!(guest_create_gid(&ctx, &st), 1001);
    }

    #[test]
    fn guest_xattr_name_is_mapped_to_user_namespace() {
        let name = CStr::from_bytes_with_nul(b"security.capability\0").unwrap();
        let got = host_xattr_name_for_guest(name).unwrap();

        assert_eq!(
            got.to_bytes(),
            b"user.containers.guest_xattr.73656375726974792e6361706162696c697479"
        );
    }

    #[test]
    fn guest_xattr_list_decodes_only_mapped_names() {
        let raw = b"user.containers.override_stat\0user.containers.guest_xattr.73656375726974792e6361706162696c697479\0user.host-only\0";

        let got = guest_xattr_list_from_host(raw);

        assert_eq!(got, b"security.capability\0");
    }

    #[test]
    fn concurrent_lookups_and_forgets_keep_looked_up_inodes_known() {
        let dir = unique_tmp_dir("lookup-forget-race");
        std::fs::write(dir.join("file"), b"").unwrap();
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let ctx = Context {
            uid: 0,
            gid: 0,
            pid: 1,
        };
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    for _ in 0..20_000 {
                        let entry = fs.lookup(ctx, fuse::ROOT_ID, c"file").unwrap();
                        // Until its FORGET, the guest may use the inode a
                        // lookup returned, whatever other FORGETs do.
                        fs.getattr(ctx, entry.inode, None).unwrap();
                        fs.forget(ctx, entry.inode, 1);
                    }
                });
            }
        });
        // Every lookup was forgotten, and no duplicate entry was left behind.
        let inodes: Vec<_> = fs
            .inodes
            .read()
            .unwrap()
            .values()
            .map(|d| d.inode)
            .collect();
        assert_eq!(inodes, [fuse::ROOT_ID]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    fn unique_tmp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "krun-devices-{name}-{}-{suffix}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn override_xattr_ignores_symlink_owner() {
        let dir = unique_tmp_dir("symlink-owner");
        let link_path = dir.join("link");
        std::os::unix::fs::symlink("/missing-target", &link_path).unwrap();

        let c_path = CString::new(link_path.as_os_str().as_bytes()).unwrap();
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        assert!(fd >= 0, "open symlink: {}", io::Error::last_os_error());
        let file = unsafe { File::from_raw_fd(fd) };

        set_override_xattr(file.as_raw_fd(), Some((33, 44)), None).unwrap();

        std::fs::remove_dir_all(dir).unwrap();
    }

    fn root_ctx() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    fn host_override_reads() -> u64 {
        HOST_OVERRIDE_READS.with(|reads| reads.get())
    }

    #[test]
    fn exclusive_share_reads_override_stat_once_per_inode() {
        let dir = unique_tmp_dir("override-read-once");
        let existing = File::create(dir.join("existing")).unwrap();
        set_override_xattr(existing.as_raw_fd(), Some((33, 44)), Some(0o640)).unwrap();
        drop(existing);
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            cache_guest_metadata: true,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let before = host_override_reads();
        let first = fs.do_lookup(fuse::ROOT_ID, c"existing").unwrap();
        assert_eq!((first.attr.st_uid, first.attr.st_gid), (33, 44));
        assert_eq!(first.attr.st_mode & 0o7777, 0o640);
        let again = fs.do_lookup(fuse::ROOT_ID, c"existing").unwrap();
        let (attr, _) = fs.getattr(root_ctx(), first.inode, None).unwrap();
        assert_eq!(again.inode, first.inode);
        assert_eq!(
            (attr.st_uid, attr.st_gid, attr.st_mode & 0o7777),
            (33, 44, 0o640)
        );
        assert_eq!(host_override_reads() - before, 1);

        // A file this server creates starts without an override to read.
        fs.getattr(root_ctx(), fuse::ROOT_ID, None).unwrap();
        let before = host_override_reads();
        let (created, _, _) = fs
            .create(
                Context {
                    uid: 1000,
                    gid: 1000,
                    pid: 1,
                },
                fuse::ROOT_ID,
                c"created",
                0o600,
                false,
                libc::O_RDWR as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        fs.getattr(root_ctx(), created.inode, None).unwrap();
        fs.do_lookup(fuse::ROOT_ID, c"created").unwrap();
        assert_eq!(host_override_reads(), before);
        assert_eq!((created.attr.st_uid, created.attr.st_gid), (1000, 1000));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn exclusive_share_answers_a_missing_name_with_a_negative_entry() {
        let dir = unique_tmp_dir("negative-entry");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            cache_negative_entries: true,
            entry_timeout: Duration::from_secs(60),
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let missing = fs.lookup(root_ctx(), fuse::ROOT_ID, c"missing").unwrap();
        assert_eq!(missing.inode, 0);
        assert_eq!(missing.entry_timeout, Duration::from_secs(60));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn always_cache_policy_keeps_a_directory_listing_across_opens() {
        let dir = unique_tmp_dir("keep-dir-cache");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            cache_policy: CachePolicy::Always,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let (_, opts) = fs.opendir(root_ctx(), fuse::ROOT_ID, 0).unwrap();
        assert_eq!(opts, OpenOptions::KEEP_CACHE | OpenOptions::CACHE_DIR);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shared_directory_reports_a_missing_name_as_an_error() {
        let dir = unique_tmp_dir("missing-name-error");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let err = fs
            .lookup(root_ctx(), fuse::ROOT_ID, c"missing")
            .err()
            .unwrap();
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn shared_directory_rereads_override_stat_on_every_request() {
        let dir = unique_tmp_dir("override-reread");
        File::create(dir.join("file")).unwrap();
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let entry = fs.do_lookup(fuse::ROOT_ID, c"file").unwrap();

        // Another writer changes the owner while the inode is live.
        let file = File::open(dir.join("file")).unwrap();
        set_override_xattr(file.as_raw_fd(), Some((33, 44)), Some(0o640)).unwrap();
        let (attr, _) = fs.getattr(root_ctx(), entry.inode, None).unwrap();

        assert_eq!((attr.st_uid, attr.st_gid), (33, 44));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn cached_override_stat_matches_the_host_after_each_chmod_and_chown() {
        let dir = unique_tmp_dir("override-cache-updates");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            cache_guest_metadata: true,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        let (entry, _, _) = fs
            .create(
                root_ctx(),
                fuse::ROOT_ID,
                c"file",
                0o644,
                false,
                libc::O_RDWR as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let host = File::open(dir.join("file")).unwrap();
        let assert_matches_host = |want: (u32, u32, u32)| {
            let (got, _) = fs.getattr(root_ctx(), entry.inode, None).unwrap();
            assert_eq!((got.st_uid, got.st_gid, got.st_mode & 0o7777), want);
            let stored = read_override_stat(host.as_raw_fd()).unwrap();
            assert_eq!(
                (
                    stored.uid,
                    stored.gid,
                    stored.mode.map(|mode| mode & 0o7777)
                ),
                (Some(want.0), Some(want.1), Some(want.2))
            );
        };
        let mut attr: libc::stat64 = unsafe { mem::zeroed() };

        attr.st_uid = 1;
        attr.st_gid = 2;
        fs.setattr(
            root_ctx(),
            entry.inode,
            attr,
            None,
            SetattrValid::UID | SetattrValid::GID,
        )
        .unwrap();
        attr.st_mode = libc::S_IFREG | 0o4750;
        fs.setattr(root_ctx(), entry.inode, attr, None, SetattrValid::MODE)
            .unwrap();
        assert_matches_host((1, 2, 0o4750));

        // A uid-only chown keeps the group and clears setuid.
        attr.st_uid = 7;
        fs.setattr(root_ctx(), entry.inode, attr, None, SetattrValid::UID)
            .unwrap();
        assert_matches_host((7, 2, 0o750));

        attr.st_gid = 8;
        fs.setattr(root_ctx(), entry.inode, attr, None, SetattrValid::GID)
            .unwrap();
        assert_matches_host((7, 8, 0o750));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writeback_open_falls_back_to_write_only_for_unreadable_files() {
        let dir = unique_tmp_dir("writeback-write-only");
        let path = dir.join("file");
        File::create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200)).unwrap();
        if File::open(&path).is_ok() {
            // Running with CAP_DAC_OVERRIDE; the host can read anything.
            std::fs::remove_dir_all(dir).unwrap();
            return;
        }
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            writeback: true,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
        let entry = fs.do_lookup(fuse::ROOT_ID, c"file").unwrap();

        let (handle, _) = fs
            .open(root_ctx(), entry.inode, false, libc::O_WRONLY as u32)
            .unwrap();

        let data = fs.handles.read().unwrap()[&handle.unwrap()].clone();
        let fd = data.file.read().unwrap().as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_WRONLY);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writeback_create_opens_write_only_files_readable_without_append() {
        let dir = unique_tmp_dir("writeback-create");
        let fs = PassthroughFs::new(Config {
            root_dir: dir.to_str().unwrap().to_string(),
            writeback: true,
            ..Config::default()
        })
        .unwrap();
        fs.init(FsOptions::WRITEBACK_CACHE).unwrap();
        let (_, handle, _) = fs
            .create(
                root_ctx(),
                fuse::ROOT_ID,
                c"file",
                0o600,
                false,
                (libc::O_WRONLY | libc::O_APPEND) as u32,
                0,
                Extensions::default(),
            )
            .unwrap();
        let data = fs
            .handles
            .read()
            .unwrap()
            .get(&handle.unwrap())
            .cloned()
            .unwrap();
        let flags = unsafe { libc::fcntl(data.file.read().unwrap().as_raw_fd(), libc::F_GETFL) };
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDWR);
        assert_eq!(flags & libc::O_APPEND, 0);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

impl Drop for ScopedCaps {
    fn drop(&mut self) {
        caps::raise(None, CapSet::Effective, self.cap)
            .unwrap_or_else(|e| panic!("couldn't restore {:?} capability: {e}", self.cap));
    }
}

pub fn drop_effective_cap(cap: Capability) -> io::Result<Option<ScopedCaps>> {
    ScopedCaps::new(cap)
}

fn ebadf() -> io::Error {
    io::Error::from_raw_os_error(libc::EBADF)
}

fn einval() -> io::Error {
    io::Error::from_raw_os_error(libc::EINVAL)
}

fn proc_fd_path(fd: RawFd) -> io::Result<CString> {
    CString::new(format!("/proc/self/fd/{fd}"))
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn item_to_value(item: &[u8], radix: u32) -> Option<u32> {
    match std::str::from_utf8(item) {
        Ok(val) => u32::from_str_radix(val, radix).ok(),
        Err(_) => None,
    }
}

fn get_xattr_common(buf: &[u8]) -> (Option<u32>, Option<u32>, Option<u32>) {
    let mut items = buf.split(|c| *c == b':');

    let uid = items.next().and_then(|item| item_to_value(item, 10));
    let gid = items.next().and_then(|item| item_to_value(item, 10));
    let mode = items.next().and_then(|item| item_to_value(item, 8));

    (uid, gid, mode)
}

// Linux rejects user.* on native sockets, FIFOs and devices before FUSE sees
// the request. JuiceFS supports this owner-protected system namespace; keeping
// the metadata on the inode preserves hardlinks, rename and Snap semantics.
fn override_xattr_key(fd: RawFd) -> io::Result<Option<&'static [u8]>> {
    match host_stat_fd(fd)?.st_mode & libc::S_IFMT {
        libc::S_IFLNK => Ok(None),
        libc::S_IFREG | libc::S_IFDIR => Ok(Some(XATTR_KEY)),
        _ => Ok(Some(SPECIAL_XATTR_KEY)),
    }
}

/// Guest owner and mode stored in an inode's override xattr. `present` is
/// false when the inode has no override xattr or cannot carry one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct OverrideStat {
    present: bool,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
}

impl OverrideStat {
    fn parse(buf: &[u8]) -> Self {
        let (uid, gid, mode) = get_xattr_common(buf);
        Self {
            present: true,
            uid,
            gid,
            mode,
        }
    }
}

// Inode descriptors are O_PATH, which the f*xattr calls reject with EBADF, so
// xattrs are always accessed through the descriptor's procfs path.
#[cfg(test)]
thread_local! {
    static HOST_OVERRIDE_READS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn read_override_stat(fd: RawFd) -> io::Result<OverrideStat> {
    #[cfg(test)]
    HOST_OVERRIDE_READS.with(|reads| reads.set(reads.get() + 1));
    let Some(key) = override_xattr_key(fd)? else {
        return Ok(OverrideStat::default());
    };
    let path = proc_fd_path(fd)?;
    // Values written here fit in 32 bytes; other writers may store more.
    let mut buf = vec![0u8; 32];
    loop {
        let res = unsafe {
            libc::getxattr(
                path.as_ptr(),
                key.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if res >= 0 {
            return Ok(OverrideStat::parse(&buf[..res as usize]));
        }
        let err = io::Error::last_os_error();
        if is_missing_override_xattr_error(&err) {
            return Ok(OverrideStat::default());
        }
        if err.raw_os_error() != Some(libc::ERANGE) || buf.len() >= 64 * 1024 {
            return Err(err);
        }
        let len = buf.len();
        buf.resize(len * 8, 0);
    }
}

/// Reads the current value only when a partial update needs it to fill in
/// the owner or mode it does not change.
fn read_override_stat_for_update(
    fd: RawFd,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
) -> io::Result<OverrideStat> {
    if is_valid_owner(owner) && mode.is_some() {
        Ok(OverrideStat::default())
    } else {
        read_override_stat(fd)
    }
}

#[cfg(test)]
fn get_override_xattr(fd: RawFd) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    let value = read_override_stat(fd).unwrap_or_default();
    Ok((value.uid, value.gid, value.mode))
}

fn is_missing_override_xattr_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if
        code == libc::ENODATA
            || code == libc::ENOTSUP
            || code == libc::EOPNOTSUPP)
}

fn should_store_override_stat_for_setattr_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if
        code == libc::EINVAL
            || code == libc::EPERM
            || code == libc::ENOTSUP
            || code == libc::EOPNOTSUPP)
}

fn is_valid_owner(owner: Option<(u32, u32)>) -> bool {
    if let Some(owner) = owner {
        owner.0 < UID_MAX && owner.1 < UID_MAX
    } else {
        false
    }
}

fn set_override_xattr(fd: RawFd, owner: Option<(u32, u32)>, mode: Option<u32>) -> io::Result<()> {
    let current = read_override_stat_for_update(fd, owner, mode)?;
    write_override_stat(fd, owner, mode, current).map(|_| ())
}

/// Writes the override xattr, completing a partial update from `current`, and
/// returns the stored value.
fn write_override_stat(
    fd: RawFd,
    owner: Option<(u32, u32)>,
    mode: Option<u32>,
    current: OverrideStat,
) -> io::Result<OverrideStat> {
    let Some(key) = override_xattr_key(fd)? else {
        return Ok(current);
    };
    let buf = if is_valid_owner(owner) && mode.is_some() {
        let owner = owner.unwrap();
        let mode = mode.unwrap();
        format!("{}:{}:0{:o}", owner.0, owner.1, mode)
    } else {
        let (uid, gid) = match owner {
            Some((uid, gid)) => {
                let uid = if uid < UID_MAX {
                    Some(uid)
                } else {
                    current.uid
                };
                let gid = if gid < UID_MAX {
                    Some(gid)
                } else {
                    current.gid
                };
                (uid, gid)
            }
            None => (current.uid, current.gid),
        };

        let mut buf = String::new();
        if let Some(uid) = uid {
            buf.push_str(&uid.to_string());
        } else {
            buf.push('x');
        }
        if let Some(gid) = gid {
            buf.push_str(&format!(":{gid}:"));
        } else {
            buf.push_str(":x:");
        }
        if let Some(mode) = mode {
            buf.push_str(&format!("0{:o}", mode));
        } else if let Some(orig_mode) = current.mode {
            buf.push_str(&format!("0{:o}", orig_mode));
        } else {
            buf.push('x');
        }
        buf
    };

    let path = proc_fd_path(fd)?;
    let res = unsafe {
        libc::setxattr(
            path.as_ptr(),
            key.as_ptr() as *const libc::c_char,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
        )
    };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(OverrideStat::parse(buf.as_bytes()))
    }
}

fn host_xattr_name_for_guest(name: &CStr) -> io::Result<CString> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let guest_name = name.to_bytes();
    let mut host_name = Vec::with_capacity(GUEST_XATTR_PREFIX.len() + guest_name.len() * 2);
    host_name.extend_from_slice(GUEST_XATTR_PREFIX);
    for b in guest_name {
        host_name.push(HEX[(b >> 4) as usize]);
        host_name.push(HEX[(b & 0x0f) as usize]);
    }

    CString::new(host_name).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn guest_xattr_name_from_host(name: &[u8]) -> Option<Vec<u8>> {
    fn hex_value(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let encoded = name.strip_prefix(GUEST_XATTR_PREFIX)?;
    if encoded.is_empty() || encoded.len() % 2 != 0 {
        return None;
    }

    let mut guest_name = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.chunks_exact(2) {
        let high = hex_value(pair[0])?;
        let low = hex_value(pair[1])?;
        guest_name.push((high << 4) | low);
    }
    if guest_name.is_empty() || guest_name.contains(&0) {
        return None;
    }

    Some(guest_name)
}

fn guest_xattr_list_from_host(host_list: &[u8]) -> Vec<u8> {
    let mut guest_list = Vec::new();
    for host_name in host_list.split(|b| *b == 0) {
        if host_name.is_empty() {
            continue;
        }
        if let Some(guest_name) = guest_xattr_name_from_host(host_name) {
            guest_list.extend_from_slice(&guest_name);
            guest_list.push(0);
        }
    }
    guest_list
}

fn apply_override_stat(
    mut st: libc::stat64,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
    host_uid: Option<libc::uid_t>,
    host_gid: Option<libc::gid_t>,
) -> libc::stat64 {
    if let Some(uid) = uid {
        st.st_uid = uid;
    } else if host_uid == Some(st.st_uid) {
        st.st_uid = 0;
    }
    if let Some(gid) = gid {
        st.st_gid = gid;
    } else if host_gid == Some(st.st_gid) {
        st.st_gid = 0;
    }
    if let Some(mode) = mode {
        if mode as libc::mode_t & libc::S_IFMT == 0 {
            st.st_mode = (st.st_mode & libc::S_IFMT) | mode as libc::mode_t;
        } else {
            st.st_mode = mode as libc::mode_t;
        }
    }
    st
}

/// How far a regular file's host ctime may trail its mtime and still be taken
/// as the time its write-back landed rather than a later change of its own.
/// Dirty pages are written back within about 35 s (the kernel's default
/// expiry plus flusher interval); the margin covers a slow host.
const WRITEBACK_CTIME_SLACK: Duration = Duration::from_secs(60);

/// Reports a regular file's mtime as its ctime when the host ctime is only
/// the write-back delay after it.
///
/// With FUSE writeback the guest kernel keeps its own mtime and ctime for
/// regular files: a write stamps both with the same instant, and the inode's
/// write-back sends them here. The host takes the mtime but cannot take a
/// ctime, so it records the moment the write-back landed instead. The guest
/// trusts its own value while the inode stays cached, but after a restart it
/// reads the host's, which differs for every file it wrote; tools that trust
/// ctime, such as git, then treat those files as changed and read them all
/// again. Reporting the mtime gives back
/// exactly the ctime the guest assigned. A metadata change within the slack
/// after a write is reported up to the slack early; a later one, or a file
/// whose mtime was set into the past, keeps the host ctime.
fn writeback_ctime(mut st: libc::stat64) -> libc::stat64 {
    let nanos = |sec: i64, nsec: i64| i128::from(sec) * 1_000_000_000 + i128::from(nsec);
    let delay = nanos(st.st_ctime, st.st_ctime_nsec) - nanos(st.st_mtime, st.st_mtime_nsec);
    if st.st_mode & libc::S_IFMT == libc::S_IFREG
        && (0..=WRITEBACK_CTIME_SLACK.as_nanos() as i128).contains(&delay)
    {
        st.st_ctime = st.st_mtime;
        st.st_ctime_nsec = st.st_mtime_nsec;
    }
    st
}

fn host_stat_fd(fd: RawFd) -> io::Result<libc::stat64> {
    let mut st = MaybeUninit::<libc::stat64>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe {
        libc::fstatat64(
            fd,
            pathname.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        Ok(unsafe { st.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

fn host_stat(f: &File) -> io::Result<libc::stat64> {
    host_stat_fd(f.as_raw_fd())
}

fn host_fd_is_symlink(fd: RawFd) -> io::Result<bool> {
    Ok(host_stat_fd(fd)?.st_mode & libc::S_IFMT == libc::S_IFLNK)
}

fn clear_suid_sgid(mode: libc::mode_t) -> libc::mode_t {
    mode & !((libc::S_ISUID | libc::S_ISGID) as libc::mode_t)
}

fn check_stat_access(
    ctx: &Context,
    st: &libc::stat64,
    mask: u32,
    supplementary_gids: &[u32],
) -> io::Result<()> {
    let mode = mask as i32 & (libc::R_OK | libc::W_OK | libc::X_OK);
    if mode == libc::F_OK {
        return Ok(());
    }

    if ctx.uid == 0 {
        if mode & libc::X_OK != 0
            && st.st_mode & libc::S_IFMT != libc::S_IFDIR
            && st.st_mode & 0o111 == 0
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        return Ok(());
    }

    let permission_bits = if st.st_uid == ctx.uid {
        (st.st_mode >> 6) & 0o7
    } else if st.st_gid == ctx.gid || supplementary_gids.contains(&st.st_gid) {
        (st.st_mode >> 3) & 0o7
    } else {
        st.st_mode & 0o7
    };
    if permission_bits & mode as libc::mode_t != mode as libc::mode_t {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(())
}

fn guest_create_gid(ctx: &Context, parent_attr: &libc::stat64) -> libc::gid_t {
    if parent_attr.st_mode & libc::S_ISGID as libc::mode_t != 0 {
        parent_attr.st_gid
    } else {
        ctx.gid
    }
}

fn statx(f: &File) -> io::Result<(libc::stat64, u64)> {
    statx_with_flags(f, 0)
}

fn statx_with_flags(f: &File, flags: i32) -> io::Result<(libc::stat64, u64)> {
    let mut stx = MaybeUninit::<libc::statx>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe {
        libc::statx(
            f.as_raw_fd(),
            pathname.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | flags,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            stx.as_mut_ptr(),
        )
    };
    if res >= 0 {
        // Safe because the kernel guarantees that the struct is now fully initialized.
        let stx = unsafe { stx.assume_init() };

        // Unfortunately, we cannot use an initializer to create the stat64 object,
        // because it may contain padding and reserved fields (depending on the
        // architecture), and it does not implement the Default trait.
        // So we take a zeroed struct and set what we can. (Zero in all fields is
        // wrong, but safe.)
        let mut st = unsafe { MaybeUninit::<libc::stat64>::zeroed().assume_init() };

        st.st_dev = libc::makedev(stx.stx_dev_major, stx.stx_dev_minor);
        st.st_ino = stx.stx_ino;
        st.st_mode = stx.stx_mode as _;
        st.st_nlink = stx.stx_nlink as _;
        st.st_uid = stx.stx_uid;
        st.st_gid = stx.stx_gid;
        st.st_rdev = libc::makedev(stx.stx_rdev_major, stx.stx_rdev_minor);
        st.st_size = stx.stx_size as _;
        st.st_blksize = stx.stx_blksize as _;
        st.st_blocks = stx.stx_blocks as _;
        st.st_atime = stx.stx_atime.tv_sec;
        st.st_atime_nsec = stx.stx_atime.tv_nsec as _;
        st.st_mtime = stx.stx_mtime.tv_sec;
        st.st_mtime_nsec = stx.stx_mtime.tv_nsec as _;
        st.st_ctime = stx.stx_ctime.tv_sec;
        st.st_ctime_nsec = stx.stx_ctime.tv_nsec as _;
        Ok((st, stx.stx_mnt_id))
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The caching policy that the file system should report to the FUSE client. By default the FUSE
/// protocol uses close-to-open consistency. This means that any cached contents of the file are
/// invalidated the next time that file is opened.
#[derive(Default, Debug, Clone)]
pub enum CachePolicy {
    /// The client should never cache file data and all I/O should be directly forwarded to the
    /// server. This policy must be selected when file contents may change without the knowledge of
    /// the FUSE client (i.e., the file system does not have exclusive access to the directory).
    Never,

    /// The client is free to choose when and how to cache file data. This is the default policy and
    /// uses close-to-open consistency as described in the enum documentation.
    #[default]
    Auto,

    /// The client should always cache file data. This means that the FUSE client will not
    /// invalidate any cached data that was returned by the file system the last time the file was
    /// opened. This policy should only be selected when the file system has exclusive access to the
    /// directory.
    Always,
}

impl FromStr for CachePolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "never" | "Never" | "NEVER" => Ok(CachePolicy::Never),
            "auto" | "Auto" | "AUTO" => Ok(CachePolicy::Auto),
            "always" | "Always" | "ALWAYS" => Ok(CachePolicy::Always),
            _ => Err("invalid cache policy"),
        }
    }
}

/// Options that configure the behavior of the file system.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long the FUSE client should consider directory entries to be valid. If the contents of a
    /// directory can only be modified by the FUSE client (i.e., the file system has exclusive
    /// access), then this should be a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub entry_timeout: Duration,

    /// How long the FUSE client should consider file and directory attributes to be valid. If the
    /// attributes of a file or directory can only be modified by the FUSE client (i.e., the file
    /// system has exclusive access), then this should be set to a large value.
    ///
    /// The default value for this option is 5 seconds.
    pub attr_timeout: Duration,

    /// The caching policy the file system should use. See the documentation of `CachePolicy` for
    /// more details.
    pub cache_policy: CachePolicy,

    /// Whether the file system should enabled writeback caching. This can improve performance as it
    /// allows the FUSE client to cache and coalesce multiple writes before sending them to the file
    /// system. However, enabling this option can increase the risk of data corruption if the file
    /// contents can change without the knowledge of the FUSE client (i.e., the server does **NOT**
    /// have exclusive access). Additionally, the file system should have read access to all files
    /// in the directory it is serving as the FUSE client may send read requests even for files
    /// opened with `O_WRONLY`.
    ///
    /// Therefore callers should only enable this option when they can guarantee that: 1) the file
    /// system has exclusive access to the directory and 2) the file system has read permissions for
    /// all files in that directory.
    ///
    /// The default value for this option is `false`.
    pub writeback: bool,

    /// Whether this server is the only writer of the override xattrs that
    /// carry guest owner and mode, so each inode's value can be read once and
    /// kept in memory. The default is `false`.
    pub cache_guest_metadata: bool,

    /// Whether a lookup of a missing name answers with a negative entry the
    /// guest may cache for `entry_timeout`, instead of an error it cannot
    /// cache. Only correct when nothing but the guest creates names here.
    /// The default is `false`.
    pub cache_negative_entries: bool,

    /// The path of the root directory.
    ///
    /// The default is `/`.
    pub root_dir: String,

    /// Whether the file system should support Extended Attributes (xattr). Enabling this feature may
    /// have a significant impact on performance, especially on write parallelism. This is the result
    /// of FUSE attempting to remove the special file privileges after each write request.
    ///
    /// The default value for this options is `false`.
    pub xattr: bool,

    /// Optional file descriptor for /proc/self/fd. Callers can obtain a file descriptor and pass it
    /// here, so there's no need to open it in PassthroughFs::new(). This is specially useful for
    /// sandboxing.
    ///
    /// The default is `None`.
    pub proc_sfd_rawfd: Option<RawFd>,

    /// ID of this filesystem to uniquely identify exports.
    pub export_fsid: u64,
    /// Table of exported FDs to share with other subsystems.
    pub export_table: Option<ExportTable>,
    pub allow_root_dir_delete: bool,
    pub checkpoint_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            cache_guest_metadata: false,
            cache_negative_entries: false,
            root_dir: String::from("/"),
            xattr: true,
            proc_sfd_rawfd: None,
            export_fsid: 0,
            export_table: None,
            allow_root_dir_delete: false,
            checkpoint_enabled: false,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
    fd_budget: Arc<FdBudget>,
    // File descriptors for various points in the file system tree. These fds are always opened with
    // the `O_PATH` option so they cannot be used for reading or writing any data. See the
    // documentation of the `O_PATH` flag in `open(2)` for more details on what one can and cannot
    // do with an fd opened with this flag.
    inodes: RwLock<MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>>,
    next_inode: AtomicU64,
    init_inode: u64,

    // File descriptors for open files and directories. Unlike the fds in `inodes`, these _can_ be
    // used for reading and writing data.
    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,
    init_handle: u64,

    // File descriptor pointing to the `/proc/self/fd` directory. This is used to convert an fd from
    // `inodes` into one that can go into `handles`. This is accomplished by reading the
    // `/proc/self/fd/{}` symlink. We keep an open fd here in case the file system tree that we are
    // meant to be serving doesn't have access to `/proc/self/fd`.
    proc_self_fd: File,

    // Whether writeback caching is enabled for this directory. This will only be true when
    // `cfg.writeback` is true and `init` was called with `FsOptions::WRITEBACK_CACHE`.
    writeback: AtomicBool,
    dax_used: AtomicBool,
    announce_submounts: AtomicBool,
    supplementary_group_extension: AtomicBool,
    my_uid: Option<libc::uid_t>,
    my_gid: Option<libc::gid_t>,
    cap_fowner: bool,

    cfg: Config,
}

/// Non-symlink metadata uses a pinned O_PATH inode via procfs. Symlink metadata
/// keeps the no-follow xattr path; it must never address the symlink's target.
enum FileOrLink {
    File(File),
    /// A symlink's procfs path, with the inode whose descriptor the path names
    /// kept alive so a concurrent FORGET cannot close it while the path is used.
    Link {
        path: CString,
        _inode: Arc<InodeData>,
    },
}

fn list_xattr_raw(
    target: &FileOrLink,
    buf: *mut libc::c_char,
    size: libc::size_t,
) -> io::Result<libc::ssize_t> {
    Ok(match target {
        FileOrLink::File(file) => unsafe {
            libc::listxattr(proc_fd_path(file.as_raw_fd())?.as_ptr(), buf, size)
        },
        FileOrLink::Link { path: link, .. } => unsafe {
            libc::llistxattr(link.as_ptr(), buf, size)
        },
    })
}

fn list_host_xattrs(target: &FileOrLink) -> io::Result<Vec<u8>> {
    let res = list_xattr_raw(target, std::ptr::null_mut(), 0)?;
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    if res == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0; res as usize];
    let res = list_xattr_raw(target, buf.as_mut_ptr() as *mut libc::c_char, buf.len())?;
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.resize(res as usize, 0);
    Ok(buf)
}

impl PassthroughFs {
    pub fn new(cfg: Config) -> io::Result<PassthroughFs> {
        let fd = if let Some(fd) = cfg.proc_sfd_rawfd {
            fd
        } else {
            // Safe because this is a constant value and a valid C string.
            let proc_cstr = unsafe { CStr::from_bytes_with_nul_unchecked(PROC_CSTR) };

            // Safe because this doesn't modify any memory and we check the return value.
            let fd = unsafe {
                libc::openat(
                    libc::AT_FDCWD,
                    proc_cstr.as_ptr(),
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            fd
        };
        // Take ownership before further fallible setup, including budget probing.
        let proc_self_fd = unsafe { File::from_raw_fd(fd) };
        let fd_budget = FdBudget::process(&proc_self_fd)?;

        let my_uid = if has_cap(None, CapSet::Effective, Capability::CAP_SETUID).unwrap_or_default()
        {
            None
        } else {
            // SAFETY: This syscall is always safe to call and always succeeds.
            Some(unsafe { libc::getuid() })
        };

        let my_gid = if has_cap(None, CapSet::Effective, Capability::CAP_SETGID).unwrap_or_default()
        {
            None
        } else {
            // SAFETY: This syscall is always safe to call and always succeeds.
            Some(unsafe { libc::getgid() })
        };

        let cap_fowner =
            has_cap(None, CapSet::Effective, Capability::CAP_FOWNER).unwrap_or_default();

        Ok(PassthroughFs {
            fd_budget,
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 2),
            init_inode: fuse::ROOT_ID + 1,

            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            init_handle: 0,

            proc_self_fd,

            writeback: AtomicBool::new(false),
            dax_used: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            supplementary_group_extension: AtomicBool::new(false),
            my_uid,
            my_gid,
            cap_fowner,
            cfg,
        })
    }

    fn override_stat(&self, data: &InodeData) -> io::Result<OverrideStat> {
        if self.cfg.cache_guest_metadata {
            data.cached_override_stat()
        } else {
            read_override_stat(data.file.as_raw_fd())
        }
    }

    fn set_override_stat(
        &self,
        data: &InodeData,
        owner: Option<(u32, u32)>,
        mode: Option<u32>,
    ) -> io::Result<()> {
        if self.cfg.cache_guest_metadata {
            data.set_cached_override_stat(owner, mode)
        } else {
            set_override_xattr(data.file.as_raw_fd(), owner, mode)
        }
    }

    fn guest_stat(&self, data: &InodeData) -> io::Result<libc::stat64> {
        let st = host_stat(&data.file)?;
        // An unreadable override leaves the host attributes.
        let value = self.override_stat(data).unwrap_or_default();
        Ok(self.guest_attr(st, value))
    }

    /// The attributes the guest sees for a host inode: its guest owner and
    /// mode and, under writeback, the ctime the guest assigned.
    fn guest_attr(&self, st: libc::stat64, value: OverrideStat) -> libc::stat64 {
        let st = apply_override_stat(
            st,
            value.uid,
            value.gid,
            value.mode,
            self.my_uid,
            self.my_gid,
        );
        if self.writeback.load(Ordering::Relaxed) {
            writeback_ctime(st)
        } else {
            st
        }
    }

    fn open_inode(&self, inode: Inode, mut flags: i32) -> io::Result<File> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let pathname = CString::new(format!("{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // When writeback caching is enabled, the kernel may send read requests even if the
        // userspace program opened the file write-only. So we need to ensure that we have opened
        // the file for reading as well as writing.
        let writeback = self.writeback.load(Ordering::Relaxed);
        let requested_access = flags & libc::O_ACCMODE;
        if writeback && requested_access == libc::O_WRONLY {
            flags &= !libc::O_ACCMODE;
            flags |= libc::O_RDWR;
        }

        // When writeback caching is enabled the kernel is responsible for handling `O_APPEND`.
        // However, this breaks atomicity as the file may have changed on disk, invalidating the
        // cached copy of the data in the kernel and the offset that the kernel thinks is the end of
        // the file. Just allow this for now as it is the user's responsibility to enable writeback
        // caching only for directories that are not shared. It also means that we need to clear the
        // `O_APPEND` flag.
        if writeback && flags & libc::O_APPEND != 0 {
            flags &= !libc::O_APPEND;
        }

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems. Also, clear the `O_NOFOLLOW` flag if it is set since we need
        // to follow the `/proc/self/fd` symlink to get the file.
        let open = |flags: i32| unsafe {
            libc::openat(
                self.proc_self_fd.as_raw_fd(),
                pathname.as_ptr(),
                (flags | libc::O_CLOEXEC) & (!libc::O_NOFOLLOW),
            )
        };
        let mut fd = open(flags);
        // A file this server may write but not read still opens write-only;
        // the guest then cannot fill partial pages from it.
        if fd < 0
            && flags & libc::O_ACCMODE != requested_access
            && io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
        {
            fd = open((flags & !libc::O_ACCMODE) | requested_access);
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    // Xattrs are inode metadata, not device I/O. Keep an O_PATH descriptor
    // pinned and access it through procfs; opening a whiteout fails with EACCES,
    // opening a socket fails with ENXIO, and opening a device may have side effects.
    fn xattr_target(&self, inode: Inode) -> io::Result<FileOrLink> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;
        if host_fd_is_symlink(data.file.as_raw_fd())? {
            Ok(FileOrLink::Link {
                path: proc_fd_path(data.file.as_raw_fd())?,
                _inode: data,
            })
        } else {
            Ok(FileOrLink::File(data.file.try_clone()?))
        }
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.do_lookup_reserved(parent, name, None, false)
    }

    // `created` means this request just created the inode, so it has no
    // override xattr yet and the lookup need not read one.
    fn do_lookup_reserved(
        &self,
        parent: Inode,
        name: &CStr,
        permit: Option<FdPermit>,
        created: bool,
    ) -> io::Result<Entry> {
        let p = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let fd = unsafe {
            libc::openat(
                p.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        let f = unsafe { File::from_raw_fd(fd) };

        let (st, mnt_id) = statx(&f)?;
        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
            mnt_id,
        };
        let existing = claim_inode(&self.inodes.read().unwrap(), &altkey);
        // The override read for a new inode; a known inode has its own.
        let (data, new_override) = match existing {
            Some(data) => (data, None),
            None => {
                // A new inode starts with the value read here; an unreadable
                // override is left uncached and shown as the host attributes.
                let cache = self.cfg.cache_guest_metadata;
                let (known_override, cached_override) = if created && cache {
                    (OverrideStat::default(), Some(OverrideStat::default()))
                } else {
                    match read_override_stat(f.as_raw_fd()) {
                        Ok(value) => (value, cache.then_some(value)),
                        Err(_) => (OverrideStat::default(), None),
                    }
                };
                let permit = match permit {
                    Some(permit) => permit,
                    None => self.fd_budget.acquire()?,
                };
                let mut inodes = self.inodes.write().unwrap();
                // A concurrent lookup, for example of another name of this
                // inode, may have added it meanwhile. Adding it again would
                // move the host inode's alternate key to the new entry and
                // drop the first entry, whose inode number the guest holds.
                match claim_inode(&inodes, &altkey) {
                    Some(data) => (data, None),
                    None => {
                        let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
                        let data = Arc::new(InodeData {
                            inode,
                            guest_ino: st.st_ino,
                            file: permit.attach(f),
                            dev: st.st_dev,
                            mnt_id,
                            refcount: AtomicU64::new(1),
                            override_stat: Mutex::new(cached_override),
                        });
                        inodes.insert(inode, altkey, Arc::clone(&data));
                        (data, Some(known_override))
                    }
                }
            }
        };
        let known_override = match new_override {
            Some(value) => value,
            None => self.override_stat(&data).unwrap_or_default(),
        };
        let mut attr = self.guest_attr(st, known_override);
        attr.st_ino = data.guest_ino;
        let inode = data.inode;

        let mut attr_flags: u32 = 0;

        if st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && self.announce_submounts.load(Ordering::Relaxed)
            && (st.st_dev != p.dev || mnt_id != p.mnt_id)
        {
            attr_flags |= fuse::ATTR_SUBMOUNT;
        }

        debug!("do_lookup: {}, inode: {:?}", name.to_str().unwrap(), inode);

        Ok(Entry {
            inode,
            generation: 0,
            attr,
            attr_flags,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    fn do_readdir<F>(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        if !self.cfg.checkpoint_enabled {
            let mut buf = vec![0; size as usize];

            {
                // Since we are going to work with the kernel offset, we have to acquire the file lock
                // for both the `lseek64` and `getdents64` syscalls to ensure that no other thread
                // changes the kernel offset while we are using it.
                let dir = data.file.write().unwrap();

                // Safe because this doesn't modify any memory and we check the return value.
                let res = unsafe {
                    libc::lseek64(dir.as_raw_fd(), offset as libc::off64_t, libc::SEEK_SET)
                };
                if res < 0 {
                    return Err(io::Error::last_os_error());
                }

                // Safe because the kernel guarantees that it will only write to `buf` and we check the
                // return value.
                let res = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        dir.as_raw_fd(),
                        buf.as_mut_ptr() as *mut LinuxDirent64,
                        size as libc::c_int,
                    )
                };
                if res < 0 {
                    return Err(io::Error::last_os_error());
                }
                buf.resize(res as usize, 0);

                // Explicitly drop the lock so that it's not held while we fill in the fuse buffer.
                mem::drop(dir);
            }

            let mut rem = &buf[..];
            while !rem.is_empty() {
                // We only use debug asserts here because these values are coming from the kernel and we
                // trust them implicitly.
                debug_assert!(
                    rem.len() >= size_of::<LinuxDirent64>(),
                    "not enough space left in `rem`"
                );

                let (front, back) = rem.split_at(size_of::<LinuxDirent64>());

                let dirent64 = LinuxDirent64::from_slice(front)
                    .expect("unable to get LinuxDirent64 from slice");

                let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
                debug_assert!(namelen <= back.len(), "back is smaller than `namelen`");

                let name = &back[..namelen];
                let term = name
                    .iter()
                    .position(|&a| a == 0)
                    .expect("LinuxDirent64 name not NUL-terminated");
                let name = &name[..term];
                let res = if name == b"." || name == b".." {
                    // We don't want to report the "." and ".." entries. However, returning `Ok(0)` will
                    // break the loop so return `Ok` with a non-zero value instead.
                    Ok(1)
                } else {
                    add_entry(DirEntry {
                        ino: dirent64.d_ino,
                        offset: dirent64.d_off as u64,
                        type_: u32::from(dirent64.d_ty),
                        name,
                    })
                };

                debug_assert!(
                    rem.len() >= dirent64.d_reclen as usize,
                    "rem is smaller than `d_reclen`"
                );

                match res {
                    Ok(0) => break,
                    Ok(_) => rem = &rem[dirent64.d_reclen as usize..],
                    Err(e) => return Err(e),
                }
            }

            return Ok(());
        }

        // Guest cookies are logical entry positions, independent of host getdents
        // offsets. Keep the enumeration with the handle across checkpoint/restore.
        let mut directory = data.directory.write().unwrap();
        if offset == 0 || directory.is_none() {
            *directory = Some(checkpoint::read_directory(&data.file.write().unwrap())?);
        }
        let entries = directory.as_ref().unwrap();
        let start = usize::try_from(offset).map_err(|_| einval())?;
        if start > entries.len() {
            return Err(einval());
        }
        for (index, entry) in entries.iter().enumerate().skip(start) {
            if add_entry(DirEntry {
                ino: entry.inode,
                offset: (index + 1) as u64,
                type_: entry.kind,
                name: &entry.name,
            })? == 0
            {
                break;
            }
        }

        Ok(())
    }

    fn do_open(
        &self,
        inode: Inode,
        kill_priv: bool,
        mut flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        debug!("do_open: {inode:?}");
        if !self.cap_fowner {
            // O_NOATIME can only be used with CAP_FOWNER or if we are the file
            // owner. Not worth checking the latter, just drop it if we don't
            // have the cap. This makes overlayfs mounts with virtiofs lower dirs
            // work.
            flags &= !(libc::O_NOATIME as u32);
        }

        let permit = self.fd_budget.acquire()?;
        let file = {
            let _killpriv_guard = if kill_priv {
                drop_effective_cap(Capability::CAP_FSETID)?
            } else {
                None
            };
            RwLock::new(permit.attach(self.open_inode(inode, flags as i32)?))
        };

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            file,
            exported: Default::default(),
            directory: RwLock::new(None),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(
                OpenOptions::DIRECT_IO,
                flags & (libc::O_DIRECTORY as u32) == 0,
            ),
            // A directory needs KEEP_CACHE as well: the kernel drops a
            // directory's cached listing on every opendir without it, so
            // CACHE_DIR alone would never serve a listing from the cache.
            CachePolicy::Always => {
                opts |= OpenOptions::KEEP_CACHE;
                if flags & (libc::O_DIRECTORY as u32) != 0 {
                    opts |= OpenOptions::CACHE_DIR;
                }
            }
            _ => {}
        };

        Ok((Some(handle), opts))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();

        if let btree_map::Entry::Occupied(e) = handles.entry(handle) {
            if e.get().inode == inode {
                if e.get().exported.lock().unwrap().is_some() {
                    self.cfg
                        .export_table
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .remove(&(self.cfg.export_fsid, handle));
                }

                // We don't need to close the file here because that will happen automatically when
                // the last `Arc` is dropped.
                e.remove();
                return Ok(());
            }
        }

        Err(ebadf())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(libc::stat64, Duration)> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let mut st = self.guest_stat(&data)?;
        st.st_ino = data.guest_ino;

        Ok((st, self.cfg.attr_timeout))
    }

    fn set_guest_metadata(
        &self,
        inode: Inode,
        uid: libc::uid_t,
        gid: libc::gid_t,
        mode: Option<u32>,
    ) -> io::Result<()> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;
        self.set_override_stat(&data, Some((uid, gid)), mode)
    }

    fn refresh_entry_attr(&self, mut entry: Entry) -> io::Result<Entry> {
        let (attr, _) = self.do_getattr(entry.inode)?;
        entry.attr = attr;
        Ok(entry)
    }

    fn check_access(
        &self,
        ctx: &Context,
        inode: Inode,
        mask: u32,
        supplementary_gids: &[u32],
    ) -> io::Result<()> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let st = self.guest_stat(&data)?;
        check_stat_access(ctx, &st, mask, supplementary_gids)
    }

    fn prepare_create(
        &self,
        ctx: &Context,
        parent: Inode,
        extensions: &Extensions,
    ) -> io::Result<(libc::gid_t, bool)> {
        let (parent_attr, _) = self.do_getattr(parent)?;
        // Without FUSE_CREATE_SUPP_GROUP, the server cannot know which
        // supplementary group authorized this request. In that case the guest
        // VFS permission check is the only complete source of truth.
        if self.supplementary_group_extension.load(Ordering::Relaxed) {
            check_stat_access(
                ctx,
                &parent_attr,
                (libc::W_OK | libc::X_OK) as u32,
                &extensions.sup_gids,
            )?;
        }

        let inherits_group = parent_attr.st_mode & libc::S_ISGID as libc::mode_t != 0;
        let gid = guest_create_gid(ctx, &parent_attr);
        Ok((gid, inherits_group))
    }

    fn do_unlink(&self, parent: Inode, name: &CStr, flags: libc::c_int) -> io::Result<()> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::unlinkat(data.file.as_raw_fd(), name.as_ptr(), flags) };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Takes a lookup reference on the inode `altkey` names, if this server knows
/// it. The caller holds the map lock while the count rises: `forget_one`
/// removes an inode whose count drops to zero under the write lock, so a
/// reference taken outside the lock could revive an inode already removed and
/// hand the guest an inode number this server no longer knows.
fn claim_inode(
    inodes: &MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    altkey: &InodeAltKey,
) -> Option<Arc<InodeData>> {
    let data = inodes.get_alt(altkey)?;
    data.refcount.fetch_add(1, Ordering::Relaxed);
    Some(Arc::clone(data))
}

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        // Lookups raise the count only under the map lock (see `claim_inode`),
        // which the caller holds for writing, so the count cannot change here.
        // Saturating sub because it doesn't make sense for a refcount to go
        // below zero and we don't want misbehaving clients to cause integer
        // overflow.
        let new_count = data.refcount.load(Ordering::Relaxed).saturating_sub(count);
        data.refcount.store(new_count, Ordering::Relaxed);
        if new_count == 0 {
            inodes.remove(&inode);
        }
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let permit = self.fd_budget.acquire()?;
        let root = CString::new(self.cfg.root_dir.as_str()).expect("CString::new failed");

        // Safe because this doesn't modify any memory and we check the return value.
        // We use `O_PATH` because we just want this for traversing the directory tree
        // and not for actually reading the contents.
        let fd = unsafe {
            libc::openat(
                libc::AT_FDCWD,
                root.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd above.
        let f = unsafe { File::from_raw_fd(fd) };

        let (st, mnt_id) = statx(&f)?;

        // Safe because this doesn't modify any memory and there is no need to check the return
        // value because this system call always succeeds. We need to clear the umask here because
        // we want the client to be able to set all the bits in the mode.
        unsafe { libc::umask(0o000) };

        let mut inodes = self.inodes.write().unwrap();

        // Not sure why the root inode gets a refcount of 2 but that's what libfuse does.
        inodes.insert(
            fuse::ROOT_ID,
            InodeAltKey {
                ino: st.st_ino,
                dev: st.st_dev,
                mnt_id,
            },
            Arc::new(InodeData {
                inode: fuse::ROOT_ID,
                guest_ino: st.st_ino,
                file: permit.attach(f),
                dev: st.st_dev,
                mnt_id,
                refcount: AtomicU64::new(2),
                override_stat: Mutex::new(None),
            }),
        );

        let mut opts = FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }

        if capable.contains(FsOptions::SUBMOUNTS) {
            opts |= FsOptions::SUBMOUNTS;
            self.announce_submounts.store(true, Ordering::Relaxed);
        }
        if capable.contains(FsOptions::CREATE_SUPP_GROUP) {
            opts |= FsOptions::CREATE_SUPP_GROUP;
            self.supplementary_group_extension
                .store(true, Ordering::Relaxed);
        }

        Ok(opts)
    }

    fn destroy(&self) {
        let mut handles = self.handles.write().unwrap();
        // Exported duplicates must close before their handle-owned permits drop.
        if let Some(exports) = &self.cfg.export_table {
            exports
                .lock()
                .unwrap()
                .retain(|(fsid, _), _| *fsid != self.cfg.export_fsid);
        }
        handles.clear();
        drop(handles);
        self.inodes.write().unwrap().clear();
        self.supplementary_group_extension
            .store(false, Ordering::Relaxed);
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<libc::statvfs64> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let mut out = MaybeUninit::<libc::statvfs64>::zeroed();

        // Safe because this will only modify `out` and we check the return value.
        let res = unsafe { libc::fstatvfs64(data.file.as_raw_fd(), out.as_mut_ptr()) };
        if res == 0 {
            // Safe because the kernel guarantees that `out` has been initialized.
            Ok(unsafe { out.assume_init() })
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        debug!("do_lookup: {name:?}");
        let init_name = unsafe { CStr::from_bytes_with_nul_unchecked(INIT_CSTR) };

        if self.init_inode != 0 && name == init_name {
            let mut st: libc::stat64 = unsafe { mem::zeroed() };
            st.st_size = INIT_BINARY.len() as i64;
            st.st_ino = self.init_inode;
            st.st_mode = 0o100_755;

            Ok(Entry {
                inode: self.init_inode,
                generation: 0,
                attr: st,
                attr_flags: 0,
                attr_timeout: self.cfg.attr_timeout,
                entry_timeout: self.cfg.entry_timeout,
            })
        } else {
            match self.do_lookup(parent, name) {
                Err(e)
                    if self.cfg.cache_negative_entries
                        && e.raw_os_error() == Some(libc::ENOENT) =>
                {
                    // Inode 0 is FUSE's negative entry: the guest remembers the
                    // name is missing until it creates it or the entry expires.
                    Ok(Entry {
                        inode: 0,
                        generation: 0,
                        attr: unsafe { mem::zeroed() },
                        attr_flags: 0,
                        attr_timeout: Duration::ZERO,
                        entry_timeout: self.cfg.entry_timeout,
                    })
                }
                result => result,
            }
        }
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        let mut inodes = self.inodes.write().unwrap();

        forget_one(&mut inodes, inode, count)
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();

        for (inode, count) in requests {
            forget_one(&mut inodes, inode, count)
        }
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_open(inode, false, flags | (libc::O_DIRECTORY as u32))
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if extensions.secctx.is_some() {
            unimplemented!("SECURITY_CTX is not supported and should not be used by the guest");
        }

        let inode_permit = self.fd_budget.acquire()?;
        let (guest_gid, inherits_group) = self.prepare_create(&ctx, parent, &extensions)?;
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let mut create_mode = mode & !umask;
        if inherits_group {
            create_mode |= libc::S_ISGID;
        }
        // Guest permissions are stored separately. The rootless server must
        // retain access even for an overlayfs work directory created mode 000.
        let res =
            unsafe { libc::mkdirat(data.file.as_raw_fd(), name.as_ptr(), create_mode | 0o700) };
        if res == 0 {
            let entry = self.do_lookup_reserved(parent, name, Some(inode_permit), true)?;
            self.set_guest_metadata(entry.inode, ctx.uid, guest_gid, Some(create_mode))?;
            self.refresh_entry_attr(entry)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, libc::AT_REMOVEDIR)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn readdirplus<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, |dir_entry| {
            let name = CString::new(dir_entry.name).map_err(|_| einval())?;
            let entry = self.do_lookup(inode, name.as_c_str())?;

            add_entry(dir_entry, entry)
        })
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if inode == self.init_inode {
            Ok((Some(self.init_handle), OpenOptions::empty()))
        } else {
            self.do_open(inode, kill_priv, flags)
        }
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        if extensions.secctx.is_some() {
            unimplemented!("SECURITY_CTX is not supported and should not be used by the guest");
        }

        // Reserve both retained descriptors before creating or truncating a file.
        let handle_permit = self.fd_budget.acquire()?;
        let inode_permit = self.fd_budget.acquire()?;
        let (guest_gid, _) = self.prepare_create(&ctx, parent, &extensions)?;
        let _killpriv_guard = if kill_priv {
            drop_effective_cap(Capability::CAP_FSETID)?
        } else {
            None
        };

        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // The writeback cache may read pages of a write-only file and owns
        // `O_APPEND`, as in `open_inode`.
        let mut flags = flags as i32;
        let requested_access = flags & libc::O_ACCMODE;
        if self.writeback.load(Ordering::Relaxed) {
            if requested_access == libc::O_WRONLY {
                flags = (flags & !libc::O_ACCMODE) | libc::O_RDWR;
            }
            flags &= !libc::O_APPEND;
        }

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let mut fd = unsafe {
            libc::openat(
                data.file.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                (mode & !(umask & 0o777)) | 0o600,
            )
        };
        let created = fd >= 0;
        if !created
            && io::Error::last_os_error().raw_os_error() == Some(libc::EEXIST)
            && flags & libc::O_EXCL == 0
        {
            // A stale negative lookup or concurrent host create can reach here.
            // Opening an existing inode must not reset its owner or permissions.
            let open_existing = |flags: i32| unsafe {
                libc::openat(
                    data.file.as_raw_fd(),
                    name.as_ptr(),
                    (flags & !libc::O_CREAT) | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            fd = open_existing(flags);
            if fd < 0
                && flags & libc::O_ACCMODE != requested_access
                && io::Error::last_os_error().raw_os_error() == Some(libc::EACCES)
            {
                fd = open_existing((flags & !libc::O_ACCMODE) | requested_access);
            }
        }
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        let file = RwLock::new(handle_permit.attach(unsafe { File::from_raw_fd(fd) }));

        let entry = self.do_lookup_reserved(parent, name, Some(inode_permit), created)?;
        if created {
            self.set_guest_metadata(
                entry.inode,
                ctx.uid,
                guest_gid,
                Some(mode & !(umask & 0o777)),
            )?;
        }
        let entry = self.refresh_entry_attr(entry)?;

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode: entry.inode,
            file,
            exported: Default::default(),
            directory: RwLock::new(None),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            CachePolicy::Never => opts |= OpenOptions::DIRECT_IO,
            CachePolicy::Always => opts |= OpenOptions::KEEP_CACHE,
            _ => {}
        };

        Ok((entry, Some(handle), opts))
    }

    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name, 0)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        debug!("read: {inode:?}");
        if inode == self.init_inode {
            let off: usize = offset.try_into().map_err(|_| einval())?;
            let len = if off + (size as usize) < INIT_BINARY.len() {
                size as usize
            } else {
                INIT_BINARY.len() - off
            };
            return w.write(&INIT_BINARY[off..(off + len)]);
        }

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // This is safe because write_from uses preadv64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        w.write_from(&f, size as usize, offset)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let _killpriv_guard = if kill_priv {
            // We need to drop FSETID during a write so that the kernel will remove setuid
            // or setgid bits from the file if it was written to by someone other than the
            // owner.
            drop_effective_cap(Capability::CAP_FSETID)?
        } else {
            None
        };

        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // This is safe because read_to uses pwritev64, so the underlying file descriptor
        // offset is not affected by this operation.
        let f = data.file.read().unwrap();
        let result = r.read_to(&f, size as usize, offset);
        if result.is_ok() && kill_priv {
            let inode_data = self
                .inodes
                .read()
                .unwrap()
                .get(&inode)
                .cloned()
                .ok_or_else(ebadf)?;
            if self.override_stat(&inode_data)?.present {
                let st = self.guest_stat(&inode_data)?;
                let mode = clear_suid_sgid(st.st_mode);
                if mode != st.st_mode {
                    self.set_override_stat(&inode_data, None, Some(mode))?;
                }
            }
        }
        result
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(libc::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: libc::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(libc::stat64, Duration)> {
        let inode_data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        enum Data {
            // Kept, not just its descriptor number, so that a concurrent
            // RELEASE cannot close the descriptor while it is used here.
            Handle(Arc<HandleData>),
            ProcPath(CString),
        }

        // If we have a handle then use it otherwise get a new fd from the inode.
        let data = if let Some(handle) = handle {
            let hd = self
                .handles
                .read()
                .unwrap()
                .get(&handle)
                .filter(|hd| hd.inode == inode)
                .cloned()
                .ok_or_else(ebadf)?;
            Data::Handle(hd)
        } else {
            let pathname = CString::new(format!("{}", inode_data.file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Data::ProcPath(pathname)
        };

        if valid.contains(SetattrValid::MODE) {
            if self.override_stat(&inode_data)?.present {
                self.set_override_stat(&inode_data, None, Some(attr.st_mode))?;
            } else {
                // Safe because this doesn't modify any memory and we check the return value.
                let res = unsafe {
                    match data {
                        Data::Handle(ref hd) => {
                            libc::fchmod(hd.file.read().unwrap().as_raw_fd(), attr.st_mode)
                        }
                        Data::ProcPath(ref p) => libc::fchmodat(
                            self.proc_self_fd.as_raw_fd(),
                            p.as_ptr(),
                            attr.st_mode,
                            0,
                        ),
                    }
                };
                if res < 0 {
                    let err = io::Error::last_os_error();
                    if should_store_override_stat_for_setattr_error(&err) {
                        self.set_override_stat(&inode_data, None, Some(attr.st_mode))?;
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        if valid.intersects(SetattrValid::UID | SetattrValid::GID) {
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                // Cannot use -1 here because these are unsigned values.
                u32::MAX
            };

            let st = self.guest_stat(&inode_data)?;
            let mode = clear_suid_sgid(st.st_mode);
            let mode = if mode != st.st_mode { Some(mode) } else { None };
            // A no-op chown of a native whiteout must not attempt user.*
            // xattrs, which Linux does not permit on character devices.
            if (uid != u32::MAX && uid != st.st_uid)
                || (gid != u32::MAX && gid != st.st_gid)
                || mode.is_some()
            {
                self.set_override_stat(&inode_data, Some((uid, gid)), mode)?;
            }
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(ref hd) => unsafe {
                    libc::ftruncate(hd.file.read().unwrap().as_raw_fd(), attr.st_size)
                },
                _ => {
                    // There is no `ftruncateat` so we need to get a new fd and truncate it.
                    let f = self.open_inode(inode, libc::O_NONBLOCK | libc::O_RDWR)?;
                    unsafe { libc::ftruncate(f.as_raw_fd(), attr.st_size) }
                }
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
            let mut tvs = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];

            if valid.contains(SetattrValid::ATIME_NOW) {
                tvs[0].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::ATIME) {
                tvs[0].tv_sec = attr.st_atime;
                tvs[0].tv_nsec = attr.st_atime_nsec;
            }

            if valid.contains(SetattrValid::MTIME_NOW) {
                tvs[1].tv_nsec = libc::UTIME_NOW;
            } else if valid.contains(SetattrValid::MTIME) {
                tvs[1].tv_sec = attr.st_mtime;
                tvs[1].tv_nsec = attr.st_mtime_nsec;
            }

            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(ref hd) => unsafe {
                    libc::futimens(hd.file.read().unwrap().as_raw_fd(), tvs.as_ptr())
                },
                Data::ProcPath(ref p) => unsafe {
                    libc::utimensat(self.proc_self_fd.as_raw_fd(), p.as_ptr(), tvs.as_ptr(), 0)
                },
            };
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.do_getattr(inode)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        let old_inode = self
            .inodes
            .read()
            .unwrap()
            .get(&olddir)
            .cloned()
            .ok_or_else(ebadf)?;
        let new_inode = self
            .inodes
            .read()
            .unwrap()
            .get(&newdir)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        // TODO: Switch to libc::renameat2 once https://github.com/rust-lang/libc/pull/1508 lands
        // and we have glibc 2.28.
        let res = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_inode.file.as_raw_fd(),
                oldname.as_ptr(),
                new_inode.file.as_raw_fd(),
                newname.as_ptr(),
                flags,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn mknod(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        if extensions.secctx.is_some() {
            unimplemented!("SECURITY_CTX is not supported and should not be used by the guest");
        }

        // Reserve before creating a new inode.
        let inode_permit = self.fd_budget.acquire()?;
        let (guest_gid, _) = self.prepare_create(&ctx, parent, &extensions)?;
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let guest_mode = mode & !umask;
        let host_mode = if mode & libc::S_IFMT == libc::S_IFREG {
            guest_mode | 0o600
        } else {
            guest_mode
        };
        let res = unsafe {
            libc::mknodat(
                data.file.as_raw_fd(),
                name.as_ptr(),
                host_mode as libc::mode_t,
                u64::from(rdev),
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            let entry = self.do_lookup_reserved(parent, name, Some(inode_permit), true)?;
            // Native root-owned special inodes need no ownership override.
            // Non-root owners use the filesystem's system namespace instead.
            if mode & libc::S_IFMT != libc::S_IFREG
                && entry.attr.st_uid == ctx.uid
                && entry.attr.st_gid == guest_gid
            {
                return Ok(entry);
            }
            self.set_guest_metadata(entry.inode, ctx.uid, guest_gid, Some(guest_mode))?;
            self.refresh_entry_attr(entry)
        }
    }

    fn link(
        &self,
        _ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;
        let new_inode = self
            .inodes
            .read()
            .unwrap()
            .get(&newparent)
            .cloned()
            .ok_or_else(ebadf)?;

        let procname = CString::new(format!("{}", data.file.as_raw_fd()))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::linkat(
                self.proc_self_fd.as_raw_fd(),
                procname.as_ptr(),
                new_inode.file.as_raw_fd(),
                newname.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if res == 0 {
            self.do_lookup(newparent, newname)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        // Set security context on symlink.
        if extensions.secctx.is_some() {
            unimplemented!("SECURITY_CTX is not supported and should not be used by the guest");
        }

        let inode_permit = self.fd_budget.acquire()?;
        self.prepare_create(&ctx, parent, &extensions)?;
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res =
            unsafe { libc::symlinkat(linkname.as_ptr(), data.file.as_raw_fd(), name.as_ptr()) };
        if res == 0 {
            let entry = self.do_lookup_reserved(parent, name, Some(inode_permit), true)?;
            self.refresh_entry_attr(entry)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let mut buf = vec![0; libc::PATH_MAX as usize];

        // Safe because this is a constant value and a valid C string.
        let empty = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

        // Safe because this will only modify the contents of `buf` and we check the return value.
        let res = unsafe {
            libc::readlinkat(
                data.file.as_raw_fd(),
                empty.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        buf.resize(res as usize, 0);
        Ok(buf)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        // Since this method is called whenever an fd is closed in the client, we can emulate that
        // behavior by doing the same thing (dup-ing the fd and then immediately closing it). Safe
        // because this doesn't modify any memory and we check the return values.
        unsafe {
            let newfd = libc::dup(data.file.write().unwrap().as_raw_fd());
            if newfd < 0 {
                return Err(io::Error::last_os_error());
            }

            if libc::close(newfd) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn fsync(&self, _ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            if datasync {
                libc::fdatasync(fd)
            } else {
                libc::fsync(fd)
            }
        };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.fsync(ctx, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        self.check_access(&ctx, inode, mask, &[])
    }

    fn setxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let host_name = host_xattr_name_for_guest(name)?;

        let res = match self.xattr_target(inode)? {
            FileOrLink::File(file) => {
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::setxattr(
                        proc_fd_path(file.as_raw_fd())?.as_ptr(),
                        host_name.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags as libc::c_int,
                    )
                }
            }
            FileOrLink::Link { path: link, .. } => {
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::lsetxattr(
                        link.as_ptr(),
                        host_name.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags as libc::c_int,
                    )
                }
            }
        };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn getxattr(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        if inode == self.init_inode {
            return Err(io::Error::from_raw_os_error(libc::ENODATA));
        }

        let host_name = host_xattr_name_for_guest(name)?;
        let mut buf = vec![0; size as usize];

        let res = match self.xattr_target(inode)? {
            FileOrLink::File(file) => {
                // Safe because this will only modify the contents of `buf`.
                unsafe {
                    libc::getxattr(
                        proc_fd_path(file.as_raw_fd())?.as_ptr(),
                        host_name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                    )
                }
            }
            FileOrLink::Link { path: link, .. } => {
                // Safe because this will only modify the contents of `buf`.
                unsafe {
                    libc::lgetxattr(
                        link.as_ptr(),
                        host_name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                    )
                }
            }
        };

        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        if size == 0 {
            Ok(GetxattrReply::Count(res as u32))
        } else {
            buf.resize(res as usize, 0);
            Ok(GetxattrReply::Value(buf))
        }
    }

    fn listxattr(&self, _ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let target = self.xattr_target(inode)?;
        let buf = guest_xattr_list_from_host(&list_host_xattrs(&target)?);

        if size == 0 {
            Ok(ListxattrReply::Count(buf.len() as u32))
        } else if (size as usize) < buf.len() {
            Err(io::Error::from_raw_os_error(libc::ERANGE))
        } else {
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        if !self.cfg.xattr {
            return Err(io::Error::from_raw_os_error(libc::ENOSYS));
        }

        let host_name = host_xattr_name_for_guest(name)?;

        let res = match self.xattr_target(inode)? {
            FileOrLink::File(file) => {
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::removexattr(proc_fd_path(file.as_raw_fd())?.as_ptr(), host_name.as_ptr())
                }
            }
            FileOrLink::Link { path: link, .. } => {
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe { libc::lremovexattr(link.as_ptr(), host_name.as_ptr()) }
            }
        };

        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();
        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::fallocate64(
                fd,
                mode as libc::c_int,
                offset as libc::off64_t,
                length as libc::off64_t,
            )
        };
        if res == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn lseek(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|hd| hd.inode == inode)
            .cloned()
            .ok_or_else(ebadf)?;

        let fd = data.file.write().unwrap().as_raw_fd();

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe { libc::lseek(fd, offset as libc::off64_t, whence as libc::c_int) };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as u64)
        }
    }

    fn copyfilerange(
        &self,
        _ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        let data_in = self
            .handles
            .read()
            .unwrap()
            .get(&handle_in)
            .filter(|hd| hd.inode == inode_in)
            .cloned()
            .ok_or_else(ebadf)?;

        // Take just a read lock as we're not going to alter the file descriptor offset.
        let fd_in = data_in.file.read().unwrap().as_raw_fd();

        let data_out = self
            .handles
            .read()
            .unwrap()
            .get(&handle_out)
            .filter(|hd| hd.inode == inode_out)
            .cloned()
            .ok_or_else(ebadf)?;

        // Take just a read lock as we're not going to alter the file descriptor offset.
        let fd_out = data_out.file.read().unwrap().as_raw_fd();

        // Safe because this will only modify `offset_in` and `offset_out` and we check
        // the return value.
        let res = unsafe {
            libc::copy_file_range(
                fd_in,
                &mut (offset_in as i64) as &mut _ as *mut _,
                fd_out,
                &mut (offset_out as i64) as &mut _ as *mut _,
                len.try_into().unwrap(),
                flags.try_into().unwrap(),
            )
        };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(res as usize)
        }
    }

    fn setupmapping(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        // Conservatively reject checkpoints once this window has been used;
        // even removed DAX ranges may now contain PROT_NONE mappings.
        self.dax_used.store(true, Ordering::Relaxed);
        let open_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::O_RDWR
        } else {
            libc::O_RDONLY
        };

        let prot_flags = if (flags & fuse::SetupmappingFlags::WRITE.bits()) != 0 {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        if (moffset + len) > shm_size {
            return Err(einval());
        }

        let addr = host_shm_base + moffset;

        debug!("setupmapping: ino {inode:?} addr={addr:x} len={len}");

        if inode == self.init_inode {
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    len as usize,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if std::ptr::eq(ret, libc::MAP_FAILED) {
                return Err(io::Error::last_os_error());
            }

            let to_copy = if len as usize > INIT_BINARY.len() {
                INIT_BINARY.len()
            } else {
                len as usize
            };
            unsafe {
                libc::memcpy(
                    addr as *mut libc::c_void,
                    INIT_BINARY.as_ptr() as *const _,
                    to_copy,
                )
            };
            return Ok(());
        }

        let file = self.open_inode(inode, open_flags)?;
        let fd = file.as_raw_fd();

        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                prot_flags,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                foffset as libc::off_t,
            )
        };
        if std::ptr::eq(ret, libc::MAP_FAILED) {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        for req in requests {
            let addr = host_shm_base + req.moffset;
            if (req.moffset + req.len) > shm_size {
                return Err(einval());
            }
            debug!("removemapping: addr={:x} len={:?}", addr, req.len);
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    req.len as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0_i64,
                )
            };
            if std::ptr::eq(ret, libc::MAP_FAILED) {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(())
    }

    fn ioctl(
        &self,
        _ctx: Context,
        inode: Self::Inode,
        handle: Self::Handle,
        _flags: u32,
        cmd: u32,
        arg: u64,
        _in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        const VIRTIO_IOC_MAGIC: u8 = b'v';

        const VIRTIO_IOC_TYPE_EXPORT_FD: u8 = 1;
        const VIRTIO_IOC_EXPORT_FD_SIZE: usize = 2 * mem::size_of::<u64>();
        const VIRTIO_IOC_EXPORT_FD_REQ: u32 = request_code_read!(
            VIRTIO_IOC_MAGIC,
            VIRTIO_IOC_TYPE_EXPORT_FD,
            VIRTIO_IOC_EXPORT_FD_SIZE
        ) as u32;

        const VIRTIO_IOC_TYPE_EXIT_CODE: u8 = 2;
        const VIRTIO_IOC_EXIT_CODE_REQ: u32 =
            request_code_none!(VIRTIO_IOC_MAGIC, VIRTIO_IOC_TYPE_EXIT_CODE) as u32;

        const VIRTIO_IOC_REMOVE_ROOT_DIR_CODE: u8 = 3;
        const VIRTIO_IOC_REMOVE_ROOT_DIR_REQ: u32 =
            request_code_none!(VIRTIO_IOC_MAGIC, VIRTIO_IOC_REMOVE_ROOT_DIR_CODE) as u32;

        match cmd {
            VIRTIO_IOC_EXPORT_FD_REQ => {
                if out_size as usize != VIRTIO_IOC_EXPORT_FD_SIZE {
                    return Err(einval());
                }

                let handles = self.handles.read().unwrap();
                let data = handles
                    .get(&handle)
                    .filter(|hd| hd.inode == inode)
                    .ok_or_else(ebadf)?;

                let mut exports = self
                    .cfg
                    .export_table
                    .as_ref()
                    .ok_or(io::Error::from_raw_os_error(libc::EOPNOTSUPP))?
                    .lock()
                    .unwrap();

                let permit = self.fd_budget.acquire()?;
                let fd = data.file.read().unwrap().try_clone()?;
                exports.insert((self.cfg.export_fsid, handle), fd);
                *data.exported.lock().unwrap() = Some(permit);

                let mut ret: Vec<_> = self.cfg.export_fsid.to_ne_bytes().into();
                ret.extend_from_slice(&handle.to_ne_bytes());
                Ok(ret)
            }
            VIRTIO_IOC_EXIT_CODE_REQ => {
                exit_code.store(arg as i32, Ordering::SeqCst);
                Ok(Vec::new())
            }
            VIRTIO_IOC_REMOVE_ROOT_DIR_REQ if self.cfg.allow_root_dir_delete => {
                std::fs::remove_dir_all(&self.cfg.root_dir)?;
                Ok(Vec::new())
            }
            // Unknown ioctls use ENOTTY. OverlayFS treats this as absence of
            // optional file-attribute support; EOPNOTSUPP aborts copy-up.
            _ => Err(io::Error::from_raw_os_error(libc::ENOTTY)),
        }
    }
}

impl Drop for PassthroughFs {
    fn drop(&mut self) {
        self.destroy();
    }
}
