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
use std::sync::{Arc, RwLock};
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

const CURRENT_DIR_CSTR: &[u8] = b".\0";
const PARENT_DIR_CSTR: &[u8] = b"..\0";
const EMPTY_CSTR: &[u8] = b"\0";
const PROC_CSTR: &[u8] = b"/proc/self/fd\0";
const INIT_CSTR: &[u8] = b"init.krun\0";
const XATTR_KEY: &[u8] = b"user.containers.override_stat\0";
const GUEST_XATTR_PREFIX: &[u8] = b"user.containers.guest_xattr.";
const UID_MAX: u32 = u32::MAX - 1;

static INIT_BINARY: &[u8] = include_bytes!(env!("KRUN_INIT_BINARY_PATH"));

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
    // Most of these aren't actually files but ¯\_(ツ)_/¯.
    file: File,
    dev: u64,
    mnt_id: u64,
    refcount: AtomicU64,
}

struct HandleData {
    inode: Inode,
    file: RwLock<File>,
    exported: AtomicBool,
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

fn get_override_xattr(fd: RawFd) -> io::Result<(Option<u32>, Option<u32>, Option<u32>)> {
    if host_fd_is_symlink(fd)? {
        return Ok((None, None, None));
    }

    let mut buf = vec![0; 32];
    let res = unsafe {
        libc::fgetxattr(
            fd,
            XATTR_KEY.as_ptr() as *const libc::c_char,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    let res = if res < 0 {
        let path = proc_fd_path(fd)?;
        unsafe {
            libc::getxattr(
                path.as_ptr(),
                XATTR_KEY.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        }
    } else {
        res
    };
    if res < 0 {
        return Ok((None, None, None));
    }

    buf.resize(res as usize, 0);
    Ok(get_xattr_common(&buf))
}

fn is_missing_override_xattr_error(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(code) if
        code == libc::ENODATA
            || code == libc::ENOTSUP
            || code == libc::EOPNOTSUPP
            || code == libc::EBADF)
}

fn has_override_xattr(fd: RawFd) -> io::Result<bool> {
    if host_fd_is_symlink(fd)? {
        return Ok(false);
    }

    let res = unsafe {
        libc::fgetxattr(
            fd,
            XATTR_KEY.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            0,
        )
    };
    if res >= 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    if !is_missing_override_xattr_error(&err) {
        return Err(err);
    }

    let path = proc_fd_path(fd)?;
    let res = unsafe {
        libc::getxattr(
            path.as_ptr(),
            XATTR_KEY.as_ptr() as *const libc::c_char,
            std::ptr::null_mut(),
            0,
        )
    };
    if res >= 0 {
        return Ok(true);
    }

    let err = io::Error::last_os_error();
    if is_missing_override_xattr_error(&err) {
        Ok(false)
    } else {
        Err(err)
    }
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
    if host_fd_is_symlink(fd)? {
        return Ok(());
    }

    let buf = if is_valid_owner(owner) && mode.is_some() {
        let owner = owner.unwrap();
        let mode = mode.unwrap();
        format!("{}:{}:0{:o}", owner.0, owner.1, mode)
    } else {
        let (orig_uid, orig_gid, orig_mode) = get_override_xattr(fd)?;
        let (uid, gid) = match owner {
            Some((uid, gid)) => {
                let uid = if uid < UID_MAX { Some(uid) } else { orig_uid };
                let gid = if gid < UID_MAX { Some(gid) } else { orig_gid };
                (uid, gid)
            }
            None => (orig_uid, orig_gid),
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
        } else if let Some(orig_mode) = orig_mode {
            buf.push_str(&format!("0{:o}", orig_mode));
        } else {
            buf.push('x');
        }
        buf
    };

    let res = unsafe {
        libc::fsetxattr(
            fd,
            XATTR_KEY.as_ptr() as *const libc::c_char,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
        )
    };
    let res = if res < 0 {
        let path = proc_fd_path(fd)?;
        unsafe {
            libc::setxattr(
                path.as_ptr(),
                XATTR_KEY.as_ptr() as *const libc::c_char,
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
                0,
            )
        }
    } else {
        res
    };
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
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
        if mode & libc::X_OK != 0 && st.st_mode & 0o111 == 0 {
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

fn stat(
    f: &File,
    host_uid: Option<libc::uid_t>,
    host_gid: Option<libc::gid_t>,
) -> io::Result<libc::stat64> {
    let st = host_stat(f)?;
    let (uid, gid, mode) = get_override_xattr(f.as_raw_fd())?;
    Ok(apply_override_stat(st, uid, gid, mode, host_uid, host_gid))
}

fn statx(f: &File) -> io::Result<(libc::stat64, u64)> {
    let mut stx = MaybeUninit::<libc::statx>::zeroed();

    // Safe because this is a constant value and a valid C string.
    let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };

    // Safe because the kernel will only write data in `st` and we check the return
    // value.
    let res = unsafe {
        libc::statx(
            f.as_raw_fd(),
            pathname.as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
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
}

impl Default for Config {
    fn default() -> Self {
        Config {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: Default::default(),
            writeback: false,
            root_dir: String::from("/"),
            xattr: true,
            proc_sfd_rawfd: None,
            export_fsid: 0,
            export_table: None,
            allow_root_dir_delete: false,
        }
    }
}

/// A file system that simply "passes through" all requests it receives to the underlying file
/// system. To keep the implementation simple it servers the contents of its root directory. Users
/// that wish to serve only a specific directory should set up the environment so that that
/// directory ends up as the root of the file system process. One way to accomplish this is via a
/// combination of mount namespaces and the pivot_root system call.
pub struct PassthroughFs {
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
    announce_submounts: AtomicBool,
    supplementary_group_extension: AtomicBool,
    my_uid: Option<libc::uid_t>,
    my_gid: Option<libc::gid_t>,
    cap_fowner: bool,

    cfg: Config,
}

/// Some operations can only be performed on opened FDs without O_PATH, or on symlink paths.
/// This enum encodes a fallback to handle those symlinks separately.
enum FileOrLink {
    File(File),
    Link(CString),
}

fn list_xattr_raw(
    target: &FileOrLink,
    buf: *mut libc::c_char,
    size: libc::size_t,
) -> libc::ssize_t {
    match target {
        FileOrLink::File(file) => unsafe { libc::flistxattr(file.as_raw_fd(), buf, size) },
        FileOrLink::Link(link) => unsafe { libc::llistxattr(link.as_ptr(), buf, size) },
    }
}

fn list_host_xattrs(target: &FileOrLink) -> io::Result<Vec<u8>> {
    let res = list_xattr_raw(target, std::ptr::null_mut(), 0);
    if res < 0 {
        return Err(io::Error::last_os_error());
    }
    if res == 0 {
        return Ok(Vec::new());
    }

    let mut buf = vec![0; res as usize];
    let res = list_xattr_raw(target, buf.as_mut_ptr() as *mut libc::c_char, buf.len());
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

        // Safe because we just opened this fd or it was provided by our caller.
        let proc_self_fd = unsafe { File::from_raw_fd(fd) };

        Ok(PassthroughFs {
            inodes: RwLock::new(MultikeyBTreeMap::new()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 2),
            init_inode: fuse::ROOT_ID + 1,

            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            init_handle: 0,

            proc_self_fd,

            writeback: AtomicBool::new(false),
            announce_submounts: AtomicBool::new(false),
            supplementary_group_extension: AtomicBool::new(false),
            my_uid,
            my_gid,
            cap_fowner,
            cfg,
        })
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
        if writeback && flags & libc::O_ACCMODE == libc::O_WRONLY {
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
        let fd = unsafe {
            libc::openat(
                self.proc_self_fd.as_raw_fd(),
                pathname.as_ptr(),
                (flags | libc::O_CLOEXEC) & (!libc::O_NOFOLLOW),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn open_inode_or_path(&self, inode: Inode, flags: i32) -> io::Result<FileOrLink> {
        match self.open_inode(inode, flags) {
            Ok(a) => Ok(FileOrLink::File(a)),
            Err(e) => {
                if e.raw_os_error() == Some(libc::ELOOP) {
                    let data = self
                        .inodes
                        .read()
                        .unwrap()
                        .get(&inode)
                        .cloned()
                        .ok_or_else(ebadf)?;

                    let pathname = CString::new(format!("/proc/self/fd/{}", data.file.as_raw_fd()))
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    Ok(FileOrLink::Link(pathname))
                } else {
                    Err(e)
                }
            }
        }
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
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
        let (uid, gid, mode) = get_override_xattr(f.as_raw_fd())?;
        let attr = apply_override_stat(st, uid, gid, mode, self.my_uid, self.my_gid);

        let mut attr_flags: u32 = 0;

        if st.st_mode & libc::S_IFMT == libc::S_IFDIR
            && self.announce_submounts.load(Ordering::Relaxed)
            && (st.st_dev != p.dev || mnt_id != p.mnt_id)
        {
            attr_flags |= fuse::ATTR_SUBMOUNT;
        }

        let altkey = InodeAltKey {
            ino: st.st_ino,
            dev: st.st_dev,
            mnt_id,
        };
        let data = self.inodes.read().unwrap().get_alt(&altkey).cloned();

        let inode = if let Some(data) = data {
            // Matches with the release store in `forget`.
            data.refcount.fetch_add(1, Ordering::Acquire);
            data.inode
        } else {
            // There is a possible race here where 2 threads end up adding the same file
            // into the inode list.  However, since each of those will get a unique Inode
            // value and unique file descriptors this shouldn't be that much of a problem.
            let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
            self.inodes.write().unwrap().insert(
                inode,
                InodeAltKey {
                    ino: st.st_ino,
                    dev: st.st_dev,
                    mnt_id,
                },
                Arc::new(InodeData {
                    inode,
                    file: f,
                    dev: st.st_dev,
                    mnt_id,
                    refcount: AtomicU64::new(1),
                }),
            );

            inode
        };

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

        let mut buf = vec![0; size as usize];

        {
            // Since we are going to work with the kernel offset, we have to acquire the file lock
            // for both the `lseek64` and `getdents64` syscalls to ensure that no other thread
            // changes the kernel offset while we are using it.
            let dir = data.file.write().unwrap();

            // Safe because this doesn't modify any memory and we check the return value.
            let res =
                unsafe { libc::lseek64(dir.as_raw_fd(), offset as libc::off64_t, libc::SEEK_SET) };
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

            let dirent64 =
                LinuxDirent64::from_slice(front).expect("unable to get LinuxDirent64 from slice");

            let namelen = dirent64.d_reclen as usize - size_of::<LinuxDirent64>();
            debug_assert!(namelen <= back.len(), "back is smaller than `namelen`");

            let name = &back[..namelen];
            let term = name
                .iter()
                .position(|&a| a == 0)
                .expect("LinuxDirent64 name not NUL-terminated");
            let name = &name[..term];
            let res = if name.starts_with(CURRENT_DIR_CSTR) || name.starts_with(PARENT_DIR_CSTR) {
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

        let file = {
            let _killpriv_guard = if kill_priv {
                drop_effective_cap(Capability::CAP_FSETID)?
            } else {
                None
            };
            RwLock::new(self.open_inode(inode, flags as i32)?)
        };

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            file,
            exported: Default::default(),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));

        let mut opts = OpenOptions::empty();
        match self.cfg.cache_policy {
            // We only set the direct I/O option on files.
            CachePolicy::Never => opts.set(
                OpenOptions::DIRECT_IO,
                flags & (libc::O_DIRECTORY as u32) == 0,
            ),
            CachePolicy::Always => {
                if flags & (libc::O_DIRECTORY as u32) == 0 {
                    opts |= OpenOptions::KEEP_CACHE;
                } else {
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
                if e.get().exported.load(Ordering::Relaxed) {
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

        let st = stat(&data.file, self.my_uid, self.my_gid)?;

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
        set_override_xattr(data.file.as_raw_fd(), Some((uid, gid)), mode)
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

        let st = stat(&data.file, self.my_uid, self.my_gid)?;
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

fn forget_one(
    inodes: &mut MultikeyBTreeMap<Inode, InodeAltKey, Arc<InodeData>>,
    inode: Inode,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode) {
        // Acquiring the write lock on the inode map prevents new lookups from incrementing the
        // refcount but there is the possibility that a previous lookup already acquired a
        // reference to the inode data and is in the process of updating the refcount so we need
        // to loop here until we can decrement successfully.
        loop {
            let refcount = data.refcount.load(Ordering::Relaxed);

            // Saturating sub because it doesn't make sense for a refcount to go below zero and
            // we don't want misbehaving clients to cause integer overflow.
            let new_count = refcount.saturating_sub(count);

            // Synchronizes with the acquire load in `do_lookup`.
            if data
                .refcount
                .compare_exchange(refcount, new_count, Ordering::Release, Ordering::Relaxed)
                .unwrap()
                == refcount
            {
                if new_count == 0 {
                    // We just removed the last refcount for this inode. There's no need for an
                    // acquire fence here because we hold a write lock on the inode map and any
                    // thread that is waiting to do a forget on the same inode will have to wait
                    // until we release the lock. So there's is no other release store for us to
                    // synchronize with before deleting the entry.
                    inodes.remove(&inode);
                }
                break;
            }
        }
    }
}

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
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
                file: f,
                dev: st.st_dev,
                mnt_id,
                refcount: AtomicU64::new(2),
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
        self.handles.write().unwrap().clear();
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
            self.do_lookup(parent, name)
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
        let res = unsafe { libc::mkdirat(data.file.as_raw_fd(), name.as_ptr(), create_mode) };
        if res == 0 {
            let entry = self.do_lookup(parent, name)?;
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
            // Safe because the kernel guarantees that the buffer is nul-terminated. Additionally,
            // the kernel will pad the name with '\0' bytes up to 8-byte alignment and there's no
            // way for us to know exactly how many padding bytes there are. This would cause
            // `CStr::from_bytes_with_nul` to return an error because it would think there are
            // interior '\0' bytes. We trust the kernel to provide us with properly formatted data
            // so we'll just skip the checks here.
            let name = unsafe { CStr::from_bytes_with_nul_unchecked(dir_entry.name) };
            let entry = self.do_lookup(inode, name)?;

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

        // Safe because this doesn't modify any memory and we check the return value. We don't
        // really check `flags` because if the kernel can't handle poorly specified flags then we
        // have much bigger problems.
        let fd = unsafe {
            libc::openat(
                data.file.as_raw_fd(),
                name.as_ptr(),
                flags as i32 | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode & !(umask & 0o777),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Safe because we just opened this fd.
        let file = RwLock::new(unsafe { File::from_raw_fd(fd) });

        let entry = self.do_lookup(parent, name)?;
        self.set_guest_metadata(entry.inode, ctx.uid, guest_gid, None)?;
        let entry = self.refresh_entry_attr(entry)?;

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode: entry.inode,
            file,
            exported: Default::default(),
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
        if result.is_ok() && kill_priv && has_override_xattr(f.as_raw_fd())? {
            let st = stat(&f, self.my_uid, self.my_gid)?;
            let mode = clear_suid_sgid(st.st_mode);
            if mode != st.st_mode {
                set_override_xattr(f.as_raw_fd(), None, Some(mode))?;
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
            Handle(RawFd),
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

            let fd = hd.file.write().unwrap().as_raw_fd();
            Data::Handle(fd)
        } else {
            let pathname = CString::new(format!("{}", inode_data.file.as_raw_fd()))
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            Data::ProcPath(pathname)
        };

        let inode_fd = inode_data.file.as_raw_fd();
        if valid.contains(SetattrValid::MODE) {
            if has_override_xattr(inode_fd)? {
                set_override_xattr(inode_fd, None, Some(attr.st_mode))?;
            } else {
                // Safe because this doesn't modify any memory and we check the return value.
                let res = unsafe {
                    match data {
                        Data::Handle(fd) => libc::fchmod(fd, attr.st_mode),
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
                        set_override_xattr(inode_fd, None, Some(attr.st_mode))?;
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

            let st = stat(&inode_data.file, self.my_uid, self.my_gid)?;
            let mode = clear_suid_sgid(st.st_mode);
            let mode = if mode != st.st_mode { Some(mode) } else { None };
            set_override_xattr(inode_fd, Some((uid, gid)), mode)?;
        }

        if valid.contains(SetattrValid::SIZE) {
            // Safe because this doesn't modify any memory and we check the return value.
            let res = match data {
                Data::Handle(fd) => unsafe { libc::ftruncate(fd, attr.st_size) },
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
                Data::Handle(fd) => unsafe { libc::futimens(fd, tvs.as_ptr()) },
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

        let (guest_gid, _) = self.prepare_create(&ctx, parent, &extensions)?;
        let data = self
            .inodes
            .read()
            .unwrap()
            .get(&parent)
            .cloned()
            .ok_or_else(ebadf)?;

        // Safe because this doesn't modify any memory and we check the return value.
        let res = unsafe {
            libc::mknodat(
                data.file.as_raw_fd(),
                name.as_ptr(),
                (mode & !umask) as libc::mode_t,
                u64::from(rdev),
            )
        };

        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            let entry = self.do_lookup(parent, name)?;
            self.set_guest_metadata(entry.inode, ctx.uid, guest_gid, None)?;
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

        let (guest_gid, _) = self.prepare_create(&ctx, parent, &extensions)?;
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
            // Linux does not allow user xattrs on symlinks. Encode the guest
            // owner directly in host symlink metadata before publishing the
            // inode to the FUSE lookup table.
            let set_owner_result = (|| -> io::Result<()> {
                let fd = unsafe {
                    libc::openat(
                        data.file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                let file = unsafe { File::from_raw_fd(fd) };
                let pathname = unsafe { CStr::from_bytes_with_nul_unchecked(EMPTY_CSTR) };
                let res = unsafe {
                    libc::fchownat(
                        file.as_raw_fd(),
                        pathname.as_ptr(),
                        self.my_uid.unwrap_or(ctx.uid),
                        self.my_gid.unwrap_or(guest_gid),
                        libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if res < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            })();
            if let Err(owner_err) = set_owner_result {
                let rollback_res =
                    unsafe { libc::unlinkat(data.file.as_raw_fd(), name.as_ptr(), 0) };
                if rollback_res < 0 {
                    return Err(io::Error::other(format!(
                        "set symlink guest owner: {owner_err}; rollback unlink: {}",
                        io::Error::last_os_error()
                    )));
                }
                return Err(owner_err);
            }
            let entry = self.do_lookup(parent, name)?;
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

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to get a new fd. This doesn't work for symlinks, so we use the l* family of
        // functions in that case.
        let res = match self.open_inode_or_path(inode, libc::O_RDONLY | libc::O_NONBLOCK)? {
            FileOrLink::File(file) => {
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe {
                    libc::fsetxattr(
                        file.as_raw_fd(),
                        host_name.as_ptr(),
                        value.as_ptr() as *const libc::c_void,
                        value.len(),
                        flags as libc::c_int,
                    )
                }
            }
            FileOrLink::Link(link) => {
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

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to get a new fd. This doesn't work for symlinks, so we use the l* family of
        // functions in that case.
        let res = match self.open_inode_or_path(inode, libc::O_RDONLY | libc::O_NONBLOCK)? {
            FileOrLink::File(file) => {
                // Safe because this will only modify the contents of `buf`.
                unsafe {
                    libc::fgetxattr(
                        file.as_raw_fd(),
                        host_name.as_ptr(),
                        buf.as_mut_ptr() as *mut libc::c_void,
                        size as libc::size_t,
                    )
                }
            }
            FileOrLink::Link(link) => {
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

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to get a new fd. This doesn't work for symlinks, so we use the l* family of
        // functions in that case.
        let target = self.open_inode_or_path(inode, libc::O_RDONLY | libc::O_NONBLOCK)?;
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

        // The f{set,get,remove,list}xattr functions don't work on an fd opened with `O_PATH` so we
        // need to get a new fd. This doesn't work for symlinks, so we use the l* family of
        // functions in that case.
        let res = match self.open_inode_or_path(inode, libc::O_RDONLY | libc::O_NONBLOCK)? {
            FileOrLink::File(file) => {
                // Safe because this doesn't modify any memory and we check the return value.
                unsafe { libc::fremovexattr(file.as_raw_fd(), host_name.as_ptr()) }
            }
            FileOrLink::Link(link) => {
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

                let mut exports = self
                    .cfg
                    .export_table
                    .as_ref()
                    .ok_or(io::Error::from_raw_os_error(libc::EOPNOTSUPP))?
                    .lock()
                    .unwrap();

                let handles = self.handles.read().unwrap();
                let data = handles
                    .get(&handle)
                    .filter(|hd| hd.inode == inode)
                    .ok_or_else(ebadf)?;

                data.exported.store(true, Ordering::Relaxed);

                let fd = data.file.read().unwrap().try_clone()?;

                exports.insert((self.cfg.export_fsid, handle), fd);

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
            _ => Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP)),
        }
    }
}
