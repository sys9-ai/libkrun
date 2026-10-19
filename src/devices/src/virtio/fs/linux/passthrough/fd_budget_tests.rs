use super::*;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn fd_budget_preopened_proc_survives_chroot() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_preopened_proc_survives_chroot"
    )) {
        return;
    }
    use std::os::fd::IntoRawFd;
    let root = std::env::temp_dir().join(format!("krun-fd-chroot-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let original_root = File::open("/").unwrap();
    let proc = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open("/proc/self/fd")
        .unwrap();
    let path = CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
    // Run this subprocess test with CAP_SYS_CHROOT (for example in Docker).
    let status = unsafe { libc::chroot(path.as_ptr()) };
    if status != 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        eprintln!("chroot regression requires CAP_SYS_CHROOT");
        std::fs::remove_dir(root).unwrap();
        return;
    }
    assert_eq!(status, 0);
    std::env::set_current_dir("/").unwrap();
    assert!(!PathBuf::from("/proc/self/fd").exists());
    let restored = PassthroughFs::new(Config {
        root_dir: "/".into(),
        proc_sfd_rawfd: Some(proc.into_raw_fd()),
        ..Default::default()
    });
    // Restore the child's root before assertions, so failure still cleans up.
    assert_eq!(unsafe { libc::fchdir(original_root.as_raw_fd()) }, 0);
    assert_eq!(unsafe { libc::chroot(c".".as_ptr()) }, 0);
    std::env::set_current_dir("/").unwrap();
    std::fs::remove_dir(root).unwrap();
    assert!(
        restored.is_ok(),
        "preopened proc directory rejected: {:?}",
        restored.err()
    );
}

// RLIMIT is process-wide. Every test runs in its own subprocess, including when
// the parent test runner executes unrelated filesystem tests concurrently.
fn in_child(name: &str) -> bool {
    let name = name.split_once("::").unwrap().1;
    if std::env::var("KRUN_FD_TEST_CHILD").as_deref() == Ok(name) {
        return true;
    }
    let result = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("KRUN_FD_TEST_CHILD", name)
        .output()
        .unwrap();
    assert!(
        result.status.success() && String::from_utf8_lossy(&result.stdout).contains("1 passed"),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    false
}

fn fixture(soft_limit: libc::rlim_t) -> (PathBuf, Arc<PassthroughFs>, Arc<PassthroughFs>) {
    let root = std::env::temp_dir().join(format!("krun-fd-budget-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("home")).unwrap();
    for i in 0..4096 {
        std::fs::write(root.join(format!("f{i}")), b"preserve-me").unwrap();
    }
    let limit = libc::rlimit {
        rlim_cur: soft_limit,
        rlim_max: 2048,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    let make_fs = || {
        let fs = Arc::new(
            PassthroughFs::new(Config {
                root_dir: root.to_str().unwrap().into(),
                ..Default::default()
            })
            .unwrap(),
        );
        fs.init(FsOptions::empty()).unwrap();
        fs
    };
    let first = make_fs();
    let second = make_fs();
    (root, first, second)
}

fn ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}
fn name(i: usize) -> CString {
    CString::new(format!("f{i}")).unwrap()
}

#[test]
fn fd_budget_retains_revalidation_and_recovers_after_forget() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_retains_revalidation_and_recovers_after_forget"
    )) {
        return;
    }
    let (root, fs, other) = fixture(2048);
    let home = fs.do_lookup(fuse::ROOT_ID, c"home").unwrap();
    let mut entries = Vec::new();
    let (failed_index, error) = (0..4096)
        .find_map(|i| match fs.do_lookup(fuse::ROOT_ID, &name(i)) {
            Ok(entry) => {
                entries.push(entry);
                None
            }
            Err(error) => Some((i, error)),
        })
        .expect("pressure must hit the budget");
    assert_eq!(error.raw_os_error(), Some(libc::ENFILE));
    let fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    assert!(fds < 1200, "reserve was consumed: {fds}");
    // Existing ancestor revalidation must still work when no new inode fits.
    assert_eq!(
        fs.do_lookup(fuse::ROOT_ID, c"home").unwrap().inode,
        home.inode
    );
    assert_eq!(
        other
            .do_lookup(fuse::ROOT_ID, &name(failed_index))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENFILE)
    );
    let retained = entries[0].inode;
    assert_eq!(
        fs.do_open(retained, false, (libc::O_WRONLY | libc::O_TRUNC) as u32)
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENFILE)
    );
    assert_eq!(std::fs::read(root.join("f0")).unwrap(), b"preserve-me");
    assert_eq!(
        fs.create(
            ctx(),
            fuse::ROOT_ID,
            c"new",
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default()
        )
        .err()
        .unwrap()
        .raw_os_error(),
        Some(libc::ENFILE)
    );
    assert!(!root.join("new").exists());
    fs.forget(ctx(), entries.pop().unwrap().inode, 1);
    let recovered = other.do_lookup(fuse::ROOT_ID, &name(failed_index)).unwrap();
    other.forget(ctx(), recovered.inode, 1);
    // Released handles return the same shared quota without waiting for FORGET.
    let (handle, _) = fs.do_open(retained, false, libc::O_RDONLY as u32).unwrap();
    assert_eq!(
        other
            .do_lookup(fuse::ROOT_ID, &name(failed_index))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENFILE)
    );
    fs.do_release(retained, handle.unwrap()).unwrap();
    other.do_lookup(fuse::ROOT_ID, &name(failed_index)).unwrap();
    fs.destroy();
    other.destroy();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fd_budget_concurrent_shares_do_not_overcommit() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_concurrent_shares_do_not_overcommit"
    )) {
        return;
    }
    let (root, fs, other) = fixture(2048);
    let workers: Vec<_> = (0..8)
        .map(|worker| {
            let fs = Arc::clone(if worker % 2 == 0 { &fs } else { &other });
            std::thread::spawn(move || {
                for i in (worker..4096).step_by(8) {
                    if let Err(error) = fs.do_lookup(fuse::ROOT_ID, &name(i)) {
                        assert_eq!(error.raw_os_error(), Some(libc::ENFILE));
                        return true;
                    }
                }
                false
            })
        })
        .collect();
    let exhausted = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .filter(|hit| *hit)
        .count();
    assert!(exhausted > 0, "pressure must reach the shared budget");
    assert!(std::fs::read_dir("/proc/self/fd").unwrap().count() < 1200);
    fs.destroy();
    other.destroy();
    // Destruction returns permits held by both inode maps.
    fs.init(FsOptions::empty()).unwrap();
    fs.do_lookup(fuse::ROOT_ID, c"home").unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fd_budget_small_and_changing_soft_limits() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_small_and_changing_soft_limits"
    )) {
        return;
    }
    let (root, fs, other) = fixture(1024);
    let home = fs.do_lookup(fuse::ROOT_ID, c"home").unwrap();
    let failed_index = (0..4096)
        .find(|i| match fs.do_lookup(fuse::ROOT_ID, &name(*i)) {
            Ok(_) => false,
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::ENFILE));
                true
            }
        })
        .unwrap();
    let set_soft = |rlim_cur| {
        let limit = libc::rlimit {
            rlim_cur,
            rlim_max: 2048,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    };
    // Still above actual usage. Shrinking the budget stops growth, but leaves
    // enough descriptors for revalidating the ancestor of an existing mount.
    assert!(std::fs::read_dir("/proc/self/fd").unwrap().count() < 600);
    set_soft(900);
    assert_eq!(
        fs.do_lookup(fuse::ROOT_ID, c"home").unwrap().inode,
        home.inode
    );
    assert_eq!(
        other
            .do_lookup(fuse::ROOT_ID, &name(failed_index))
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENFILE)
    );
    set_soft(2048);
    other.do_lookup(fuse::ROOT_ID, &name(failed_index)).unwrap();
    fs.destroy();
    other.destroy();
    std::fs::remove_dir_all(root).unwrap();
}

fn exhaust(fs: &PassthroughFs, start: usize) -> Vec<Inode> {
    let mut inodes = Vec::new();
    for i in start..4096 {
        match fs.do_lookup(fuse::ROOT_ID, &name(i)) {
            Ok(entry) => inodes.push(entry.inode),
            Err(error) => {
                assert_eq!(error.raw_os_error(), Some(libc::ENFILE));
                return inodes;
            }
        }
    }
    panic!("pressure must reach the budget");
}

#[test]
fn fd_budget_export_duplicates_release_their_permits() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_export_duplicates_release_their_permits"
    )) {
        return;
    }
    let (root, mut fs, other) = fixture(2048);
    let exports: ExportTable = Default::default();
    Arc::get_mut(&mut fs).unwrap().cfg.export_table = Some(exports.clone());
    let inode = fs.do_lookup(fuse::ROOT_ID, c"f0").unwrap().inode;
    let (handle, _) = fs.do_open(inode, false, libc::O_RDONLY as u32).unwrap();
    let handle = handle.unwrap();
    let mut retained = exhaust(&fs, 1);
    let export = || {
        fs.ioctl(
            ctx(),
            inode,
            handle,
            0,
            request_code_read!(b'v', 1, 16) as u32,
            0,
            0,
            16,
            &Arc::new(AtomicI32::new(0)),
        )
    };
    assert_eq!(export().err().unwrap().raw_os_error(), Some(libc::ENFILE));
    fs.forget(ctx(), retained.pop().unwrap(), 1);
    export().unwrap();
    assert_eq!(exports.lock().unwrap().len(), 1);
    assert_eq!(
        other
            .do_lookup(fuse::ROOT_ID, c"home")
            .err()
            .unwrap()
            .raw_os_error(),
        Some(libc::ENFILE)
    );
    fs.do_release(inode, handle).unwrap();
    assert!(exports.lock().unwrap().is_empty());
    other.do_lookup(fuse::ROOT_ID, c"home").unwrap();
    other.do_lookup(fuse::ROOT_ID, c"f0").unwrap();
    fs.destroy();
    other.destroy();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fd_budget_checkpoint_restore_reacquires_permits() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_checkpoint_restore_reacquires_permits"
    )) {
        return;
    }
    let (root, fs, other) = fixture(1024);
    let payloads = root.join("payloads");
    std::fs::create_dir(&payloads).unwrap();
    let inode = fs.do_lookup(fuse::ROOT_ID, c"f0").unwrap().inode;
    fs.do_open(inode, false, libc::O_RDWR as u32).unwrap();
    std::fs::remove_file(root.join("f0")).unwrap();
    let snapshot = fs.capture_state(&payloads).unwrap();
    let second_payloads = root.join("payloads-second");
    std::fs::create_dir(&second_payloads).unwrap();
    let second_snapshot = fs.capture_state(&second_payloads).unwrap();
    exhaust(&fs, 1);
    other.destroy(); // Only returns one root inode permit; restore requires more.
    let error = other.restore_state(snapshot, &payloads).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ENFILE));
    assert!(other.inodes.read().unwrap().values().next().is_none());
    // Dropping the failed restore's local map must return its root permit.
    let limit = libc::rlimit {
        rlim_cur: 2048,
        rlim_max: 2048,
    };
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
    other
        .restore_state(second_snapshot, &second_payloads)
        .unwrap();
    assert_eq!(other.do_getattr(inode).unwrap().0.st_size, 11);
    fs.destroy();
    other.destroy();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn fd_budget_checkpoint_roundtrip_at_capacity() {
    if !in_child(concat!(
        module_path!(),
        "::fd_budget_checkpoint_roundtrip_at_capacity"
    )) {
        return;
    }
    let (root, fs, restored) = fixture(256);
    restored.destroy();
    let inode = fs.do_lookup(fuse::ROOT_ID, c"f0").unwrap().inode;
    let (handle, _) = fs.do_open(inode, false, libc::O_RDWR as u32).unwrap();
    std::fs::remove_file(root.join("f0")).unwrap();
    exhaust(&fs, 1);
    let payloads = root.join("payloads");
    std::fs::create_dir(&payloads).unwrap();
    let state = fs.capture_state(&payloads).unwrap();
    fs.destroy();
    restored.restore_state(state, &payloads).unwrap();
    let handles = restored.handles.read().unwrap();
    let file = handles.get(&handle.unwrap()).unwrap().file.read().unwrap();
    let mut body = [0; 11];
    assert_eq!(
        std::os::unix::fs::FileExt::read_at(&**file, &mut body, 0).unwrap(),
        11
    );
    assert_eq!(&body, b"preserve-me");
    drop(file);
    drop(handles);
    restored.destroy();
    std::fs::remove_dir_all(root).unwrap();
}
