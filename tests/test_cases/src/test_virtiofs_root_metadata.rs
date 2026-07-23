use macros::{guest, host};

pub struct TestVirtiofsRootMetadata;

#[host]
mod host {
    use super::*;

    use crate::common::setup_fs_and_enter;
    use crate::{krun_call, krun_call_u32};
    use crate::{Test, TestSetup};
    use krun_sys::*;

    impl Test for TestVirtiofsRootMetadata {
        fn start_vm(self: Box<Self>, test_setup: TestSetup) -> anyhow::Result<()> {
            unsafe {
                let ctx = krun_call_u32!(krun_create_ctx())?;
                krun_call!(krun_set_vm_config(ctx, 1, 512))?;
                setup_fs_and_enter(ctx, test_setup)?;
            }
            Ok(())
        }
    }
}

#[guest]
mod guest {
    use super::*;

    use crate::Test;
    use nix::libc;
    use std::fs::{self, OpenOptions};
    use std::os::unix::fs::{chown, symlink, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::Path;

    const SUPPLEMENTARY_UID: u32 = 22323;
    const SUPPLEMENTARY_GID: u32 = 22324;
    const SHARED_GID: u32 = 22322;

    fn assert_owner_and_mode(path: &Path, uid: u32, gid: u32, mode: u32) {
        let metadata = fs::symlink_metadata(path)
            .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()));
        assert_eq!(
            (metadata.uid(), metadata.gid()),
            (uid, gid),
            "{} owner",
            path.display()
        );
        assert_eq!(metadata.mode() & 0o7777, mode, "{} mode", path.display());
    }

    fn child_create_entries(parent: &Path) -> ! {
        let groups = [SHARED_GID as libc::gid_t];
        let setgroups_result = unsafe { libc::setgroups(groups.len(), groups.as_ptr()) };
        assert_eq!(
            setgroups_result,
            0,
            "setgroups: {}",
            std::io::Error::last_os_error()
        );
        let setgid_result = unsafe { libc::setgid(SUPPLEMENTARY_GID) };
        assert_eq!(
            setgid_result,
            0,
            "setgid: {}",
            std::io::Error::last_os_error()
        );
        let setuid_result = unsafe { libc::setuid(SUPPLEMENTARY_UID) };
        assert_eq!(
            setuid_result,
            0,
            "setuid: {}",
            std::io::Error::last_os_error()
        );

        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(parent.join("file"))
            .expect("create file through supplementary group");
        fs::create_dir(parent.join("dir")).expect("create directory through supplementary group");
        symlink("missing-target", parent.join("symlink"))
            .expect("create symlink through supplementary group");

        unsafe { libc::_exit(0) }
    }

    impl Test for TestVirtiofsRootMetadata {
        fn in_guest(self: Box<Self>) {
            let parent = Path::new("/metadata-parent");
            fs::create_dir(parent).expect("create parent");
            chown(parent, Some(0), Some(SHARED_GID)).expect("chown parent");
            fs::set_permissions(parent, fs::Permissions::from_mode(0o2770)).expect("chmod parent");
            assert_owner_and_mode(parent, 0, SHARED_GID, 0o2770);

            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
            if pid == 0 {
                child_create_entries(parent);
            }

            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(waited, pid, "waitpid: {}", std::io::Error::last_os_error());
            assert!(
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                "child status: {status}"
            );

            assert_owner_and_mode(&parent.join("file"), SUPPLEMENTARY_UID, SHARED_GID, 0o640);
            assert_owner_and_mode(&parent.join("dir"), SUPPLEMENTARY_UID, SHARED_GID, 0o2755);
            assert_owner_and_mode(
                &parent.join("symlink"),
                SUPPLEMENTARY_UID,
                SHARED_GID,
                0o777,
            );

            println!("OK");
        }
    }
}
