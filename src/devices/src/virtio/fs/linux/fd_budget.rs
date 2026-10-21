//! Bound guest-retained descriptors before exhausting the VMM's descriptor table.
//!
//! The budget is process-wide, including all virtiofs shares. Revalidation of an
//! existing inode uses a temporary descriptor from the reserve, not a new permit.
//! This protects against guest filesystem growth; it does not bound arbitrary
//! growth in other VMM subsystems or survive lowering RLIMIT below current usage.
//!
//! Retained descriptors follow the guest's inode cache, not its working set: a
//! guest with spare memory keeps every inode it has seen. Once half the budget
//! is retained, the embedding process is told to have the guest drop unused
//! inodes, whose FORGET requests then return their descriptors.

use nix::{dir::Dir, fcntl::OFlag, sys::stat::Mode};
use std::fs::File;
use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

// Covers concurrent temporary filesystem operations and post-init VMM activity.
// Non-filesystem descriptors already open at initialization are charged separately.
const MAX_INTERNAL_RESERVE: usize = 1024;
static PROCESS_BUDGET: Mutex<Option<Arc<FdBudget>>> = Mutex::new(None);

pub(super) struct FdBudget {
    baseline: usize,
    used: AtomicUsize,
    // Guards the pressure check against a concurrent crossing notification.
    pressure_lock: Mutex<()>,
    pressure: Condvar,
}

/// Descriptors retained for guest inodes and open files, and their current budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescriptorUsage {
    pub used: usize,
    pub capacity: usize,
}

impl DescriptorUsage {
    /// The guest should drop unused inodes at half the budget, leaving the
    /// other half for growth while its FORGET requests arrive.
    pub fn needs_reclaim(&self) -> bool {
        self.used.saturating_mul(2) >= self.capacity
    }
}

fn process_budget() -> Option<Arc<FdBudget>> {
    PROCESS_BUDGET.lock().unwrap().clone()
}

/// Current usage, or `None` before the first passthrough share is created.
pub fn descriptor_usage() -> Option<io::Result<DescriptorUsage>> {
    process_budget().map(|budget| budget.usage())
}

/// Waits up to `timeout` for usage to need reclaim. Returns `None` before the
/// first passthrough share is created.
pub fn wait_descriptor_pressure(timeout: Duration) -> Option<io::Result<bool>> {
    process_budget().map(|budget| budget.wait_pressure(timeout))
}

impl FdBudget {
    pub(super) fn process(proc_self_fd: &File) -> io::Result<Arc<Self>> {
        let mut shared = PROCESS_BUDGET.lock().unwrap();
        if let Some(budget) = shared.as_ref() {
            return Ok(Arc::clone(budget));
        }
        // Reopen through the caller's proc directory: sandboxing may have hidden
        // the absolute path. Includes this temporary descriptor in the baseline.
        let mut directory = Dir::openat(
            proc_self_fd,
            ".",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )?;
        let baseline = directory.iter().try_fold(0, |count, entry| {
            let entry = entry?;
            Ok::<_, nix::errno::Errno>(
                count + usize::from(!matches!(entry.file_name().to_bytes(), b"." | b"..")),
            )
        })?;
        let budget = Arc::new(Self {
            baseline,
            used: AtomicUsize::new(0),
            pressure_lock: Mutex::new(()),
            pressure: Condvar::new(),
        });
        *shared = Some(Arc::clone(&budget));
        Ok(budget)
    }

    fn capacity(&self) -> io::Result<usize> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // Read the current soft limit: administrative changes apply to subsequent
        // allocations without restarting the VM or changing a second setting.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let available = (limit.rlim_cur as usize).saturating_sub(self.baseline);
        // Small limits must still allow boot and a small working set. Preserve
        // half the remaining table until the full 1024-descriptor reserve fits.
        let reserve = MAX_INTERNAL_RESERVE.min(available / 2);
        Ok(available - reserve)
    }

    fn usage(&self) -> io::Result<DescriptorUsage> {
        Ok(DescriptorUsage {
            used: self.used.load(Ordering::Acquire),
            capacity: self.capacity()?,
        })
    }

    pub(super) fn acquire(self: &Arc<Self>) -> io::Result<FdPermit> {
        let capacity = self.capacity()?;
        let previous = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                (used < capacity).then_some(used + 1)
            })
            .map_err(|_| io::Error::from_raw_os_error(libc::ENFILE))?;
        let crossed = |used: usize| DescriptorUsage { used, capacity }.needs_reclaim();
        if !crossed(previous) && crossed(previous + 1) {
            let _guard = self.pressure_lock.lock().unwrap();
            self.pressure.notify_all();
        }
        Ok(FdPermit(Arc::clone(self)))
    }

    fn wait_pressure(&self, timeout: Duration) -> io::Result<bool> {
        let guard = self.pressure_lock.lock().unwrap();
        if self.usage()?.needs_reclaim() {
            return Ok(true);
        }
        // The timeout also picks up capacity changes from a new RLIMIT.
        let _guard = self.pressure.wait_timeout(guard, timeout).unwrap();
        Ok(self.usage()?.needs_reclaim())
    }
}

pub(super) struct FdPermit(Arc<FdBudget>);

impl FdPermit {
    pub(super) fn attach(self, file: File) -> GuestFile {
        GuestFile {
            file,
            _permit: self,
        }
    }
}

impl Drop for FdPermit {
    fn drop(&mut self) {
        self.0.used.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(super) struct GuestFile {
    // Rust drops fields in declaration order: close before returning the permit.
    file: File,
    _permit: FdPermit,
}

impl GuestFile {
    // The replacement is opened from the transient reserve while this file
    // still pins its inode. Closing it transfers its retained slot to the new FD.
    pub(super) fn replace_file(mut self, file: File) -> Self {
        self.file = file;
        self
    }
}

impl Deref for GuestFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}
