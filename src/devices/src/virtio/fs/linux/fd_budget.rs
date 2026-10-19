//! Bound guest-retained descriptors before exhausting the VMM's descriptor table.
//!
//! The budget is process-wide, including all virtiofs shares. Revalidation of an
//! existing inode uses a temporary descriptor from the reserve, not a new permit.
//! This protects against guest filesystem growth; it does not bound arbitrary
//! growth in other VMM subsystems or survive lowering RLIMIT below current usage.

use std::fs::File;
use std::io;
use std::ops::Deref;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

// Covers concurrent temporary filesystem operations and post-init VMM activity.
// Non-filesystem descriptors already open at initialization are charged separately.
const MAX_INTERNAL_RESERVE: usize = 1024;
static PROCESS_BUDGET: Mutex<Option<Arc<FdBudget>>> = Mutex::new(None);

pub(super) struct FdBudget {
    baseline: usize,
    used: AtomicUsize,
}

impl FdBudget {
    pub(super) fn process() -> io::Result<Arc<Self>> {
        let mut shared = PROCESS_BUDGET.lock().unwrap();
        if let Some(budget) = shared.as_ref() {
            return Ok(Arc::clone(budget));
        }
        // Includes read_dir's temporary descriptor, conservatively overcounting
        // by one. Initialize before any guest-retained descriptors are allocated.
        let baseline = std::fs::read_dir("/proc/self/fd")?
            .try_fold(0, |count, entry| entry.map(|_| count + 1))?;
        let budget = Arc::new(Self {
            baseline,
            used: AtomicUsize::new(0),
        });
        *shared = Some(Arc::clone(&budget));
        Ok(budget)
    }

    pub(super) fn acquire(self: &Arc<Self>) -> io::Result<FdPermit> {
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
        let capacity = available - reserve;
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
                (used < capacity).then_some(used + 1)
            })
            .map_err(|_| io::Error::from_raw_os_error(libc::ENFILE))?;
        Ok(FdPermit(Arc::clone(self)))
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

impl Deref for GuestFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.file
    }
}
