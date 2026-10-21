# Linux virtiofs descriptor budget

Guest-cached inodes and open files share a process-wide host descriptor budget.
New retained descriptors return `ENFILE` before filesystem-driven growth consumes
all of `RLIMIT_NOFILE`. Existing inode lookup still opens and checks a temporary
O_PATH descriptor, but does not need another retained-descriptor permit.

This distinction matters for mount ancestors. If host `openat` fails with EMFILE
during revalidation, Linux 6.12.76 FUSE can invalidate the ancestor dentry and
VFS can detach its descendant mounts. Preventing that host failure preserves the
mount; changing the guest kernel is not part of this implementation.

## Ownership and capacity

The first Linux passthrough backend records the already-open process descriptors
through its proc directory descriptor, including one supplied before sandboxing.
Each allocation reads the current soft `RLIMIT_NOFILE`. From the slots remaining
after that baseline, it reserves the smaller of 1024 or half the remaining slots
for transient operations and later VMM activity. All shares use the same atomic
permit counter. File close precedes permit release, including delayed Arc drops.

Retained inode descriptors, open handles, exported duplicates, and descriptors
reopened during checkpoint restore are charged. Restore also charges temporary
unlinked-file pins that live across multiple reopen operations. The first restored
handle of an unlinked inode takes over its pin and permit, avoiding a second
retained charge for the same handoff. The checkpoint
format does not store a budget; the target process acquires new permits.

Open with truncation and create reserve before changing the host file. Creation
reserves both a possible new inode and its open handle. Lookup of an already
known inode releases an unused reservation. FORGET, RELEASE, backend destruction,
and failed allocations return their permits.

## Reclaim signal

Retained descriptors follow the guest's inode cache, not its working set. A
guest with spare memory keeps every inode it has seen, so touching many files
eventually exhausts the budget even when few are in use at once.
`krun_wait_virtiofs_descriptor_pressure` returns when half the current budget
is retained; `krun_get_virtiofs_descriptor_usage` reports usage and capacity.
The embedding process then has the guest drop unused dentries and inodes. Their
FORGET requests return the descriptors. The crossing wakes waiters immediately;
the wait timeout also picks up capacity changes from a new RLIMIT.

## Bounds

This bounds guest filesystem retention, not arbitrary descriptor growth in other
VMM subsystems. The reserve is finite, and a host administrator must not lower
RLIMIT below current actual usage plus the space needed by concurrent operations.
A process-global budget must be initialized after the embedding application's
fork/exec boundary; BoxLite constructs these backends in its executed shim.

At the budget boundary, new opens can fail even for already-known files. For
example, SQLite may temporarily report CANTOPEN when it cannot open its journal.
The budget does not make an overloaded workload succeed. Once capacity returns,
operations can resume on the preserved mount without recreating the VM. Product
error classification and production rollout are separate work.

## Verification

On Linux, `make test-fd-budget` runs eight subprocess-isolated tests: the
reclaim signal, revalidation and FORGET/RELEASE recovery, concurrent shares,
low and changing limits, exported descriptor release, checkpoint restore
accounting, same-limit restoration at capacity, and a preopened proc directory
after chroot. The last test requires CAP_SYS_CHROOT;
run it as root in Docker to exercise that boundary.
`make test-fs` also covers the existing passthrough and checkpoint tests.

The regression tests use production PassthroughFs operations. Run them on the
unmodified base with only the test module added, then with the complete fix.
The real-VM experiment separately checks mountinfo, device/inode identity, SQLite
writes, host descriptor counts, and guest/host syscall traces under the same
immutable guest kernel. Its results are owned by the integrating BoxLite
investigation record.

The allocation/revalidation separation follows the approach in
[virtiofsd merge request 262](https://gitlab.com/virtio-fs/virtiofsd/-/merge_requests/262).
This is an adaptation for libkrun's inode and handle ownership, not a direct port.
