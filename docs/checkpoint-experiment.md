# Linux x86 execution checkpoint experiment

The opt-in control endpoint checkpoints CPU, RAM, interrupt controllers and
supported virtio devices while retaining run9's directory-backed virtiofs.
Ordinary VMs do not enter this control path. This is not a general portable
migration format; use identical runtime/kernel, CPU capabilities and topology.

`krun_set_checkpoint_socket` installs a private Unix control socket. Commands
are newline-terminated: `freeze`, `capture /absolute/directory`, and `resume`.
Replies are `OK` or an error; disconnect or failure while frozen is fatal.
A watchdog terminates the VMM if the whole transaction exceeds 30 seconds,
including a device worker stuck in host I/O. Commands are serialized on the VMM
owner thread. vCPU commands carry request IDs and bounded acknowledgment waits.

Freeze pauses every vCPU and then joins device workers before copying RAM or
queue state. The caller forks all writable disks during the frozen interval.
Capture writes a private sparse `memory.bin`, CPU/device state, and deleted-open
file sidecars. `state.bin` is published last. The caller publishes this directory
and its matching disk generation together; it must never mix generations.

`krun_set_restore_path` selects a trusted immutable checkpoint. The VMM validates
CPU, RAM geometry, queue/device topology and filesystem configuration before
resuming. RAM uses private file mappings without populate. Backend paths refer
to independent disk generations. Host file/socket descriptors are recreated;
virtiofs retains guest inode IDs, open handles and bounded directory cookies.
Unlinked inode sidecars stay alive until all restored handles are reopened.

The optional restore-ready socket is bound by the parent before spawning the
VMM. The child connects while paused, restores all state, resumes and sends `R`.
Guest-agent vsock uses a fresh transport; existing network connections must
reconnect. TSC is advanced using elapsed host realtime, then KVM clock is set
following all vCPU state acknowledgments. Host clocks must be synchronized.

Active DAX mappings, exported handles, serial, split irqchip, firmware and TEE
profiles are unsupported and rejected. Checkpoint directory iteration has a
16 MiB per-open-directory bound; the default filesystem path remains streaming.
An inode whose original path disappeared but still has another hard link is
rejected rather than guessed. External side effects, copied PRNG state,
credentials and application identities require fork-safe application design.
There is no universal application restore hook or VM-generation-ID device.

CPU serialization builds on the Apache-2.0 microsandbox libkrun fork at
https://github.com/superradcompany/libkrun/tree/e39792c (msb_krun 0.1.41).
The filesystem implementation and checkpoint protocol are specific to this fork.

Focused real-KVM checks:

```sh
cargo test -p krun-vmm execution_state_survives_source_vm_destruction
cargo test -p krun-devices renamed_open_file_and_directory_survive_backend_replacement
```

Full source-destruction, multi-clone, HTTP and remote-object tests live in the
consuming BoxLite and run9 repositories. Those tests, rather than a register
round-trip alone, qualify execution and persistent filesystem consistency.
