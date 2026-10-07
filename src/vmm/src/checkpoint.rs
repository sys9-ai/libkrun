// SPDX-License-Identifier: Apache-2.0
//! CPU checkpoint primitives. The caller must additionally quiesce devices before
//! capturing RAM or publishing a complete checkpoint.
use std::io;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::vstate::{VcpuEvent, VcpuResponse, VmState};
use crate::Vmm;

pub(crate) struct CheckpointControl {
    pub(crate) paused: bool,
    devices_quiesced: bool,
    pub(crate) failed: bool,
    request_id: u64,
}

impl Default for CheckpointControl {
    fn default() -> Self {
        Self {
            paused: true,
            devices_quiesced: false,
            failed: false,
            request_id: 0,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ExecutionState {
    vm: VmState,
    vcpus: Vec<Vec<u8>>,
}

impl Vmm {
    /// A failed pause or state operation permanently prohibits resuming this VMM.
    /// Its owner must terminate it rather than retry against ambiguous state.
    pub fn pause_vcpus(&mut self) -> io::Result<()> {
        if self.checkpoint_control.failed {
            return Err(io::Error::other("vCPU control previously failed"));
        }
        if self.checkpoint_control.paused {
            return Ok(());
        }
        self.checkpoint_control.failed = true;
        let deadline = Instant::now() + Duration::from_secs(1);
        for handle in &self.vcpus_handles {
            handle
                .send_event(VcpuEvent::Pause)
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        for handle in &self.vcpus_handles {
            match handle.response_receiver().recv_deadline(deadline) {
                Ok(VcpuResponse::Paused) => (),
                response => {
                    return Err(io::Error::other(format!("vCPU pause failed: {response:?}")))
                }
            }
        }
        self.checkpoint_control.paused = true;
        self.checkpoint_control.failed = false;
        Ok(())
    }

    fn begin_state_operation(&mut self) -> io::Result<u64> {
        if self.checkpoint_control.failed || !self.checkpoint_control.paused {
            return Err(io::Error::other(
                "execution state requires an acknowledged vCPU pause",
            ));
        }
        self.checkpoint_control.failed = true;
        self.checkpoint_control.request_id = self
            .checkpoint_control
            .request_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("vCPU control request counter exhausted"))?;
        Ok(self.checkpoint_control.request_id)
    }

    pub fn capture_execution_state(&mut self) -> io::Result<ExecutionState> {
        let request_id = self.begin_state_operation()?;
        let deadline = Instant::now() + Duration::from_secs(1);
        for handle in &self.vcpus_handles {
            handle
                .send_event(VcpuEvent::CaptureState { request_id })
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        let mut vcpus = Vec::with_capacity(self.vcpus_handles.len());
        for handle in &self.vcpus_handles {
            match handle.response_receiver().recv_deadline(deadline) {
                Ok(VcpuResponse::CapturedState {
                    request_id: id,
                    result,
                }) if id == request_id => {
                    vcpus.push(result.map_err(io::Error::other)?);
                }
                response => {
                    return Err(io::Error::other(format!(
                        "vCPU capture failed: {response:?}"
                    )))
                }
            }
        }
        let vm = self
            .vm
            .save_state()
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.checkpoint_control.failed = false;
        Ok(ExecutionState { vm, vcpus })
    }

    pub fn restore_execution_state(&mut self, state: ExecutionState) -> io::Result<()> {
        if state.vcpus.len() != self.vcpus_handles.len() {
            return Err(io::Error::other(
                "checkpoint vCPU count differs from destination",
            ));
        }
        let request_id = self.begin_state_operation()?;
        self.vm
            .restore_state(&state.vm)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let deadline = Instant::now() + Duration::from_secs(1);
        for (handle, payload) in self.vcpus_handles.iter().zip(state.vcpus) {
            handle
                .send_event(VcpuEvent::RestoreState {
                    request_id,
                    payload,
                })
                .map_err(|e| io::Error::other(e.to_string()))?;
        }
        for handle in &self.vcpus_handles {
            match handle.response_receiver().recv_deadline(deadline) {
                Ok(VcpuResponse::RestoredState {
                    request_id: id,
                    result,
                }) if id == request_id => {
                    result.map_err(io::Error::other)?;
                }
                response => {
                    return Err(io::Error::other(format!(
                        "vCPU restore failed: {response:?}"
                    )))
                }
            }
        }
        self.vm
            .restore_clock(&state.vm)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.checkpoint_control.failed = false;
        Ok(())
    }
}

use devices::virtio::{MmioTransport, TransportSnapshot};
use devices::DeviceType;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use vm_memory::{
    Address, Bytes, FileOffset, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    GuestRegionMmap, MemoryRegionAddress, MmapRegion,
};

const FORMAT: &str = "run9-libkrun-checkpoint-1";
const MAX_STATE_BYTES: usize = 128 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct MemoryRegionState {
    address: u64,
    length: u64,
    offset: u64,
}

#[derive(Serialize, Deserialize)]
struct SavedDevice {
    kind: u32,
    id: String,
    address: u64,
    state: TransportSnapshot,
}

#[derive(Serialize, Deserialize)]
pub struct Checkpoint {
    format: String,
    host_profile: Vec<u32>,
    regions: Vec<MemoryRegionState>,
    execution: ExecutionState,
    devices: Vec<SavedDevice>,
}

fn host_profile() -> Vec<u32> {
    let mut result = Vec::new();
    // Exclude the APIC ID and logical CPU count in CPUID.1.EBX. They describe
    // the host scheduling location, not the compatibility of the saved state.
    for (leaf, subleaf) in [(0, 0), (1, 0), (7, 0), (0x80000001, 0), (0x80000007, 0)] {
        let value = std::arch::x86_64::__cpuid_count(leaf, subleaf);
        result.extend([
            value.eax,
            if leaf == 1 { 0 } else { value.ebx },
            value.ecx,
            value.edx,
        ]);
    }
    result
}

pub fn read_checkpoint(directory: &Path) -> io::Result<Checkpoint> {
    let file = File::open(directory.join("state.bin"))?;
    if file.metadata()?.len() > MAX_STATE_BYTES as u64 {
        return Err(io::Error::other("checkpoint state exceeds size limit"));
    }
    let mut data = Vec::new();
    file.take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut data)?;
    let (state, consumed): (Checkpoint, usize) = bincode::serde::decode_from_slice(
        &data,
        bincode::config::standard().with_limit::<MAX_STATE_BYTES>(),
    )
    .map_err(io::Error::other)?;
    if consumed != data.len() || state.format != FORMAT || state.host_profile != host_profile() {
        return Err(io::Error::other(
            "checkpoint format or host CPU is incompatible",
        ));
    }
    Ok(state)
}

pub fn map_checkpoint_memory(
    directory: &Path,
    expected: &[(GuestAddress, usize)],
    state: &Checkpoint,
) -> io::Result<GuestMemoryMmap> {
    if state.regions.len() != expected.len() {
        return Err(io::Error::other("checkpoint memory topology differs"));
    }
    let memory = File::open(directory.join("memory.bin"))?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0u64;
    let mut regions = Vec::new();
    for (saved, (address, length)) in state.regions.iter().zip(expected) {
        if saved.address != address.raw_value()
            || saved.length != *length as u64
            || saved.offset != offset
            || saved.length == 0
            || saved.offset % page_size as u64 != 0
            || saved.length % page_size as u64 != 0
        {
            return Err(io::Error::other("invalid checkpoint memory region"));
        }
        offset = offset
            .checked_add(saved.length)
            .ok_or_else(|| io::Error::other("checkpoint memory length overflow"))?;
        let mapping = MmapRegion::build(
            Some(FileOffset::new(memory.try_clone()?, saved.offset)),
            *length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
        )
        .map_err(|e| io::Error::other(format!("checkpoint memory mmap: {e:?}")))?;
        regions.push(
            GuestRegionMmap::new(mapping, *address)
                .ok_or_else(|| io::Error::other("invalid checkpoint guest address"))?,
        );
    }
    if memory.metadata()?.len() != offset {
        return Err(io::Error::other("checkpoint memory file length differs"));
    }
    GuestMemoryMmap::from_regions(regions)
        .map_err(|e| io::Error::other(format!("checkpoint memory layout: {e:?}")))
}

impl Vmm {
    /// Called on the event-manager thread. That thread must not dispatch more
    /// device events until capture completes and the devices are resumed.
    pub fn quiesce(&mut self) -> io::Result<()> {
        self.pause_vcpus()?;
        self.checkpoint_control.failed = true;
        for (kind, id, _) in self.mmio_device_manager.checkpoint_devices() {
            let mut bus = self
                .get_bus_device(DeviceType::Virtio(kind), &id)
                .unwrap()
                .lock()
                .unwrap();
            let transport = bus
                .as_mut_any()
                .downcast_mut::<MmioTransport>()
                .ok_or_else(|| io::Error::other("unsupported checkpoint device transport"))?;
            transport.quiesce()?;
        }
        self.checkpoint_control.failed = false;
        self.checkpoint_control.devices_quiesced = true;
        Ok(())
    }

    pub fn capture_checkpoint(&mut self, directory: &Path) -> io::Result<()> {
        if !self.checkpoint_control.paused
            || !self.checkpoint_control.devices_quiesced
            || self.checkpoint_control.failed
        {
            return Err(io::Error::other("checkpoint requires a quiesced VM"));
        }
        std::fs::DirBuilder::new().mode(0o700).create(directory)?;
        let mut devices = Vec::new();
        for (kind, id, address) in self.mmio_device_manager.checkpoint_devices() {
            let payload_dir = directory.join(format!("device-{address:x}"));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&payload_dir)?;
            let bus = self
                .get_bus_device(DeviceType::Virtio(kind), &id)
                .unwrap()
                .lock()
                .unwrap();
            let transport = bus
                .as_any()
                .downcast_ref::<MmioTransport>()
                .ok_or_else(|| io::Error::other("unsupported checkpoint transport"))?;
            devices.push(SavedDevice {
                kind,
                id,
                address,
                state: transport.capture_state(&payload_dir)?,
            });
        }
        let mut memory = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("memory.bin"))?;
        let mut regions = Vec::new();
        let mut offset = 0;
        let mut buffer = vec![0u8; 1024 * 1024];
        for region in self.guest_memory.iter() {
            regions.push(MemoryRegionState {
                address: region.start_addr().raw_value(),
                length: region.len(),
                offset,
            });
            let mut position = 0;
            while position < region.len() {
                let length = buffer.len().min((region.len() - position) as usize);
                region
                    .read_slice(&mut buffer[..length], MemoryRegionAddress(position))
                    .map_err(|e| io::Error::other(format!("checkpoint RAM read: {e}")))?;
                if buffer[..length].iter().all(|byte| *byte == 0) {
                    memory.seek(SeekFrom::Current(length as i64))?;
                } else {
                    memory.write_all(&buffer[..length])?;
                }
                position += length as u64;
            }
            offset += region.len();
        }
        memory.set_len(offset)?;
        memory.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        memory.sync_all()?;
        let state = Checkpoint {
            format: FORMAT.into(),
            host_profile: host_profile(),
            regions,
            execution: self.capture_execution_state()?,
            devices,
        };
        let encoded = bincode::serde::encode_to_vec(state, bincode::config::standard())
            .map_err(io::Error::other)?;
        if encoded.len() > MAX_STATE_BYTES {
            return Err(io::Error::other("checkpoint state exceeds size limit"));
        }
        // state.bin is the completion marker. Partial writes never become a valid generation.
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("state.partial"))?;
        file.write_all(&encoded)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        std::fs::rename(directory.join("state.partial"), directory.join("state.bin"))?;
        File::open(directory)?.sync_all()?;
        Ok(())
    }

    pub fn restore_checkpoint(&mut self, state: Checkpoint, directory: &Path) -> io::Result<()> {
        let expected = self.mmio_device_manager.checkpoint_devices();
        if state.devices.len() != expected.len()
            || state
                .devices
                .iter()
                .zip(&expected)
                .any(|(saved, (kind, id, address))| {
                    saved.kind != *kind || saved.id != *id || saved.address != *address
                })
        {
            return Err(io::Error::other("checkpoint device topology differs"));
        }
        self.restore_execution_state(state.execution)?;
        self.checkpoint_control.failed = true;
        for saved in state.devices {
            let mut bus = self
                .get_bus_device(DeviceType::Virtio(saved.kind), &saved.id)
                .unwrap()
                .lock()
                .unwrap();
            let transport = bus
                .as_mut_any()
                .downcast_mut::<MmioTransport>()
                .ok_or_else(|| io::Error::other("unsupported checkpoint transport"))?;
            transport.restore_state(
                saved.state,
                &directory.join(format!("device-{:x}", saved.address)),
            )?;
        }
        self.checkpoint_control.failed = false;
        Ok(())
    }

    pub fn resume_checkpoint(&mut self) -> io::Result<()> {
        if self.checkpoint_control.failed {
            return Err(io::Error::other("checkpoint operation failed"));
        }
        self.checkpoint_control.failed = true;
        for (kind, id, _) in self.mmio_device_manager.checkpoint_devices() {
            let mut bus = self
                .get_bus_device(DeviceType::Virtio(kind), &id)
                .unwrap()
                .lock()
                .unwrap();
            let transport = bus
                .as_mut_any()
                .downcast_mut::<MmioTransport>()
                .ok_or_else(|| io::Error::other("unsupported checkpoint transport"))?;
            transport.resume()?;
        }
        self.checkpoint_control.failed = false;
        self.checkpoint_control.devices_quiesced = false;
        self.resume_vcpus()
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

use polly::event_manager::{EventManager, Subscriber};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use utils::epoll::{EpollEvent, EventSet};

// A blocked device syscall cannot be cancelled safely while preserving queue
// ownership. Bound the entire transaction and terminate an uncertain VMM.
struct CheckpointDeadline {
    cancel: std::sync::mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl CheckpointDeadline {
    fn start() -> io::Result<Self> {
        let (cancel, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::Builder::new()
            .name("checkpoint deadline".into())
            .spawn(move || {
                if matches!(
                    receiver.recv_timeout(Duration::from_secs(30)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                ) {
                    eprintln!("checkpoint transaction exceeded 30 seconds; terminating VMM");
                    std::process::exit(1);
                }
            })?;
        Ok(Self {
            cancel,
            worker: Some(worker),
        })
    }
}

impl Drop for CheckpointDeadline {
    fn drop(&mut self) {
        let _ = self.cancel.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// A local, serialized transaction endpoint. While frozen, the event-manager
/// thread stays in this transaction and cannot dispatch guest device callbacks.
pub struct CheckpointEndpoint {
    listener: UnixListener,
    vmm: Arc<Mutex<Vmm>>,
}

impl CheckpointEndpoint {
    pub fn bind(path: &Path, vmm: Arc<Mutex<Vmm>>) -> io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, vmm })
    }

    fn transaction(&self, stream: &mut UnixStream) -> io::Result<()> {
        let _deadline = CheckpointDeadline::start()?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut stream = BufReader::new(stream);
        let mut frozen = false;
        loop {
            let mut command = Vec::new();
            let count = stream.by_ref().take(8193).read_until(b'\n', &mut command)?;
            if count == 0 || count > 8192 || command.last() != Some(&b'\n') {
                return Err(io::Error::other("incomplete checkpoint control command"));
            }
            command.pop();
            let command = std::str::from_utf8(&command).map_err(io::Error::other)?;
            match command.split_once(' ').unwrap_or((command, "")) {
                ("freeze", "") if !frozen => {
                    self.vmm.lock().unwrap().quiesce()?;
                    frozen = true;
                }
                ("capture", directory) if frozen && !directory.is_empty() => {
                    self.vmm
                        .lock()
                        .unwrap()
                        .capture_checkpoint(Path::new(directory))?;
                }
                ("resume", "") if frozen => {
                    self.vmm.lock().unwrap().resume_checkpoint()?;
                    stream.get_mut().write_all(b"OK\n")?;
                    return Ok(());
                }
                _ => {
                    return Err(io::Error::other(
                        "expected freeze, capture <directory>, or resume",
                    ))
                }
            }
            stream.get_mut().write_all(b"OK\n")?;
        }
    }
}

impl Subscriber for CheckpointEndpoint {
    fn interest_list(&self) -> Vec<EpollEvent> {
        vec![EpollEvent::new(
            EventSet::IN,
            self.listener.as_raw_fd() as u64,
        )]
    }

    fn process(&mut self, _: &EpollEvent, _: &mut EventManager) {
        match self.listener.accept() {
            Ok((mut stream, _)) => {
                if let Err(error) = self.transaction(&mut stream) {
                    let message = error.to_string().replace(['\n', '\r'], " ");
                    let _ = writeln!(stream, "ERROR {message}");
                    eprintln!("checkpoint transaction failed: {message}");
                    error!("checkpoint transaction failed; terminating inconsistent VMM: {error}");
                    // A dropped controller must never release an uncertain pause
                    // or leave a quiesced VM accepting normal device events.
                    std::process::exit(1);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) => error!("checkpoint accept failed: {error}"),
        }
    }
}
