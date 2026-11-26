// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::cmp;
use std::convert::From;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
#[cfg(target_os = "macos")]
use std::os::macos::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::os::{fd::AsRawFd, linux::fs::MetadataExt};
use std::path::PathBuf;
use std::result;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::JoinHandle;

use imago::{
    file::File as ImagoFile, qcow2::Qcow2, raw::Raw, vmdk::Vmdk, DynStorage, FormatDriverBuilder,
    PermissiveImplicitOpenGate, Storage, StorageOpenOptions, SyncFormatAccess,
};
use log::{error, warn};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::{
    virtio_blk::*, virtio_config::VIRTIO_F_VERSION_1, virtio_ring::VIRTIO_RING_F_EVENT_IDX,
};
use vm_memory::{ByteValued, GuestMemoryMmap};

use super::worker::BlockWorker;
use super::{
    super::{ActivateResult, DeviceQueue, DeviceState, QueueConfig, VirtioDevice, TYPE_BLOCK},
    Error, NUM_QUEUES, QUEUE_CONFIG, SECTOR_SHIFT, SECTOR_SIZE,
};

use crate::virtio::{
    block::{ImageType, SyncMode},
    ActivateError, InterruptTransport,
};

/// Configuration options for disk caching.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CacheType {
    /// Flushing mechanic will be advertised to the guest driver, but
    /// the operation will be a noop.
    #[default]
    Unsafe,
    /// Flushing mechanic will be advertised to the guest driver and
    /// flush requests coming from the guest will be performed using
    /// `fsync`.
    Writeback,
}

impl CacheType {
    /// Picks the appropriate cache type based on disk image or device path.
    /// Special files like `/dev/rdisk*` on macOS do not support flush/sync.
    pub fn auto(_path: &str) -> CacheType {
        #[cfg(target_os = "macos")]
        if _path.starts_with("/dev/rdisk") {
            return CacheType::Unsafe;
        }
        CacheType::Writeback
    }
}

#[cfg(target_os = "linux")]
pub(super) struct RawBlock {
    file: File,
    sectors_per_block: u64,
}

#[cfg(target_os = "linux")]
impl RawBlock {
    fn new(file: &File, open: &OpenOptions) -> io::Result<Self> {
        nix::ioctl_read_bad!(blksszget, libc::BLKSSZGET, libc::c_int);
        let mut bytes = 0;
        // SAFETY: BLKSSZGET writes one integer on a live block device.
        unsafe { blksszget(file.as_raw_fd(), &mut bytes) }?;
        let bytes = u64::try_from(bytes).unwrap_or(0);
        if bytes < SECTOR_SIZE || !bytes.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid logical block size",
            ));
        }
        Ok(Self {
            // Reopen the pinned inode, including its access mode. A dup shares
            // f_wb_err: an advisory trim must not consume a guest flush error.
            file: open.open(format!("/proc/self/fd/{}", file.as_raw_fd()))?,
            sectors_per_block: bytes / SECTOR_SIZE,
        })
    }

    fn discard(&self, start: u64, end: u64) -> io::Result<()> {
        // A hint may omit a partial logical block, but must never include bytes
        // outside the guest's range. The caller bounded both ends by capacity.
        let first = start.next_multiple_of(self.sectors_per_block);
        let last = end / self.sectors_per_block * self.sectors_per_block;
        if first >= last {
            return Ok(());
        }
        let range = [first * SECTOR_SIZE, (last - first) * SECTOR_SIZE];
        nix::ioctl_write_ptr_bad!(blkdiscard, 0x1277, [u64; 2]);
        // SAFETY: BLKDISCARD reads the two native u64 values in range.
        let trim = || unsafe { blkdiscard(self.file.as_raw_fd(), &range) };
        let mut result = trim();
        if result == Err(nix::errno::Errno::EBUSY) {
            // BoxLite holds its exclusive claim on a separate description.
            // Linux cannot invalidate dirty buffered writes under that claim.
            self.file.sync_all()?;
            result = trim();
        }
        match result {
            // A pinned range or a device without discard may retain the bytes.
            Ok(_) | Err(nix::errno::Errno::EBUSY | nix::errno::Errno::EOPNOTSUPP) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}

type Image = SyncFormatAccess<Box<dyn DynStorage>>;

/// Helper object for setting up all `Block` fields derived from its backing file.
pub(crate) struct DiskProperties {
    #[cfg(target_os = "linux")]
    raw_block: Option<Arc<RawBlock>>,
    cache_type: CacheType,
    file: Arc<RwLock<Image>>,
    nsectors: u64,
    image_id: Vec<u8>,
}

impl DiskProperties {
    pub(super) fn new(
        disk_image: Arc<RwLock<Image>>,
        disk_image_id: Vec<u8>,
        cache_type: CacheType,
        #[cfg(target_os = "linux")] raw_block: Option<Arc<RawBlock>>,
    ) -> io::Result<Self> {
        let disk_size = disk_image
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .size();

        // We only support disk size, which uses the first two words of the configuration space.
        // If the image is not a multiple of the sector size, the tail bits are not exposed.
        if !disk_size.is_multiple_of(SECTOR_SIZE) {
            warn!(
                "Disk size {disk_size} is not a multiple of sector size {SECTOR_SIZE}; \
                 the remainder will not be visible to the guest."
            );
        }

        Ok(Self {
            #[cfg(target_os = "linux")]
            raw_block,
            cache_type,
            nsectors: disk_size >> SECTOR_SHIFT,
            image_id: disk_image_id,
            file: disk_image,
        })
    }

    /// The image for a request. imago serves concurrent requests, so the I/O
    /// threads share it. A panic in one request leaves the image usable, so a
    /// poisoned lock is not an error.
    pub(crate) fn image(&self) -> RwLockReadGuard<'_, Image> {
        self.file.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The image alone, for a discard. A discard can invalidate the data
    /// mappings of concurrent requests (hence imago's `&mut self`), and must
    /// not land inside an unaligned write's read-modify-write, which would
    /// bring the discarded bytes back.
    pub(crate) fn image_mut(&self) -> RwLockWriteGuard<'_, Image> {
        self.file.write().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn discard(&self, sector: u64, sectors: u32) -> io::Result<()> {
        let count = u64::from(sectors);
        if sector > self.nsectors || count > self.nsectors - sector {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if count == 0 {
            return Ok(());
        }
        let mut image = self.image_mut();
        #[cfg(target_os = "linux")]
        if let Some(raw) = &self.raw_block {
            return raw.discard(sector, sector + count);
        }
        image.discard_to_any(sector * SECTOR_SIZE, count * SECTOR_SIZE)
    }

    pub fn nsectors(&self) -> u64 {
        self.nsectors
    }

    pub fn image_id(&self) -> &[u8] {
        &self.image_id
    }

    fn build_device_id(disk_file: &File) -> result::Result<String, Error> {
        let blk_metadata = disk_file.metadata().map_err(Error::GetFileMetadata)?;
        // This is how kvmtool does it.
        let device_id = format!(
            "{}{}{}",
            blk_metadata.st_dev(),
            blk_metadata.st_rdev(),
            blk_metadata.st_ino()
        );
        Ok(device_id)
    }

    fn build_disk_image_id(disk_file: &File) -> Vec<u8> {
        let mut default_id = vec![0; VIRTIO_BLK_ID_BYTES as usize];
        match Self::build_device_id(disk_file) {
            Err(_) => {
                warn!("Could not generate device id. We'll use a default.");
            }
            Ok(m) => {
                // The kernel only knows to read a maximum of VIRTIO_BLK_ID_BYTES.
                // This will also zero out any leftover bytes.
                let disk_id = m.as_bytes();
                let bytes_to_copy = cmp::min(disk_id.len(), VIRTIO_BLK_ID_BYTES as usize);
                default_id[..bytes_to_copy].clone_from_slice(&disk_id[..bytes_to_copy])
            }
        }
        default_id
    }

    pub fn cache_type(&self) -> CacheType {
        self.cache_type
    }
}

impl Drop for DiskProperties {
    fn drop(&mut self) {
        match self.cache_type {
            CacheType::Writeback => {
                // flush() first to force any cached data out.
                if self.image().flush().is_err() {
                    error!("Failed to flush block data on drop.");
                }
                // Sync data out to physical media on host.
                if self.image().sync().is_err() {
                    error!("Failed to sync block data on drop.")
                }
            }
            CacheType::Unsafe => {
                // This is a noop.
            }
        };
    }
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkGeometry {
    cylinders: u16,
    heads: u8,
    sectors: u8,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkTopology {
    physical_block_exp: u8,
    alignment_offset: u8,
    min_io_size: u16,
    opt_io_size: u32,
}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioBlkConfig {
    capacity: u64,
    size_max: u32,
    seg_max: u32,
    geometry: VirtioBlkGeometry,
    blk_size: u32,
    topology: VirtioBlkTopology,
    writeback: u8,
    unused0: u8,
    num_queues: u16,
    max_discard_sectors: u32,
    max_discard_seg: u32,
    discard_sector_alignment: u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_seg: u32,
    write_zeroes_may_unmap: u8,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioBlkConfig {}

/// Virtio device for exposing block level read/write operations on a host file.
pub struct Block {
    // Host file and properties.
    disk: Option<DiskProperties>,
    #[cfg(target_os = "linux")]
    raw_block: Option<Arc<RawBlock>>,
    cache_type: CacheType,
    disk_image: Arc<RwLock<Image>>,
    disk_image_id: Vec<u8>,
    worker_thread: Option<JoinHandle<BlockWorker>>,
    paused_worker: Option<BlockWorker>,
    worker_stopfd: EventFd,

    // Virtio fields.
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    config: VirtioBlkConfig,

    // Transport related fields.
    pub(crate) device_state: DeviceState,

    // Implementation specific fields.
    pub(crate) id: String,
    pub(crate) partuuid: Option<String>,
}

impl Block {
    /// Create a new virtio block device that operates on the given file.
    ///
    /// The given file must be seekable and sizable.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: String,
        partuuid: Option<String>,
        cache_type: CacheType,
        disk_image_path: String,
        disk_image_format: ImageType,
        is_disk_read_only: bool,
        direct_io: bool,
        sync_mode: SyncMode,
    ) -> io::Result<Block> {
        let mut open = OpenOptions::new();
        open.read(true).write(!is_disk_read_only);
        #[cfg(target_os = "linux")]
        if direct_io {
            open.custom_flags(libc::O_DIRECT);
        }
        let disk_image = open.open(PathBuf::from(&disk_image_path))?;

        let disk_image_id = DiskProperties::build_disk_image_id(&disk_image);

        let file_opts = StorageOpenOptions::new()
            .write(!is_disk_read_only)
            .filename(disk_image_path)
            .direct(direct_io);

        #[cfg(target_os = "macos")]
        let file_opts = file_opts.relaxed_sync(sync_mode == SyncMode::Relaxed);
        #[cfg(target_os = "linux")]
        let raw_block = if disk_image_format == ImageType::Raw
            && disk_image.metadata()?.file_type().is_block_device()
        {
            Some(Arc::new(RawBlock::new(&disk_image, &open)?))
        } else {
            None
        };
        #[cfg(target_os = "linux")]
        let file = ImagoFile::from_open_file(disk_image, file_opts)?;
        #[cfg(not(target_os = "linux"))]
        let file = ImagoFile::open_sync(file_opts)?;
        let discard_alignment = file.discard_align();
        #[cfg(target_os = "linux")]
        let discard_alignment = raw_block.as_ref().map_or(discard_alignment, |raw| {
            (raw.sectors_per_block * SECTOR_SIZE) as usize
        });

        let disk_image = match disk_image_format {
            ImageType::Qcow2 => {
                let mut qcow2 =
                    Qcow2::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::open_image_sync(
                        Box::new(file),
                        !is_disk_read_only,
                    )?;
                qcow2.open_implicit_dependencies_sync()?;
                SyncFormatAccess::new(qcow2)?
            }
            ImageType::Raw => {
                let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(
                    Box::new(file),
                    !is_disk_read_only,
                )?;
                SyncFormatAccess::new(raw)?
            }
            ImageType::Vmdk => {
                let vmdk = Vmdk::<Box<dyn DynStorage>, Arc<imago::FormatAccess<_>>>::builder(
                    Box::new(file),
                )
                .open_sync(PermissiveImplicitOpenGate::default())?;
                SyncFormatAccess::new(vmdk)?
            }
        };

        let disk_image = Arc::new(RwLock::new(disk_image));

        let disk_properties = DiskProperties::new(
            disk_image.clone(),
            disk_image_id.clone(),
            cache_type,
            #[cfg(target_os = "linux")]
            raw_block.clone(),
        )?;

        let mut avail_features = (1u64 << VIRTIO_F_VERSION_1)
            | (1u64 << VIRTIO_BLK_F_SEG_MAX)
            | (1u64 << VIRTIO_BLK_F_DISCARD)
            | (1u64 << VIRTIO_BLK_F_WRITE_ZEROES)
            | (1u64 << VIRTIO_RING_F_EVENT_IDX);

        if sync_mode != SyncMode::None {
            avail_features |= 1u64 << VIRTIO_BLK_F_FLUSH;
        }

        if is_disk_read_only {
            avail_features |= 1u64 << VIRTIO_BLK_F_RO;
        };

        let config = VirtioBlkConfig {
            capacity: disk_properties.nsectors(),
            size_max: 0,
            // QUEUE_SIZE - 2
            seg_max: 254,
            max_discard_sectors: u32::MAX,
            max_discard_seg: 1,
            discard_sector_alignment: discard_alignment as u32 / 512,
            max_write_zeroes_sectors: u32::MAX,
            max_write_zeroes_seg: 1,
            write_zeroes_may_unmap: 1,
            ..Default::default()
        };

        Ok(Block {
            id,
            partuuid,
            config,
            disk: Some(disk_properties),
            #[cfg(target_os = "linux")]
            raw_block,
            cache_type,
            disk_image,
            disk_image_id,
            avail_features,
            acked_features: 0u64,
            device_state: DeviceState::Inactive,
            worker_thread: None,
            paused_worker: None,
            worker_stopfd: EventFd::new(EFD_NONBLOCK)?,
        })
    }

    /// Provides the ID of this block device.
    pub fn id(&self) -> &String {
        &self.id
    }

    /// Provides the PARTUUID of this block device.
    pub fn partuuid(&self) -> Option<&String> {
        self.partuuid.as_ref()
    }

    /// Specifies if this block device is read only.
    pub fn is_read_only(&self) -> bool {
        self.avail_features & (1u64 << VIRTIO_BLK_F_RO) != 0
    }
}

impl VirtioDevice for Block {
    fn quiesce(&mut self) -> io::Result<()> {
        if let Some(worker) = self.worker_thread.take() {
            self.worker_stopfd.write(1)?;
            self.paused_worker = Some(
                worker
                    .join()
                    .map_err(|_| io::Error::other("block worker panicked"))?,
            );
        }
        let disk = self
            .disk_image
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        disk.flush()?;
        disk.sync()?;
        Ok(())
    }

    fn capture_state(
        &self,
        _directory: &std::path::Path,
    ) -> io::Result<crate::virtio::DeviceSnapshot> {
        let worker = self
            .paused_worker
            .as_ref()
            .ok_or_else(|| io::Error::other("block worker is not paused"))?;
        let mut payload = self.config.as_slice().to_vec();
        payload.extend_from_slice(&self.disk_image_id);
        Ok(crate::virtio::DeviceSnapshot {
            queues: vec![worker.device_queue.queue.capture_state()],
            payload,
        })
    }

    fn restore_state(&mut self, payload: &[u8], _directory: &std::path::Path) -> io::Result<()> {
        let config = self.config.as_slice();
        if payload.len() != config.len() + VIRTIO_BLK_ID_BYTES as usize
            || &payload[..config.len()] != config
        {
            return Err(io::Error::other("checkpoint block geometry differs"));
        }
        self.disk_image_id = payload[config.len()..].to_vec();
        if let Some(disk) = &mut self.disk {
            disk.image_id = self.disk_image_id.clone();
        }
        Ok(())
    }

    fn resume(&mut self) -> io::Result<()> {
        if let Some(worker) = self.paused_worker.take() {
            self.worker_thread = Some(worker.run()?);
        }
        Ok(())
    }

    fn device_type(&self) -> u32 {
        TYPE_BLOCK
    }

    fn device_name(&self) -> &str {
        "block"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, _offset: u64, _data: &[u8]) {
        error!("Guest attempted to write config");
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.worker_thread.is_some() {
            panic!("virtio_blk: worker thread already exists");
        }

        let [blk_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        let disk = match self.disk.take() {
            Some(d) => d,
            None => DiskProperties::new(
                Arc::clone(&self.disk_image),
                self.disk_image_id.clone(),
                self.cache_type,
                #[cfg(target_os = "linux")]
                self.raw_block.clone(),
            )
            .map_err(|_| ActivateError::BadActivate)?,
        };

        let worker = BlockWorker::new(
            blk_q,
            interrupt.clone(),
            mem.clone(),
            disk,
            self.worker_stopfd.try_clone().unwrap(),
        );
        self.worker_thread = Some(worker.run().map_err(|e| {
            error!("Cannot start the virtio-blk worker: {e}");
            ActivateError::BadActivate
        })?);

        self.device_state = DeviceState::Activated(mem, interrupt);
        Ok(())
    }

    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker_thread.take() {
            let _ = self.worker_stopfd.write(1);
            if let Err(e) = worker.join() {
                error!("error waiting for worker thread: {e:?}");
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(test)]
mod discard_tests {
    use super::*;
    use std::os::unix::fs::FileExt;
    use utils::tempfile::TempFile;

    fn discard_tail(path: &std::path::Path) {
        let block = Block::new(
            "scratch".into(),
            None,
            CacheType::Writeback,
            path.to_str().unwrap().into(),
            ImageType::Raw,
            false,
            false,
            SyncMode::None,
        )
        .unwrap();
        let disk = block.disk.as_ref().unwrap();
        let last = disk.nsectors() - 8;
        assert!(disk.discard(last, 9).is_err());
        disk.discard(last, 8).unwrap();
    }

    #[test]
    fn raw_image_tail_discard_preserves_capacity() {
        let image = TempFile::new().unwrap();
        let file = image.as_file();
        file.set_len(2 << 20).unwrap();
        file.write_all_at(&[9; 4096], (2 << 20) - 4096).unwrap();
        discard_tail(image.as_path());
        assert_eq!(file.metadata().unwrap().len(), 2 << 20);
        let mut data = [1; 4096];
        file.read_exact_at(&mut data, (2 << 20) - 4096).unwrap();
        assert_eq!(data, [0; 4096]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "creates a fresh loop device on a privileged Linux test host"]
    fn raw_block_tail_discard_reaches_device() {
        use std::process::Command;
        let image = TempFile::new().unwrap();
        let file = image.as_file();
        file.set_len(2 << 20).unwrap();
        file.write_all_at(&[7; 4096], 0).unwrap();
        file.write_all_at(&[9; 4096], (2 << 20) - 4096).unwrap();
        let bind = Command::new("losetup")
            .args(["--find", "--show", "--sector-size", "4096"])
            .arg(image.as_path())
            .output()
            .unwrap();
        assert!(bind.status.success());
        struct Loop(String);
        impl Drop for Loop {
            fn drop(&mut self) {
                let _ = Command::new("losetup").args(["-d", &self.0]).status();
            }
        }
        let device = Loop(String::from_utf8(bind.stdout).unwrap().trim().into());
        let claim = File::options()
            .read(true)
            .write(true)
            .custom_flags(libc::O_EXCL)
            .open(&device.0)
            .unwrap();
        // A dup shares both the file offset and writeback-error cursor. An
        // advisory discard must observe failures independently of guest fsync.
        use std::io::{Seek, SeekFrom};
        let mut data_fd = File::options()
            .read(true)
            .write(true)
            .open(&device.0)
            .unwrap();
        let mut discard_fd =
            RawBlock::new(&data_fd, File::options().read(true).write(true)).unwrap();
        data_fd.seek(SeekFrom::Start(4096)).unwrap();
        assert_eq!(discard_fd.file.stream_position().unwrap(), 0);
        // Preserve the two partial ends and trim the middle block, even before
        // the guest flushes its buffered writes on the separately claimed disk.
        claim.write_all_at(&[3; 12288], 4096).unwrap();
        let block = Block::new(
            "scratch".into(),
            None,
            CacheType::Writeback,
            device.0.clone(),
            ImageType::Raw,
            false,
            false,
            SyncMode::None,
        )
        .unwrap();
        block.disk.as_ref().unwrap().discard(9, 16).unwrap();
        let mut observed = [0; 12288];
        claim.read_exact_at(&mut observed, 4096).unwrap();
        assert_eq!(observed[..4096], [3; 4096]);
        assert_eq!(observed[4096..8192], [0; 4096]);
        assert_eq!(observed[8192..], [3; 4096]);
        discard_tail(std::path::Path::new(&device.0));
        let mut data = [1; 4096];
        file.read_exact_at(&mut data, 0).unwrap();
        assert_eq!(data, [7; 4096]);
        file.read_exact_at(&mut data, (2 << 20) - 4096).unwrap();
        assert_eq!(data, [0; 4096]);
        assert_eq!(file.metadata().unwrap().len(), 2 << 20);
    }
}
