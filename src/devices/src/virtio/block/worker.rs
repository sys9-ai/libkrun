use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::{DescriptorChain, DeviceQueue, Queue};
use super::device::{CacheType, DiskProperties};

use crate::virtio::InterruptTransport;
use crossbeam_channel::Sender;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::result;
use std::sync::Mutex;
use std::thread;
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use virtio_bindings::virtio_blk::*;
use vm_memory::{ByteValued, GuestMemoryMmap};

#[allow(dead_code)]
#[derive(Debug)]
pub enum RequestError {
    Discarding(io::Error),
    DiscardingToZero(io::Error),
    FlushingToDisk(io::Error),
    InvalidDataLength,
    ReadingFromDescriptor(io::Error),
    WritingToDescriptor(io::Error),
    WritingZeroes(io::Error),
    UnknownRequest,
}

/// The request header represents the mandatory fields of each block device request.
///
/// A request header contains the following fields:
///   * request_type: an u32 value mapping to a read, write or flush operation.
///   * reserved: 32 bits are reserved for future extensions of the Virtio Spec.
///   * sector: an u64 value representing the offset where a read/write is to occur.
///
/// The header simplifies reading the request from memory as all request follow
/// the same memory layout.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RequestHeader {
    request_type: u32,
    _reserved: u32,
    sector: u64,
}
// Safe because RequestHeader only contains plain data.
unsafe impl ByteValued for RequestHeader {}

#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct DiscardWriteData {
    sector: u64,
    num_sectors: u32,
    flags: u32,
}
// Safe because DiscardWriteData only contains plain data.
unsafe impl ByteValued for DiscardWriteData {}

/// Requests the device serves at once. The guest queues many requests, and
/// each I/O blocks its thread for the backend's whole latency: a cold read of
/// a userspace NBD disk waits for an object store GET. With one thread, guest
/// queue depth 16 became queue depth 1 at the host.
const IO_THREADS: usize = 16;

pub struct BlockWorker {
    pub(super) device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
}

impl BlockWorker {
    pub fn new(
        device_queue: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        disk: DiskProperties,
        stop_fd: EventFd,
    ) -> Self {
        Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
        }
    }

    pub fn run(self) -> thread::JoinHandle<Self> {
        thread::Builder::new()
            .name("block worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) -> Self {
        self.serve_until_stopped();
        self
    }

    /// Pops requests on this thread and serves them on IO_THREADS scoped
    /// threads, which complete them in any order, as virtio allows. Stopping
    /// waits for every popped request to complete, so a quiesced queue has
    /// nothing in flight.
    fn serve_until_stopped(&mut self) {
        let Self {
            device_queue,
            interrupt,
            mem,
            disk,
            stop_fd,
        } = self;
        let queue_event = &device_queue.event;
        let virtq_ev_fd = queue_event.as_raw_fd();
        let stop_ev_fd = stop_fd.as_raw_fd();
        let queue = Mutex::new(&mut device_queue.queue);
        let (requests, pending) = crossbeam_channel::unbounded();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_ev_fd as u64),
        );

        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        thread::scope(|scope| {
            // Owned here so that returning closes the channel: each I/O
            // thread then finishes its requests and exits before the scope
            // joins it.
            let requests = requests;
            for _ in 0..IO_THREADS {
                let pending = pending.clone();
                let (queue, interrupt, mem, disk) = (&queue, &*interrupt, &*mem, &*disk);
                thread::Builder::new()
                    .name("block io".into())
                    .spawn_scoped(scope, move || {
                        for head in pending {
                            serve(head, queue, interrupt, mem, disk);
                        }
                    })
                    .unwrap();
            }
            loop {
                let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
                match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                    Ok(ev_cnt) => {
                        for ev in &epoll_events[0..ev_cnt] {
                            let source = ev.fd();
                            let event_set = ev.event_set();
                            match event_set {
                                EventSet::IN if source == virtq_ev_fd => {
                                    if let Err(e) = queue_event.read() {
                                        error!("Failed to get queue event: {e:?}");
                                    } else {
                                        pop_requests(&queue, mem, &requests);
                                    }
                                }
                                EventSet::IN if source == stop_ev_fd => {
                                    debug!("stopping worker thread");
                                    let _ = stop_fd.read();
                                    return;
                                }
                                _ => {
                                    log::warn!(
                                        "Received unknown event: {event_set:?} from fd: {source:?}"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("failed to consume muxer epoll event: {e}");
                    }
                }
            }
        });
    }
}

/// Hands every available request to the I/O threads, then re-enables guest
/// notifications and pops again if more arrived meanwhile.
fn pop_requests<'a>(
    queue: &Mutex<&mut Queue>,
    mem: &'a GuestMemoryMmap,
    requests: &Sender<DescriptorChain<'a>>,
) {
    loop {
        let mut queue = queue.lock().unwrap();
        queue.disable_notification(mem).unwrap();
        while let Some(head) = queue.pop(mem) {
            requests.send(head).unwrap();
        }
        if !queue.enable_notification(mem).unwrap() {
            break;
        }
    }
}

/// Serves one request and returns it to the guest.
fn serve(
    head: DescriptorChain,
    queue: &Mutex<&mut Queue>,
    interrupt: &InterruptTransport,
    mem: &GuestMemoryMmap,
    disk: &DiskProperties,
) {
    let mut reader = match Reader::new(mem, head.clone()) {
        Ok(r) => r,
        Err(e) => {
            error!("invalid descriptor chain: {e:?}");
            return;
        }
    };
    let mut writer = match Writer::new(mem, head.clone()) {
        Ok(r) => r,
        Err(e) => {
            error!("invalid descriptor chain: {e:?}");
            return;
        }
    };
    let request_header: RequestHeader = match reader.read_obj() {
        Ok(h) => h,
        Err(e) => {
            error!("invalid request header: {e:?}");
            return;
        }
    };

    let (status, len): (u8, usize) =
        match process_request(disk, request_header, &mut reader, &mut writer) {
            Ok(l) => (VIRTIO_BLK_S_OK.try_into().unwrap(), l),
            Err(e) => {
                error!("error processing request: {e:?}");
                (VIRTIO_BLK_S_IOERR.try_into().unwrap(), 0)
            }
        };

    if let Err(e) = writer.write_obj(status) {
        error!("Failed to write virtio block status: {e:?}")
    }

    let mut queue = queue.lock().unwrap();
    if let Err(e) = queue.add_used(mem, head.index, len as u32) {
        error!("failed to add used elements to the queue: {e:?}");
    }

    if queue.needs_notification(mem).unwrap() {
        if let Err(e) = interrupt.try_signal_used_queue() {
            error!("error signalling queue: {e:?}");
        }
    }
}

fn process_request(
    disk: &DiskProperties,
    request_header: RequestHeader,
    reader: &mut Reader,
    writer: &mut Writer,
) -> result::Result<usize, RequestError> {
    match request_header.request_type {
        VIRTIO_BLK_T_IN => {
            let data_len = writer.available_bytes() - 1;
            if !data_len.is_multiple_of(512) {
                Err(RequestError::InvalidDataLength)
            } else {
                writer
                    .write_from_at(disk, data_len, request_header.sector * 512)
                    .map_err(RequestError::WritingToDescriptor)
            }
        }
        VIRTIO_BLK_T_OUT => {
            let data_len = reader.available_bytes();
            if !data_len.is_multiple_of(512) {
                Err(RequestError::InvalidDataLength)
            } else {
                reader
                    .read_to_at(disk, data_len, request_header.sector * 512)
                    .map_err(RequestError::ReadingFromDescriptor)
            }
        }
        VIRTIO_BLK_T_FLUSH => match disk.cache_type() {
            CacheType::Writeback => {
                let diskfile = disk.file.read().unwrap();
                diskfile.flush().map_err(RequestError::FlushingToDisk)?;
                diskfile.sync().map_err(RequestError::FlushingToDisk)?;
                Ok(0)
            }
            CacheType::Unsafe => Ok(0),
        },
        VIRTIO_BLK_T_GET_ID => {
            let data_len = writer.available_bytes();
            let disk_id = disk.image_id();
            if data_len < disk_id.len() {
                Err(RequestError::InvalidDataLength)
            } else {
                writer
                    .write_all(disk_id)
                    .map_err(RequestError::WritingToDescriptor)?;
                Ok(disk_id.len())
            }
        }
        VIRTIO_BLK_T_DISCARD => {
            let discard_write_data: DiscardWriteData = reader
                .read_obj()
                .map_err(RequestError::ReadingFromDescriptor)?;
            disk.discard(discard_write_data.sector, discard_write_data.num_sectors)
                .map_err(RequestError::Discarding)?;
            Ok(0)
        }
        VIRTIO_BLK_T_WRITE_ZEROES => {
            let discard_write_data: DiscardWriteData = reader
                .read_obj()
                .map_err(RequestError::ReadingFromDescriptor)?;
            let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
            if unmap {
                disk.file
                    .write()
                    .unwrap()
                    .discard_to_zero(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::DiscardingToZero)?;
            } else {
                disk.file
                    .read()
                    .unwrap()
                    .write_zeroes(
                        discard_write_data.sector * 512,
                        discard_write_data.num_sectors as u64 * 512,
                    )
                    .map_err(RequestError::WritingZeroes)?;
            }
            Ok(0)
        }
        _ => Err(RequestError::UnknownRequest),
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::{self, Display, Formatter};
    use std::sync::{Arc, RwLock};
    use std::time::{Duration, Instant};

    use imago::io_buffers::{IoVector, IoVectorMut};
    use imago::raw::Raw;
    use imago::storage::drivers::CommonStorageHelper;
    use imago::{DynStorage, Storage, SyncFormatAccess};
    use vm_memory::{Bytes, GuestAddress};

    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    const READ_LATENCY: Duration = Duration::from_millis(100);

    /// A disk of zeroes whose every read blocks its thread, like a cold read
    /// of a userspace NBD disk waiting for an object store GET.
    #[derive(Debug, Default)]
    struct SlowDisk {
        helper: CommonStorageHelper,
    }

    impl Display for SlowDisk {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "slow")
        }
    }

    impl Storage for SlowDisk {
        fn size(&self) -> io::Result<u64> {
            Ok(1 << 20)
        }

        async unsafe fn pure_readv(
            &self,
            mut bufv: IoVectorMut<'_>,
            _offset: u64,
        ) -> io::Result<()> {
            thread::sleep(READ_LATENCY);
            bufv.fill(0);
            Ok(())
        }

        async unsafe fn pure_writev(&self, _bufv: IoVector<'_>, _offset: u64) -> io::Result<()> {
            Ok(())
        }

        async fn flush(&self) -> io::Result<()> {
            Ok(())
        }

        async fn sync(&self) -> io::Result<()> {
            Ok(())
        }

        async unsafe fn invalidate_cache(&self) -> io::Result<()> {
            Ok(())
        }

        fn get_storage_helper(&self) -> &CommonStorageHelper {
            &self.helper
        }
    }

    #[test]
    fn slow_reads_are_served_concurrently() {
        const READS: u16 = 16;
        const BUFFERS: u64 = 0x10000;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let guest = VirtQueue::new(GuestAddress(0), &mem, 64);
        let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(Box::new(SlowDisk::default()), false)
            .unwrap();
        let disk = DiskProperties::new(
            Arc::new(RwLock::new(SyncFormatAccess::new(raw).unwrap())),
            b"slow".to_vec(),
            CacheType::Unsafe,
            #[cfg(target_os = "linux")]
            None,
        )
        .unwrap();
        let kick = Arc::new(EventFd::new(0).unwrap());
        let stop = EventFd::new(0).unwrap();
        let worker = BlockWorker::new(
            DeviceQueue::new(guest.create_queue(), kick.clone()),
            InterruptTransport::new(DummyIrqChip::new().into(), "block".into()).unwrap(),
            mem.clone(),
            disk,
            stop.try_clone().unwrap(),
        )
        .run();

        // Each read is a header, a 4 KiB data buffer and a status byte, as
        // the guest driver sends them.
        let status = |i: u16| GuestAddress(BUFFERS + u64::from(i) * 0x3000 + 0x2000);
        for i in 0..READS {
            let header = GuestAddress(BUFFERS + u64::from(i) * 0x3000);
            let data = GuestAddress(header.0 + 0x1000);
            let request = RequestHeader {
                request_type: VIRTIO_BLK_T_IN,
                _reserved: 0,
                sector: u64::from(i) * 8,
            };
            mem.write_obj(request, header).unwrap();
            mem.write_obj(0xffu8, status(i)).unwrap();
            let head = 3 * i;
            guest.dtable[head as usize].set(header.0, 16, VIRTQ_DESC_F_NEXT, head + 1);
            guest.dtable[head as usize + 1].set(
                data.0,
                0x1000,
                VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
                head + 2,
            );
            guest.dtable[head as usize + 2].set(status(i).0, 1, VIRTQ_DESC_F_WRITE, 0);
            guest.avail.ring[i as usize].set(head);
        }
        let start = Instant::now();
        guest.avail.idx.set(READS);
        kick.write(1).unwrap();
        while guest.used.idx.get() < READS {
            thread::yield_now();
        }
        let elapsed = start.elapsed();
        for i in 0..READS {
            let status: u8 = mem.read_obj(status(i)).unwrap();
            assert_eq!(u32::from(status), VIRTIO_BLK_S_OK);
        }
        assert!(elapsed >= READ_LATENCY);
        assert!(
            elapsed < READ_LATENCY * 4,
            "{READS} reads took {elapsed:?}; one at a time takes {:?}",
            READ_LATENCY * u32::from(READS)
        );
        stop.write(1).unwrap();
        worker.join().unwrap();
    }
}
