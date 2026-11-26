use crate::virtio::descriptor_utils::{Reader, Writer};

use super::super::{DescriptorChain, DeviceQueue, Queue};
use super::device::{CacheType, DiskProperties, MAX_REQUEST_BYTES};

use crate::virtio::InterruptTransport;
use crossbeam_channel::Sender;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::panic::{self, AssertUnwindSafe};
use std::result;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
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
    InvalidHeader(io::Error),
    InvalidSector,
    Panicked,
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

/// Requests the device serves at once. Each I/O blocks its thread for the
/// backend's whole latency: a cold read of a userspace NBD disk waits for an
/// object store GET, so a single thread turned guest queue depth 16 into
/// queue depth 1 at the host. Each thread holds one request, so this also
/// bounds what a guest can make the device hold: further requests wait in
/// the avail ring.
const IO_THREADS: usize = 16;

pub struct BlockWorker {
    pub(super) device_queue: DeviceQueue,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    disk: DiskProperties,
    stop_fd: EventFd,
}

/// The queue and what the I/O threads agree on, under one lock. The lock is
/// held only to pop and to complete a request, never across its I/O.
struct Serving<'q> {
    queue: &'q mut Queue,
    stopping: bool,
    /// The guest made the queue unusable; its requests are no longer served.
    broken: bool,
}

impl Serving<'_> {
    /// Pops the next request, if one is available.
    fn next_request<'m>(&mut self, mem: &'m GuestMemoryMmap) -> Option<DescriptorChain<'m>> {
        while !self.broken {
            let available = self.queue.len(mem);
            // A driver cannot make more requests available than the queue
            // holds; without this check, a guest could keep the device
            // popping without end.
            if available > self.queue.actual_size() {
                error!("virtio-blk guest made {available} requests available in a smaller queue");
                self.broken = true;
                break;
            }
            if available == 0 {
                // Look once more after re-arming the guest's kick: a request
                // made available meanwhile would not kick.
                if self.enable_notification(mem) {
                    continue;
                }
                break;
            }
            let Some(head) = self.queue.pop(mem) else {
                error!("virtio-blk guest made an invalid descriptor chain available");
                self.broken = true;
                break;
            };
            // With VIRTIO_RING_F_EVENT_IDX, ask the guest to kick for the
            // next request too.
            self.enable_notification(mem);
            return Some(head);
        }
        None
    }

    /// Re-enables guest notifications. Returns whether more requests are
    /// available.
    fn enable_notification(&mut self, mem: &GuestMemoryMmap) -> bool {
        self.queue.enable_notification(mem).unwrap_or_else(|e| {
            error!("failed to enable virtio-blk notifications: {e:?}");
            false
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Request panics are caught before they can poison the lock.
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

    /// Starts serving. Fails if a thread cannot be started, for example under
    /// a pids limit, rather than leaving a disk that never answers.
    pub fn run(self) -> io::Result<thread::JoinHandle<Self>> {
        let (started, start) = crossbeam_channel::bounded(1);
        let worker = thread::Builder::new()
            .name("block worker".into())
            .spawn(move || {
                let mut worker = self;
                worker.serve_until_stopped(started);
                worker
            })?;
        match start.recv() {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(e)) => {
                let _ = worker.join();
                Err(e)
            }
            Err(_) => Err(io::Error::other("block worker exited before serving")),
        }
    }

    /// Serves requests on IO_THREADS scoped threads, which complete them in
    /// any order, as virtio allows. Stopping waits only for the requests in
    /// flight, at most one per thread.
    fn serve_until_stopped(&mut self, started: Sender<io::Result<()>>) {
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
        // The guest cannot move the rings once the device is active, so
        // checking them here keeps every later ring access in bounds.
        let broken = !device_queue.queue.is_valid(mem);
        let serving = Mutex::new(Serving {
            queue: &mut device_queue.queue,
            stopping: false,
            broken,
        });
        let kicked = Condvar::new();
        let stop = || {
            lock(&serving).stopping = true;
            kicked.notify_all();
        };

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
            for _ in 0..IO_THREADS {
                let (serving, kicked) = (&serving, &kicked);
                let (interrupt, mem, disk) = (&*interrupt, &*mem, &*disk);
                let spawned = thread::Builder::new()
                    .name("block io".into())
                    .spawn_scoped(scope, move || {
                        serve_requests(serving, kicked, interrupt, mem, disk)
                    });
                if let Err(e) = spawned {
                    stop();
                    let _ = started.send(Err(e));
                    return;
                }
            }
            let _ = started.send(Ok(()));
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
                                    }
                                    // Taking the lock orders this wake-up after
                                    // a thread that found the queue empty
                                    // started waiting.
                                    drop(lock(&serving));
                                    kicked.notify_all();
                                }
                                EventSet::IN if source == stop_ev_fd => {
                                    debug!("stopping worker thread");
                                    let _ = stop_fd.read();
                                    stop();
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

/// One I/O thread: takes the next request, serves it without holding the
/// queue, and returns it to the guest.
fn serve_requests(
    serving: &Mutex<Serving>,
    kicked: &Condvar,
    interrupt: &InterruptTransport,
    mem: &GuestMemoryMmap,
    disk: &DiskProperties,
) {
    loop {
        let head = {
            let mut serving = lock(serving);
            loop {
                if serving.stopping {
                    return;
                }
                if let Some(head) = serving.next_request(mem) {
                    break head;
                }
                serving = kicked.wait(serving).unwrap_or_else(PoisonError::into_inner);
            }
        };
        let len = serve(&head, mem, disk);
        let mut serving = lock(serving);
        if let Err(e) = serving.queue.add_used(mem, head.index, len) {
            error!("failed to add used elements to the queue: {e:?}");
        }
        match serving.queue.needs_notification(mem) {
            Ok(true) => {
                if let Err(e) = interrupt.try_signal_used_queue() {
                    error!("error signalling queue: {e:?}");
                }
            }
            Ok(false) => {}
            Err(e) => error!("failed to check virtio-blk notification: {e:?}"),
        }
    }
}

/// Serves one request and writes its status. Returns the length for the used
/// ring. Every request is answered, whatever the guest put in it.
fn serve(head: &DescriptorChain, mem: &GuestMemoryMmap, disk: &DiskProperties) -> u32 {
    let (Ok(mut reader), Ok(mut writer)) = (
        Reader::new(mem, head.clone()),
        Writer::new(mem, head.clone()),
    ) else {
        error!("invalid descriptor chain");
        return 0;
    };
    // The status is the last writable byte, however far the data got.
    let Some(mut status_writer) = writer
        .available_bytes()
        .checked_sub(1)
        .and_then(|data_len| writer.split_at(data_len).ok())
    else {
        error!("virtio block request without a status byte");
        return 0;
    };
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        process_request(disk, &mut reader, &mut writer)
    }))
    .unwrap_or(Err(RequestError::Panicked));
    let (status, len) = match result {
        // A request is at most MAX_REQUEST_BYTES.
        Ok(len) => (VIRTIO_BLK_S_OK, len as u32),
        Err(e) => {
            error!("error processing request: {e:?}");
            (VIRTIO_BLK_S_IOERR, 0)
        }
    };
    if let Err(e) = status_writer.write_obj(status as u8) {
        error!("Failed to write virtio block status: {e:?}")
    }
    len
}

fn process_request(
    disk: &DiskProperties,
    reader: &mut Reader,
    writer: &mut Writer,
) -> result::Result<usize, RequestError> {
    let request_header: RequestHeader = reader.read_obj().map_err(RequestError::InvalidHeader)?;
    // The disk offset of a read or write of len bytes, checked before the
    // bounce buffer of len bytes is allocated.
    let data_offset = |len: usize| {
        if !len.is_multiple_of(512) || len > MAX_REQUEST_BYTES {
            return Err(RequestError::InvalidDataLength);
        }
        disk_offset(disk, request_header.sector, len as u64)
    };
    match request_header.request_type {
        VIRTIO_BLK_T_IN => {
            let data_len = writer.available_bytes();
            let offset = data_offset(data_len)?;
            writer
                .write_from_at(disk, data_len, offset)
                .map_err(RequestError::WritingToDescriptor)
        }
        VIRTIO_BLK_T_OUT => {
            let data_len = reader.available_bytes();
            let offset = data_offset(data_len)?;
            reader
                .read_to_at(disk, data_len, offset)
                .map_err(RequestError::ReadingFromDescriptor)
        }
        VIRTIO_BLK_T_FLUSH => match disk.cache_type() {
            CacheType::Writeback => {
                let image = disk.image();
                image.flush().map_err(RequestError::FlushingToDisk)?;
                image.sync().map_err(RequestError::FlushingToDisk)?;
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
            let length = u64::from(discard_write_data.num_sectors) * 512;
            let offset = disk_offset(disk, discard_write_data.sector, length)?;
            let unmap = (discard_write_data.flags & VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP) != 0;
            if unmap {
                disk.image_mut()
                    .discard_to_zero(offset, length)
                    .map_err(RequestError::DiscardingToZero)?;
            } else {
                disk.image()
                    .write_zeroes(offset, length)
                    .map_err(RequestError::WritingZeroes)?;
            }
            Ok(0)
        }
        _ => Err(RequestError::UnknownRequest),
    }
}

/// The byte offset of len bytes at sector, which must all lie within the disk.
fn disk_offset(disk: &DiskProperties, sector: u64, len: u64) -> result::Result<u64, RequestError> {
    sector
        .checked_mul(512)
        .filter(|offset| {
            offset
                .checked_add(len)
                .is_some_and(|end| end <= disk.nsectors() * 512)
        })
        .ok_or(RequestError::InvalidSector)
}

#[cfg(test)]
mod tests {
    use std::fmt::{self, Display, Formatter};
    use std::sync::atomic::{AtomicUsize, Ordering};
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
    const RING_SIZE: u16 = 128;
    const BUFFERS: u64 = 0x10000;
    const DISK_SIZE: u64 = 64 << 20;

    /// How many reads of a SlowDisk run now, and the most that ran at once.
    #[derive(Debug, Default)]
    struct Reads {
        now: AtomicUsize,
        most: AtomicUsize,
    }

    /// A disk of zeroes whose every read blocks its thread, like a cold read
    /// of a userspace NBD disk waiting for an object store GET.
    #[derive(Debug, Default)]
    struct SlowDisk {
        helper: CommonStorageHelper,
        reads: Arc<Reads>,
    }

    impl Display for SlowDisk {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            write!(f, "slow")
        }
    }

    impl Storage for SlowDisk {
        fn size(&self) -> io::Result<u64> {
            Ok(DISK_SIZE)
        }

        async unsafe fn pure_readv(
            &self,
            mut bufv: IoVectorMut<'_>,
            _offset: u64,
        ) -> io::Result<()> {
            let now = self.reads.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.reads.most.fetch_max(now, Ordering::SeqCst);
            thread::sleep(READ_LATENCY);
            self.reads.now.fetch_sub(1, Ordering::SeqCst);
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

    /// The guest driver's side of the queue of a worker serving a SlowDisk.
    struct Guest<'a> {
        mem: &'a GuestMemoryMmap,
        queue: VirtQueue<'a>,
        reads: Arc<Reads>,
        kick: Arc<EventFd>,
        stop: EventFd,
        worker: thread::JoinHandle<BlockWorker>,
    }

    impl<'a> Guest<'a> {
        /// Starts the worker on the queue, as adjusted by the guest.
        fn start(mem: &'a GuestMemoryMmap, adjust: impl FnOnce(&mut Queue)) -> Self {
            let queue = VirtQueue::new(GuestAddress(0), mem, RING_SIZE);
            let mut device_queue = queue.create_queue();
            adjust(&mut device_queue);
            let reads = Arc::new(Reads::default());
            let slow = SlowDisk {
                helper: CommonStorageHelper::default(),
                reads: reads.clone(),
            };
            let raw = Raw::<Box<dyn DynStorage>>::open_image_sync(Box::new(slow), false).unwrap();
            let disk = Arc::new(RwLock::new(SyncFormatAccess::new(raw).unwrap()));
            let kick = Arc::new(EventFd::new(0).unwrap());
            let stop = EventFd::new(0).unwrap();
            let worker = BlockWorker::new(
                DeviceQueue::new(device_queue, kick.clone()),
                InterruptTransport::new(DummyIrqChip::new().into(), "block".into()).unwrap(),
                mem.clone(),
                DiskProperties::new(
                    disk,
                    b"slow".to_vec(),
                    CacheType::Unsafe,
                    #[cfg(target_os = "linux")]
                    None,
                )
                .unwrap(),
                stop.try_clone().unwrap(),
            )
            .run()
            .unwrap();
            Guest {
                mem,
                queue,
                reads,
                kick,
                stop,
                worker,
            }
        }

        fn status_of(i: u16) -> GuestAddress {
            GuestAddress(BUFFERS + u64::from(i) * 0x3000 + 0x2000)
        }

        /// Makes request `i` available: a header, a 4 KiB data buffer and a
        /// status byte, as the guest driver sends a read.
        fn add_read(&self, i: u16) {
            let header = GuestAddress(BUFFERS + u64::from(i) * 0x3000);
            let data = GuestAddress(header.0 + 0x1000);
            let request = RequestHeader {
                request_type: VIRTIO_BLK_T_IN,
                _reserved: 0,
                sector: u64::from(i) * 8,
            };
            self.mem.write_obj(request, header).unwrap();
            self.mem.write_obj(0xffu8, Self::status_of(i)).unwrap();
            let head = 3 * i;
            self.queue.dtable[head as usize].set(header.0, 16, VIRTQ_DESC_F_NEXT, head + 1);
            self.queue.dtable[head as usize + 1].set(
                data.0,
                0x1000,
                VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
                head + 2,
            );
            self.queue.dtable[head as usize + 2].set(
                Self::status_of(i).0,
                1,
                VIRTQ_DESC_F_WRITE,
                0,
            );
            self.queue.avail.ring[i as usize].set(head);
        }

        /// Publishes the avail index and kicks, then returns how long the
        /// device took to answer `count` requests in total.
        fn submit(&self, count: u16) -> Duration {
            let start = Instant::now();
            self.queue.avail.idx.set(count);
            self.kick.write(1).unwrap();
            while self.queue.used.idx.get() < count {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "requests were not answered"
                );
                thread::yield_now();
            }
            start.elapsed()
        }

        fn status(&self, i: u16) -> u32 {
            u32::from(self.mem.read_obj::<u8>(Self::status_of(i)).unwrap())
        }

        fn stop(self) {
            self.stop.write(1).unwrap();
            self.worker.join().unwrap();
        }
    }

    #[test]
    fn slow_reads_are_served_concurrently() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        let guest = Guest::start(&mem, |_| {});
        for i in 0..16 {
            guest.add_read(i);
        }
        let elapsed = guest.submit(16);
        for i in 0..16 {
            assert_eq!(guest.status(i), VIRTIO_BLK_S_OK);
        }
        assert!(elapsed >= READ_LATENCY);
        assert!(
            elapsed < READ_LATENCY * 4,
            "16 reads took {elapsed:?}; one at a time takes {:?}",
            READ_LATENCY * 16
        );
        guest.stop();
    }

    #[test]
    fn at_most_sixteen_requests_are_in_flight() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        let guest = Guest::start(&mem, |_| {});
        for i in 0..32 {
            guest.add_read(i);
        }
        let elapsed = guest.submit(32);
        for i in 0..32 {
            assert_eq!(guest.status(i), VIRTIO_BLK_S_OK);
        }
        assert_eq!(guest.reads.most.load(Ordering::SeqCst), IO_THREADS);
        assert!(elapsed >= READ_LATENCY * 2, "32 reads took {elapsed:?}");
        guest.stop();
    }

    #[test]
    fn a_queue_claiming_more_requests_than_it_holds_is_not_served() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        let guest = Guest::start(&mem, |_| {});
        guest.add_read(0);
        guest.queue.avail.idx.set(RING_SIZE + 1);
        guest.kick.write(1).unwrap();
        thread::sleep(READ_LATENCY);
        assert_eq!(guest.queue.used.idx.get(), 0);
        assert_eq!(guest.reads.most.load(Ordering::SeqCst), 0);
        let stopping = Instant::now();
        guest.stop();
        assert!(stopping.elapsed() < READ_LATENCY);
    }

    #[test]
    fn a_queue_with_rings_outside_guest_memory_is_not_served() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        let guest = Guest::start(&mem, |queue| queue.avail_ring = GuestAddress(0x100000));
        guest.add_read(0);
        guest.queue.avail.idx.set(1);
        guest.kick.write(1).unwrap();
        thread::sleep(READ_LATENCY);
        assert_eq!(guest.queue.used.idx.get(), 0);
        assert_eq!(guest.reads.most.load(Ordering::SeqCst), 0);
        guest.stop();
    }

    #[test]
    fn a_read_longer_than_a_request_can_be_is_refused_without_reading() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x800000)]).unwrap();
        let guest = Guest::start(&mem, |_| {});
        guest.add_read(0);
        let len = MAX_REQUEST_BYTES as u32 + 512;
        guest.queue.dtable[1].set(0x200000, len, VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT, 2);
        guest.submit(1);
        assert_eq!(guest.status(0), VIRTIO_BLK_S_IOERR);
        assert_eq!(guest.queue.used.ring[0].get().len, 0);
        assert_eq!(guest.reads.most.load(Ordering::SeqCst), 0);
        guest.stop();
    }

    #[test]
    fn a_read_past_the_end_of_the_disk_is_refused_without_reading() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        let guest = Guest::start(&mem, |_| {});
        guest.add_read(0);
        guest.add_read(1);
        // Request 0 reads 4 KiB ending 512 bytes past the disk; request 1 the
        // last 4 KiB of the disk.
        let last = RequestHeader {
            request_type: VIRTIO_BLK_T_IN,
            _reserved: 0,
            sector: DISK_SIZE / 512 - 7,
        };
        mem.write_obj(last, GuestAddress(BUFFERS)).unwrap();
        mem.write_obj(
            RequestHeader {
                sector: DISK_SIZE / 512 - 8,
                ..last
            },
            GuestAddress(BUFFERS + 0x3000),
        )
        .unwrap();
        guest.submit(2);
        assert_eq!(guest.status(0), VIRTIO_BLK_S_IOERR);
        assert_eq!(guest.status(1), VIRTIO_BLK_S_OK);
        assert_eq!(guest.reads.most.load(Ordering::SeqCst), 1);
        guest.stop();
    }

    #[test]
    fn a_read_without_room_for_its_status_is_answered() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x100000)]).unwrap();
        let guest = Guest::start(&mem, |_| {});
        guest.add_read(0);
        guest.add_read(1);
        // Request 0 keeps only its header: no data buffer and no status byte.
        guest.queue.dtable[0].set(BUFFERS, 16, 0, 0);
        guest.submit(2);
        let used = guest.queue.used.ring[0].get().len + guest.queue.used.ring[1].get().len;
        assert_eq!(used, 0x1000);
        assert_eq!(guest.status(1), VIRTIO_BLK_S_OK);
        guest.stop();
    }
}
