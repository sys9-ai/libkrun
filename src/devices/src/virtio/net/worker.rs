use crate::virtio::net::backend::ConnectError;
#[cfg(target_os = "linux")]
use crate::virtio::net::tap::Tap;
use crate::virtio::net::unixgram::Unixgram;
use crate::virtio::net::unixstream::Unixstream;
use crate::virtio::net::{MAX_BUFFER_SIZE, QUEUE_SIZE};
use crate::virtio::{DeviceQueue, InterruptTransport};

use super::backend::{NetBackend, ReadError, WriteError};
use super::device::{FrontendError, RxError, TxError, VirtioNetBackend};
use super::VNET_HDR_LEN;

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::thread;
use std::time::{Duration, Instant};
use std::{cmp, result};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

/// How long a frame may wait in one direction before the worker reports a
/// stall. Ordinary backpressure clears within milliseconds.
const STALL_REPORT_AFTER: Duration = Duration::from_secs(10);

/// While a frame waits, the worker wakes this often to check for a stall.
const STALL_CHECK_INTERVAL_MS: i32 = 5000;

/// When the frame one direction holds back started waiting, and whether that
/// wait was already reported as a stall. The reports go to stderr, which the
/// embedding process keeps beside the VM, because no logger is installed for
/// this library.
#[derive(Default)]
struct DeferredSince {
    since: Option<Instant>,
    reported: bool,
}

impl DeferredSince {
    /// Records whether a frame is deferred now, and reports a wait that
    /// passed `STALL_REPORT_AFTER` once, then its end. `detail` describes
    /// the queue state that explains the wait.
    fn observe(
        &mut self,
        deferred: bool,
        direction: &str,
        waiting_for: &str,
        detail: impl FnOnce() -> String,
    ) {
        if !deferred {
            if let Some(since) = self.since.take() {
                if self.reported {
                    eprintln!(
                        "LIBKRUN VIRTIO-NET RECOVERED: {direction} frame was delivered after {} ms",
                        since.elapsed().as_millis()
                    );
                }
            }
            self.reported = false;
            return;
        }
        let since = *self.since.get_or_insert_with(Instant::now);
        if !self.reported && since.elapsed() >= STALL_REPORT_AFTER {
            self.reported = true;
            eprintln!(
                "LIBKRUN VIRTIO-NET STALL: {direction} frame has waited {} ms for {waiting_for} ({})",
                since.elapsed().as_millis(),
                detail()
            );
        }
    }
}

/// Describes the bytes queued in the backend socket in each direction: unread
/// by this worker, and written by it but not yet read by the backend. A stall
/// with a full side shows which end stopped reading. `-1` means unknown.
fn socket_queues(fd: RawFd) -> String {
    let mut unread: libc::c_int = -1;
    let mut unsent: libc::c_int = -1;
    // SAFETY: each ioctl writes one c_int through a pointer to a local.
    unsafe {
        libc::ioctl(fd, libc::FIONREAD, &mut unread);
        #[cfg(target_os = "linux")]
        libc::ioctl(fd, libc::TIOCOUTQ, &mut unsent);
    }
    format!("socket_unread_bytes={unread} socket_unsent_bytes={unsent}")
}

pub struct NetWorker {
    pub(super) stop: std::sync::Arc<EventFd>,
    rx_q: DeviceQueue,
    tx_q: DeviceQueue,
    interrupt: InterruptTransport,

    mem: GuestMemoryMmap,
    backend: Box<dyn NetBackend + Send>,

    rx_frame_buf: [u8; MAX_BUFFER_SIZE],
    rx_frame_buf_len: usize,
    rx_has_deferred_frame: bool,

    tx_iovec: Vec<(GuestAddress, usize)>,
    tx_frame_buf: [u8; MAX_BUFFER_SIZE],
    tx_frame_len: usize,
    tx_has_deferred_frame: bool,

    rx_deferred: DeferredSince,
    tx_deferred: DeferredSince,
}

impl NetWorker {
    pub fn new(
        rx_q: DeviceQueue,
        tx_q: DeviceQueue,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        _vnet_features: u64,
        cfg_backend: VirtioNetBackend,
    ) -> Result<Self, ConnectError> {
        let backend = match cfg_backend {
            VirtioNetBackend::UnixstreamFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixstream::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixstreamPath(path) => {
                Box::new(Unixstream::open(path)?) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramFd(fd) => {
                // SAFETY: we need to trust that the library user has configured
                // the backend with a healthy file descriptor.
                let owned_fd = unsafe { OwnedFd::from_raw_fd(fd) };
                Box::new(Unixgram::new(owned_fd)) as Box<dyn NetBackend + Send>
            }
            VirtioNetBackend::UnixgramPath(path, vfkit_magic) => {
                Box::new(Unixgram::open(path, vfkit_magic)?) as Box<dyn NetBackend + Send>
            }
            #[cfg(target_os = "linux")]
            VirtioNetBackend::Tap(tap_name) => {
                Box::new(Tap::new(tap_name, _vnet_features)?) as Box<dyn NetBackend + Send>
            }
        };

        Ok(Self {
            stop: std::sync::Arc::new(EventFd::new(EFD_NONBLOCK).expect("network stop eventfd")),
            rx_q,
            tx_q,

            mem,
            backend,
            interrupt,

            rx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            rx_frame_buf_len: 0,
            rx_has_deferred_frame: false,

            tx_frame_buf: [0u8; MAX_BUFFER_SIZE],
            tx_frame_len: 0,
            tx_iovec: Vec::with_capacity(QUEUE_SIZE as usize),
            tx_has_deferred_frame: false,

            rx_deferred: DeferredSince::default(),
            tx_deferred: DeferredSince::default(),
        })
    }

    pub fn run(self) -> thread::JoinHandle<Self> {
        thread::Builder::new()
            .name("virtio-net worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) -> Self {
        #[cfg(target_os = "macos")]
        const TX_TIMER_FD: RawFd = -2;

        let virtq_rx_ev_fd = self.rx_q.event.as_raw_fd();
        let virtq_tx_ev_fd = self.tx_q.event.as_raw_fd();
        let backend_socket = self.backend.raw_socket_fd();

        let epoll = Epoll::new().unwrap();
        let stop_fd = self.stop.as_raw_fd();
        epoll
            .ctl(
                ControlOperation::Add,
                stop_fd,
                &EpollEvent::new(EventSet::IN, stop_fd as u64),
            )
            .unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_rx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_rx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_tx_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_tx_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            backend_socket,
            &EpollEvent::new(
                EventSet::IN | EventSet::OUT | EventSet::EDGE_TRIGGERED | EventSet::READ_HANG_UP,
                backend_socket as u64,
            ),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            // A held-back frame wakes the worker periodically, so a wait that
            // never ends is reported instead of passing silently.
            let timeout = if self.rx_has_deferred_frame
                || self.tx_has_deferred_frame
                || self.backend.has_unfinished_write()
            {
                STALL_CHECK_INTERVAL_MS
            } else {
                -1
            };
            match epoll.wait(epoll_events.len(), timeout, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        if source == stop_fd {
                            let _ = self.stop.read();
                            return self;
                        }
                        match event_set {
                            EventSet::IN if source == virtq_rx_ev_fd => {
                                self.process_rx_queue_event();
                            }
                            EventSet::IN if source == virtq_tx_ev_fd => {
                                self.process_tx_queue_event();
                            }
                            _ if source == backend_socket => {
                                if event_set.contains(EventSet::HANG_UP)
                                    || event_set.contains(EventSet::READ_HANG_UP)
                                {
                                    log::error!("Got {event_set:?} on backend fd, virtio-net will stop working");
                                    eprintln!("LIBKRUN VIRTIO-NET FATAL: Backend process seems to have quit or crashed! Networking is now disabled!");
                                } else {
                                    if event_set.contains(EventSet::IN) {
                                        self.process_backend_socket_readable()
                                    }

                                    if event_set.contains(EventSet::OUT) {
                                        self.process_backend_socket_writeable()
                                    }
                                }
                            }
                            #[cfg(target_os = "macos")]
                            _ if event_set.is_empty() && source == TX_TIMER_FD => {
                                self.process_tx_loop();
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }

                    self.observe_deferred_frames();

                    // Arm the retry timer after processing all events, so it
                    // reflects the final state of tx_has_deferred_frame.
                    #[cfg(target_os = "macos")]
                    if self.tx_has_deferred_frame {
                        let delay = self.backend.write_retry_delay_us();
                        if delay > 0 {
                            epoll.add_oneshot_timer(delay, TX_TIMER_FD as u64);
                        }
                    }
                }
                Err(e) => {
                    debug!("vsock: failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    pub(crate) fn process_rx_queue_event(&mut self) {
        if let Err(e) = self.rx_q.event.read() {
            log::error!("Failed to get rx event from queue: {e:?}");
        }
        self.process_rx_loop();
    }

    pub(crate) fn process_tx_queue_event(&mut self) {
        match self.tx_q.event.read() {
            Ok(_) => self.process_tx_loop(),
            Err(e) => {
                log::error!("Failed to get tx queue event from queue: {e:?}");
            }
        }
    }

    pub(crate) fn process_backend_socket_readable(&mut self) {
        self.process_rx_loop();
    }

    /// Delivers backend frames into the guest's receive buffers, then asks the
    /// guest to notify when it adds buffers after the last one used.
    ///
    /// A frame left over when the buffers run out is delivered only on that
    /// notification: the backend socket is edge-triggered and, once its buffer
    /// is full, raises no further readable event. With `VIRTIO_RING_F_EVENT_IDX`
    /// the guest notifies only when its index passes the `avail_event` written
    /// by `enable_notification`, so that must be written after the pass, at the
    /// position where it stopped; written before, it lies behind every buffer
    /// the guest adds next and the guest never notifies. Buffers added before
    /// re-enabling are found by its return value and consumed by another pass.
    fn process_rx_loop(&mut self) {
        loop {
            if let Err(e) = self.rx_q.queue.disable_notification(&self.mem) {
                error!("error disabling queue notifications: {e:?}");
            }
            if let Err(e) = self.process_rx() {
                log::error!("Failed to process rx: {e:?}");
            }
            match self.rx_q.queue.enable_notification(&self.mem) {
                Ok(true) if self.rx_has_deferred_frame => continue,
                Ok(_) => break,
                Err(e) => {
                    error!("error enabling queue notifications: {e:?}");
                    break;
                }
            }
        }
    }

    /// Reports a frame held back in either direction for longer than
    /// `STALL_REPORT_AFTER`, with the queue state that tells a guest that
    /// gives no buffers from a notification the worker missed.
    fn observe_deferred_frames(&mut self) {
        let (rx_queue, tx_queue, mem) = (&self.rx_q.queue, &self.tx_q.queue, &self.mem);
        let socket = self.backend.raw_socket_fd();
        self.rx_deferred.observe(
            self.rx_has_deferred_frame,
            "rx",
            "guest receive buffers",
            || {
                format!(
                    "guest_buffers_available={} {}",
                    rx_queue.len(mem),
                    socket_queues(socket)
                )
            },
        );
        let unfinished_write = self.backend.has_unfinished_write();
        let tx_waiting = self.tx_has_deferred_frame || unfinished_write;
        self.tx_deferred
            .observe(tx_waiting, "tx", "the backend socket", || {
                format!(
                    "guest_frames_pending={} unfinished_write={unfinished_write} {}",
                    tx_queue.len(mem),
                    socket_queues(socket)
                )
            });
    }

    pub(crate) fn process_backend_socket_writeable(&mut self) {
        match self
            .backend
            .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
        {
            Ok(()) => self.process_tx_loop(),
            Err(WriteError::PartialWrite | WriteError::NothingWritten) => {}
            Err(e @ WriteError::Internal(_)) => {
                log::error!("Failed to finish write: {e:?}");
            }
            Err(e @ WriteError::ProcessNotRunning) => {
                log::debug!("Failed to finish write: {e:?}");
            }
        }
    }

    fn process_rx(&mut self) -> result::Result<(), RxError> {
        // if we have a deferred frame we try to process it first,
        // if that is not possible, we don't continue processing other frames
        if self.rx_has_deferred_frame {
            if self.write_frame_to_guest() {
                self.rx_has_deferred_frame = false;
            } else {
                return Ok(());
            }
        }

        let mut signal_queue = false;

        // Read as many frames as possible.
        let result = loop {
            match self.read_into_rx_frame_buf_from_backend() {
                Ok(()) => {
                    if self.write_frame_to_guest() {
                        signal_queue = true;
                    } else {
                        self.rx_has_deferred_frame = true;
                        break Ok(());
                    }
                }
                Err(ReadError::NothingRead) => break Ok(()),
                Err(e @ ReadError::Internal(_)) => break Err(RxError::Backend(e)),
            }
        };

        // At this point we processed as many Rx frames as possible.
        // We have to wake the guest if at least one descriptor chain has been used.
        if signal_queue {
            self.interrupt
                .try_signal_used_queue()
                .map_err(RxError::DeviceError)?;
        }

        result
    }

    fn process_tx_loop(&mut self) {
        loop {
            self.tx_q.queue.disable_notification(&self.mem).unwrap();

            self.tx_has_deferred_frame = match self.process_tx() {
                Err(TxError::Backend(WriteError::NothingWritten)) => true,
                Err(e) => {
                    log::error!("Failed to process tx: {e:?}");
                    false
                }
                _ => false,
            };

            let has_new_entries = self.tx_q.queue.enable_notification(&self.mem).unwrap();
            if self.tx_has_deferred_frame || !has_new_entries {
                break;
            }
        }
    }

    fn process_tx(&mut self) -> result::Result<(), TxError> {
        let tx_queue = &mut self.tx_q.queue;

        if self.backend.has_unfinished_write()
            && self
                .backend
                .try_finish_write(VNET_HDR_LEN, &self.tx_frame_buf[..self.tx_frame_len])
                .is_err()
        {
            log::trace!("Cannot process tx because of unfinished partial write!");
            return Ok(());
        }

        let mut raise_irq = false;
        let mut result = Ok(());

        while let Some(head) = tx_queue.pop(&self.mem) {
            let head_index = head.index;
            let mut next_desc = Some(head);

            self.tx_iovec.clear();
            while let Some(desc) = next_desc {
                if desc.is_write_only() {
                    self.tx_iovec.clear();
                    break;
                }
                self.tx_iovec.push((desc.addr, desc.len as usize));
                next_desc = desc.next_descriptor();
            }

            // Copy buffer from across multiple descriptors.
            let mut read_count = 0;
            for (desc_addr, desc_len) in self.tx_iovec.drain(..) {
                let limit = cmp::min(read_count + desc_len, self.tx_frame_buf.len());

                let read_result = self
                    .mem
                    .read_slice(&mut self.tx_frame_buf[read_count..limit], desc_addr);
                match read_result {
                    Ok(()) => {
                        read_count += limit - read_count;
                    }
                    Err(e) => {
                        log::error!("Failed to read slice: {e:?}");
                        read_count = 0;
                        break;
                    }
                }
            }

            self.tx_frame_len = read_count;
            match self
                .backend
                .write_frame(VNET_HDR_LEN, &mut self.tx_frame_buf[..read_count])
            {
                Ok(()) => {
                    self.tx_frame_len = 0;
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                }
                Err(WriteError::NothingWritten) => {
                    tx_queue.undo_pop();
                    result = Err(TxError::Backend(WriteError::NothingWritten));
                    break;
                }
                Err(WriteError::PartialWrite) => {
                    log::trace!("process_tx: partial write");
                    /*
                    This situation should be pretty rare, assuming reasonably sized socket buffers.
                    We have written only a part of a frame to the backend socket (the socket is full).

                    The frame we have read from the guest remains in tx_frame_buf, and will be sent
                    later.

                    Note that we cannot wait for the backend to process our sending frames, because
                    the backend could be blocked on sending a remainder of a frame to us - us waiting
                    for backend would cause a deadlock.
                     */
                    tx_queue
                        .add_used(&self.mem, head_index, 0)
                        .map_err(TxError::QueueError)?;
                    raise_irq = true;
                    break;
                }
                Err(e @ WriteError::Internal(_) | e @ WriteError::ProcessNotRunning) => {
                    return Err(TxError::Backend(e))
                }
            }
        }

        if raise_irq && tx_queue.needs_notification(&self.mem).unwrap() {
            self.interrupt
                .try_signal_used_queue()
                .map_err(TxError::DeviceError)?;
        }

        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest.
    fn write_frame_to_guest_impl(&mut self) -> result::Result<(), FrontendError> {
        let mut result: std::result::Result<(), FrontendError> = Ok(());

        let queue = &mut self.rx_q.queue;
        let head_descriptor = queue.pop(&self.mem).ok_or(FrontendError::EmptyQueue)?;
        let head_index = head_descriptor.index;

        let mut frame_slice = &self.rx_frame_buf[..self.rx_frame_buf_len];

        let frame_len = frame_slice.len();
        let mut maybe_next_descriptor = Some(head_descriptor);
        while let Some(descriptor) = &maybe_next_descriptor {
            if frame_slice.is_empty() {
                break;
            }

            if !descriptor.is_write_only() {
                result = Err(FrontendError::ReadOnlyDescriptor);
                break;
            }

            let len = std::cmp::min(frame_slice.len(), descriptor.len as usize);
            match self.mem.write_slice(&frame_slice[..len], descriptor.addr) {
                Ok(()) => {
                    frame_slice = &frame_slice[len..];
                }
                Err(e) => {
                    log::error!("Failed to write slice: {e:?}");
                    result = Err(FrontendError::GuestMemory(e));
                    break;
                }
            };

            maybe_next_descriptor = descriptor.next_descriptor();
        }
        if result.is_ok() && !frame_slice.is_empty() {
            log::warn!("Receiving buffer is too small to hold frame of current size");
            result = Err(FrontendError::DescriptorChainTooSmall);
        }

        // Mark the descriptor chain as used. If an error occurred, skip the descriptor chain.
        let used_len = if result.is_err() { 0 } else { frame_len as u32 };
        queue
            .add_used(&self.mem, head_index, used_len)
            .map_err(FrontendError::QueueError)?;
        result
    }

    // Copies a single frame from `self.rx_frame_buf` into the guest. In case of an error retries
    // the operation if possible. Returns true if the operation was successfull.
    fn write_frame_to_guest(&mut self) -> bool {
        let max_iterations = self.rx_q.queue.actual_size();
        for _ in 0..max_iterations {
            match self.write_frame_to_guest_impl() {
                Ok(()) => return true,
                Err(FrontendError::EmptyQueue) => {
                    // retry
                    continue;
                }
                Err(_) => {
                    // retry
                    continue;
                }
            }
        }

        false
    }

    /// Fills self.rx_frame_buf with an ethernet frame from backend and prepends virtio_net_hdr to it
    fn read_into_rx_frame_buf_from_backend(&mut self) -> result::Result<(), ReadError> {
        self.rx_frame_buf_len = self.backend.read_frame(&mut self.rx_frame_buf)?;
        Ok(())
    }
}

impl NetWorker {
    pub(super) fn capture_state(&self) -> std::io::Result<crate::virtio::DeviceSnapshot> {
        // Deferred frames are host-network state. Preserve them in the same VM
        // when pausing, but do not publish a checkpoint that silently drops one.
        if self.rx_has_deferred_frame || self.tx_has_deferred_frame {
            return Err(std::io::Error::other(
                "network has a deferred frame at checkpoint",
            ));
        }
        Ok(crate::virtio::DeviceSnapshot {
            queues: vec![
                self.rx_q.queue.capture_state(),
                self.tx_q.queue.capture_state(),
            ],
            payload: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::VIRTQ_DESC_F_WRITE;
    use std::io::Write;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    // The guest offers one receive buffer, then the backend sends two frames.
    // The second frame waits for a buffer. With VIRTIO_RING_F_EVENT_IDX the
    // guest notifies after adding a buffer only if `avail_event` lies in the
    // range of indices it just made available, so the worker must leave
    // `avail_event` at the buffer the waiting frame needs next.
    #[test]
    fn deferred_rx_frame_asks_the_guest_to_notify_its_next_buffer() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let rx_vq = VirtQueue::new(GuestAddress(0), &mem, 4);
        let tx_vq = VirtQueue::new(GuestAddress(0x1000), &mem, 4);
        let mut rx_queue = rx_vq.create_queue();
        rx_queue.set_event_idx(true);
        let mut tx_queue = tx_vq.create_queue();
        tx_queue.set_event_idx(true);

        rx_vq.dtable[0].set(0x4000, 0x1000, VIRTQ_DESC_F_WRITE, 0);
        rx_vq.avail.ring[0].set(0);
        rx_vq.avail.idx.set(1);

        let (worker_end, mut proxy_end) = UnixStream::pair().unwrap();
        let mut worker = NetWorker::new(
            DeviceQueue::new(rx_queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())),
            DeviceQueue::new(tx_queue, Arc::new(EventFd::new(EFD_NONBLOCK).unwrap())),
            InterruptTransport::new(DummyIrqChip::new().into(), "net".into()).unwrap(),
            mem.clone(),
            0,
            VirtioNetBackend::UnixstreamFd(OwnedFd::from(worker_end).into_raw_fd()),
        )
        .unwrap();

        for _ in 0..2 {
            proxy_end.write_all(&64u32.to_be_bytes()).unwrap();
            proxy_end.write_all(&[0xab; 64]).unwrap();
        }
        worker.process_backend_socket_readable();

        assert_eq!(rx_vq.used.idx.get(), 1);
        assert!(worker.rx_has_deferred_frame);
        assert_eq!(rx_vq.used.event.get(), 1);
    }
}
