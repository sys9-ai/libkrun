#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::thread;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

#[cfg(target_os = "linux")]
const CHECKPOINT_STATE_LIMIT: usize = 64 * 1024 * 1024;

enum FsServer {
    ReadWrite(Server<PassthroughFs>),
    ReadOnly(Server<PassthroughFsRo>),
}

impl FsServer {
    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }
}

pub struct FsWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shm_region: Option<VirtioShmRegion>,
    server: FsServer,
    stop_fd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

impl FsWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<Arc<EventFd>>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        shm_region: Option<VirtioShmRegion>,
        passthrough_cfg: passthrough::Config,
        read_only: bool,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: Option<Sender<WorkerMessage>>,
    ) -> Result<Self, io::Error> {
        let server = if read_only {
            FsServer::ReadOnly(Server::new(PassthroughFsRo::new(passthrough_cfg)?))
        } else {
            FsServer::ReadWrite(Server::new(PassthroughFs::new(passthrough_cfg)?))
        };
        Ok(Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            shm_region,
            server,
            stop_fd,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender,
        })
    }

    pub fn run(self) -> thread::JoinHandle<Self> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) -> Self {
        let virtq_hpq_ev_fd = self.queue_evts[HPQ_INDEX].as_raw_fd();
        let virtq_req_ev_fd = self.queue_evts[REQ_INDEX].as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_hpq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_hpq_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_req_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_req_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_hpq_ev_fd => {
                                self.handle_event(HPQ_INDEX);
                            }
                            EventSet::IN if source == virtq_req_ev_fd => {
                                self.handle_event(REQ_INDEX);
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return self;
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
    }

    fn handle_event(&mut self, queue_index: usize) {
        debug!("Fs: queue event: {queue_index}");
        if let Err(e) = self.queue_evts[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }

        loop {
            self.queues[queue_index]
                .disable_notification(&self.mem)
                .unwrap();

            self.process_queue(queue_index);

            if !self.queues[queue_index]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_queue(&mut self, queue_index: usize) {
        let queue = &mut self.queues[queue_index];
        while let Some(head) = queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            if let Err(e) = self.server.handle_message(
                reader,
                writer,
                &self.shm_region,
                &self.exit_code,
                #[cfg(target_os = "macos")]
                &self.map_sender,
            ) {
                error!("error handling message: {e:?}");
            }

            if let Err(e) = queue.add_used(&self.mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if queue.needs_notification(&self.mem).unwrap() {
                self.interrupt.signal_used_queue();
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl FsWorker {
    pub fn capture_state(
        &self,
        directory: &std::path::Path,
    ) -> io::Result<crate::virtio::DeviceSnapshot> {
        use std::sync::atomic::Ordering;
        let (state, options) = match &self.server {
            FsServer::ReadWrite(server) => (
                server.fs.capture_state(directory)?,
                server.options.load(Ordering::Relaxed),
            ),
            FsServer::ReadOnly(server) => (
                server.fs.inner.capture_state(directory)?,
                server.options.load(Ordering::Relaxed),
            ),
        };
        let payload = crate::checkpoint::encode::<_, CHECKPOINT_STATE_LIMIT>(&(
            state,
            options,
            matches!(self.server, FsServer::ReadOnly(_)),
        ))?;
        Ok(crate::virtio::DeviceSnapshot {
            queues: self.queues.iter().map(Queue::capture_state).collect(),
            payload,
        })
    }

    pub fn restore_state(&mut self, payload: &[u8], directory: &std::path::Path) -> io::Result<()> {
        use super::passthrough::checkpoint::FilesystemState;
        use std::sync::atomic::Ordering;
        let (state, options, read_only): (FilesystemState, u64, bool) =
            crate::checkpoint::decode::<_, CHECKPOINT_STATE_LIMIT>(payload)?;
        if read_only != matches!(self.server, FsServer::ReadOnly(_)) {
            return Err(io::Error::other(
                "filesystem checkpoint access mode or payload differs",
            ));
        }
        match &self.server {
            FsServer::ReadWrite(server) => {
                server.fs.restore_state(state, directory)?;
                server.options.store(options, Ordering::Relaxed);
            }
            FsServer::ReadOnly(server) => {
                server.fs.inner.restore_state(state, directory)?;
                server.options.store(options, Ordering::Relaxed);
            }
        }
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::fs::filesystem::{Context, FileSystem, FsOptions};
    use crate::virtio::fs::fuse;
    use utils::eventfd::EFD_NONBLOCK;
    use vm_memory::GuestAddress;

    #[test]
    fn memory_checkpoint_capture_rejects_unrestorable_directory_caches() {
        let directory = std::env::temp_dir().join(format!(
            "krun-fs-budget-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = directory.join("root");
        let payloads = directory.join("payloads");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir(&payloads).unwrap();
        let suffix = "x".repeat(236);
        for index in 0..1024 {
            std::fs::File::create(root.join(format!("{index:04}{suffix}"))).unwrap();
        }

        let new_worker = || {
            FsWorker::new(
                vec![Queue::new(1024), Queue::new(1024)],
                Vec::new(),
                InterruptTransport::new(DummyIrqChip::new().into(), "checkpoint-test".into())
                    .unwrap(),
                GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap(),
                None,
                passthrough::Config {
                    root_dir: root.to_str().unwrap().into(),
                    checkpoint_enabled: true,
                    ..Default::default()
                },
                false,
                EventFd::new(EFD_NONBLOCK).unwrap(),
                Arc::new(AtomicI32::new(0)),
            )
            .unwrap()
        };
        let source = new_worker();
        let FsServer::ReadWrite(server) = &source.server else {
            unreachable!();
        };
        server.fs.init(FsOptions::empty()).unwrap();
        let context = Context {
            uid: 0,
            gid: 0,
            pid: 0,
        };
        let (handle, _) = server.fs.opendir(context, fuse::ROOT_ID, 0).unwrap();
        let handle = handle.unwrap();
        server
            .fs
            .readdir(context, fuse::ROOT_ID, handle, 4096, 0, |_| Ok(1))
            .unwrap();
        let small = source.capture_state(&payloads).unwrap();
        let mut restored = new_worker();
        restored.restore_state(&small.payload, &payloads).unwrap();
        let FsServer::ReadWrite(restored_server) = &restored.server else {
            unreachable!();
        };
        let mut remaining_entries = 0;
        restored_server
            .fs
            .readdir(context, fuse::ROOT_ID, handle, 4096, 1, |_| {
                remaining_entries += 1;
                Ok(1)
            })
            .unwrap();
        assert_eq!(remaining_entries, 1023);
        drop(restored);

        // Each real enumeration is below the 16 MiB per-handle limit. Retaining
        // multiple handles grows checkpoint state without large files or a huge
        // directory. The bincode decoder charges 8+4+8 bytes for each entry's
        // inode/type/name length even when the varint encoding is smaller.
        for _ in 0..255 {
            let (handle, _) = server.fs.opendir(context, fuse::ROOT_ID, 0).unwrap();
            let mut entries = 0;
            server
                .fs
                .readdir(context, fuse::ROOT_ID, handle.unwrap(), 4096, 0, |_| {
                    entries += 1;
                    Ok(1)
                })
                .unwrap();
            assert_eq!(entries, 1024);
        }

        let captured = source.capture_state(&payloads);
        if let Ok(state) = &captured {
            assert!(
                state.payload.len() < 64 * 1024 * 1024,
                "fixture must catch decoder-budget overflow below the encoded-size limit"
            );
            let error = new_worker()
                .restore_state(&state.payload, &payloads)
                .unwrap_err();
            assert!(error.to_string().contains("LimitExceeded"), "{error}");
        }
        drop(source);
        std::fs::remove_dir_all(directory).unwrap();

        let error = captured.err().expect(
            "capture accepted directory caches that its own restore decoder rejects with LimitExceeded",
        );
        assert!(
            error.to_string().to_ascii_lowercase().contains("limit"),
            "capture must reject the codec limit, not an unrelated failure: {error}"
        );
    }
}
