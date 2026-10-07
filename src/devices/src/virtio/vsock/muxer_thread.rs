use std::collections::HashMap;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use utils::eventfd::{EventFd, EFD_NONBLOCK};

use super::super::Queue as VirtQueue;
use super::muxer::{push_packet, MuxerRx, ProxyMap};
use super::muxer_rxq::MuxerRxQ;
use super::proxy::{NewProxyType, Proxy, ProxyRemoval, ProxyUpdate};
use super::tsi_stream::TsiStreamProxy;

use crate::virtio::vsock::defs;
use crate::virtio::vsock::unix::{UnixAcceptorProxy, UnixProxy};
use crate::virtio::InterruptTransport;
use crossbeam_channel::Sender;
use rand::{rng, rngs::ThreadRng, Rng};
use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use vm_memory::GuestMemoryMmap;

pub struct MuxerThread {
    pub(super) stop: Arc<EventFd>,
    initialized: bool,
    cid: u64,
    pub epoll: Epoll,
    rxq: Arc<Mutex<MuxerRxQ>>,
    proxy_map: ProxyMap,
    mem: GuestMemoryMmap,
    queue: Arc<Mutex<VirtQueue>>,
    interrupt: InterruptTransport,
    reaper_sender: Sender<u64>,
    unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::vsock::packet::{
        TsiAcceptReq, TsiConnectReq, TsiListenReq, TsiSendtoAddr, VsockPacket,
    };
    use crate::virtio::vsock::proxy::ProxyStatus;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::RwLock;
    use vm_memory::GuestAddress;

    struct CountingProxy {
        event: EventFd,
        handled: Arc<AtomicUsize>,
    }

    impl AsRawFd for CountingProxy {
        fn as_raw_fd(&self) -> RawFd {
            self.event.as_raw_fd()
        }
    }

    impl Proxy for CountingProxy {
        fn id(&self) -> u64 {
            1
        }

        fn status(&self) -> ProxyStatus {
            ProxyStatus::Connecting
        }

        fn process_event(&mut self, events: EventSet) -> ProxyUpdate {
            assert!(events.contains(EventSet::IN));
            assert_eq!(self.event.read().unwrap(), 1);
            self.handled.fetch_add(1, Ordering::SeqCst);
            ProxyUpdate::default()
        }

        fn connect(&mut self, _: &VsockPacket, _: TsiConnectReq) -> ProxyUpdate {
            unreachable!()
        }

        fn getpeername(&mut self, _: &VsockPacket) {
            unreachable!()
        }

        fn sendmsg(&mut self, _: &VsockPacket) -> ProxyUpdate {
            unreachable!()
        }

        fn sendto_addr(&mut self, _: TsiSendtoAddr) -> ProxyUpdate {
            unreachable!()
        }

        fn listen(
            &mut self,
            _: &VsockPacket,
            _: TsiListenReq,
            _: &Option<HashMap<u16, u16>>,
        ) -> ProxyUpdate {
            unreachable!()
        }

        fn accept(&mut self, _: TsiAcceptReq) -> ProxyUpdate {
            unreachable!()
        }

        fn update_peer_credit(&mut self, _: &VsockPacket) -> ProxyUpdate {
            unreachable!()
        }

        fn process_op_response(&mut self, _: &VsockPacket) -> ProxyUpdate {
            unreachable!()
        }

        fn release(&mut self) -> ProxyUpdate {
            unreachable!()
        }
    }

    #[test]
    fn muxer_constructor_handles_eventfd_exhaustion() {
        const CHILD: &str = "KRUN_TEST_MUXER_EVENTFD_EXHAUSTION";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "virtio::vsock::muxer_thread::tests::muxer_constructor_handles_eventfd_exhaustion",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "eventfd-exhaustion subprocess failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("running 1 test"));
            return;
        }

        let epoll = Epoll::new().unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap();
        let interrupt =
            InterruptTransport::new(DummyIrqChip::new().into(), "checkpoint-test".into()).unwrap();
        let (reaper_sender, _reaper_receiver) = crossbeam_channel::unbounded();
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // The child has all constructor inputs; only the constructor's control
        // eventfd now needs a new descriptor. The parent retains its own limits.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            MuxerThread::new(
                3,
                epoll,
                Arc::new(Mutex::new(MuxerRxQ::new())),
                Arc::new(RwLock::new(HashMap::new())),
                mem,
                Arc::new(Mutex::new(VirtQueue::new(256))),
                interrupt,
                reaper_sender,
                HashMap::new(),
            )
        }));
        assert!(
            result.is_ok(),
            "creating the vsock control eventfd must report exhaustion without panicking"
        );
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn quiesce_processes_proxy_edges_in_stop_batch() {
        let handled = Arc::new(AtomicUsize::new(0));
        let proxy = CountingProxy {
            event: EventFd::new(EFD_NONBLOCK).unwrap(),
            handled: handled.clone(),
        };
        let proxy_event = proxy.event.try_clone().unwrap();
        let proxy_map: ProxyMap = Arc::new(RwLock::new(HashMap::new()));
        proxy_map
            .write()
            .unwrap()
            .insert(proxy.id(), Mutex::new(Box::new(proxy)));
        let (reaper_sender, _reaper_receiver) = crossbeam_channel::unbounded();
        let mut worker = MuxerThread::new(
            3,
            Epoll::new().unwrap(),
            Arc::new(Mutex::new(MuxerRxQ::new())),
            proxy_map,
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096)]).unwrap(),
            Arc::new(Mutex::new(VirtQueue::new(256))),
            InterruptTransport::new(DummyIrqChip::new().into(), "checkpoint-test".into()).unwrap(),
            reaper_sender,
            HashMap::new(),
        )
        .unwrap();

        // Model an initialized worker at its next wait. Register and make stop
        // ready first so Linux returns it before the proxy's one-time edge.
        worker
            .epoll
            .ctl(
                ControlOperation::Add,
                worker.stop.as_raw_fd(),
                &EpollEvent::new(EventSet::IN, 0),
            )
            .unwrap();
        worker
            .epoll
            .ctl(
                ControlOperation::Add,
                proxy_event.as_raw_fd(),
                &EpollEvent::new(EventSet::IN | EventSet::EDGE_TRIGGERED, 1),
            )
            .unwrap();
        worker.initialized = true;
        worker.stop.write(1).unwrap();
        proxy_event.write(1).unwrap();

        let worker = worker.run().join().unwrap();
        assert_eq!(
            handled.load(Ordering::SeqCst),
            1,
            "quiesce discarded a delivered proxy edge after the stop event"
        );

        worker.stop.write(1).unwrap();
        let _worker = worker.run().join().unwrap();
        assert_eq!(handled.load(Ordering::SeqCst), 1);
    }
}

impl MuxerThread {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cid: u64,
        epoll: Epoll,
        rxq: Arc<Mutex<MuxerRxQ>>,
        proxy_map: ProxyMap,
        mem: GuestMemoryMmap,
        queue: Arc<Mutex<VirtQueue>>,
        interrupt: InterruptTransport,
        reaper_sender: Sender<u64>,
        unix_ipc_port_map: HashMap<u32, (PathBuf, bool)>,
    ) -> std::io::Result<Self> {
        Ok(MuxerThread {
            stop: Arc::new(EventFd::new(EFD_NONBLOCK)?),
            initialized: false,
            cid,
            epoll,
            rxq,
            proxy_map,
            mem,
            queue,
            interrupt,
            reaper_sender,
            unix_ipc_port_map,
        })
    }

    pub fn run(self) -> thread::JoinHandle<Self> {
        thread::Builder::new()
            .name("vsock muxer".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn send_credit_request(&self, credit_rx: MuxerRx) {
        debug!("send_credit_request");
        push_packet(self.cid, credit_rx, &self.rxq, &self.queue, &self.mem);
    }

    pub fn update_polling(&self, id: u64, fd: RawFd, evset: EventSet) {
        debug!("update_polling id={id} fd={fd:?} evset={evset:?}");
        let _ = self
            .epoll
            .ctl(ControlOperation::Delete, fd, &EpollEvent::default());
        if !evset.is_empty() {
            let _ = self
                .epoll
                .ctl(ControlOperation::Add, fd, &EpollEvent::new(evset, id));
        }
    }

    fn process_proxy_update(&self, id: u64, update: ProxyUpdate, thread_rng: &mut ThreadRng) {
        if let Some(polling) = update.polling {
            self.update_polling(polling.0, polling.1, polling.2);
        }

        if let Some(credit_rx) = update.push_credit_req {
            debug!("send_credit_request");
            self.send_credit_request(credit_rx);
        }

        match update.remove_proxy {
            ProxyRemoval::Keep => {}
            ProxyRemoval::Immediate => {
                warn!("immediately removing proxy: {id}");
                self.proxy_map.write().unwrap().remove(&id);
            }
            ProxyRemoval::Deferred => {
                warn!("deferring proxy removal: {id}");
                if self.reaper_sender.send(id).is_err() {
                    self.proxy_map.write().unwrap().remove(&id);
                }
            }
        }

        let mut should_signal = update.signal_queue;

        if let Some((peer_port, accept_fd, family, proxy_type)) = update.new_proxy {
            let local_port: u32 = thread_rng.random_range(1024..u32::MAX);
            let new_id: u64 = ((peer_port as u64) << 32) | (local_port as u64);
            let new_proxy: Box<dyn Proxy> = match proxy_type {
                NewProxyType::Tcp => Box::new(TsiStreamProxy::new_reverse(
                    new_id,
                    self.cid,
                    id,
                    family,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                )),
                NewProxyType::Unix => Box::new(UnixProxy::new_reverse(
                    new_id,
                    self.cid,
                    local_port,
                    peer_port,
                    accept_fd,
                    self.mem.clone(),
                    self.queue.clone(),
                    self.rxq.clone(),
                )),
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(new_id, Mutex::new(new_proxy));
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&new_id) {
                proxy.lock().unwrap().push_op_request();
            };
            should_signal = true;
        }

        if should_signal {
            debug!("signal IRQ");
            self.interrupt.signal_used_queue();
        }
    }

    fn create_lisening_ipc_sockets(&self) {
        for (port, (path, do_listen)) in &self.unix_ipc_port_map {
            if !do_listen {
                continue;
            }
            let id = ((*port as u64) << 32) | (defs::TSI_PROXY_PORT as u64);
            let proxy = match UnixAcceptorProxy::new(id, path, *port) {
                Ok(proxy) => proxy,
                Err(e) => {
                    warn!("Failed to create listening proxy at {path:?}: {e:?}");
                    continue;
                }
            };
            self.proxy_map
                .write()
                .unwrap()
                .insert(id, Mutex::new(Box::new(proxy)));
            if let Some(proxy) = self.proxy_map.read().unwrap().get(&id) {
                self.update_polling(id, proxy.lock().unwrap().as_raw_fd(), EventSet::IN);
            };
        }
    }

    fn work(mut self) -> Self {
        let mut thread_rng = rng();
        if !self.initialized {
            self.create_lisening_ipc_sockets();
            // Proxy IDs always contain a nonzero ephemeral port. Zero is reserved
            // for this worker's control event and cannot collide with a proxy.
            self.epoll
                .ctl(
                    ControlOperation::Add,
                    self.stop.as_raw_fd(),
                    &EpollEvent::new(EventSet::IN, 0),
                )
                .unwrap();
            self.initialized = true;
        }
        loop {
            let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
            match self
                .epoll
                .wait(epoll_events.len(), -1, epoll_events.as_mut_slice())
            {
                Ok(ev_cnt) => {
                    let mut stop_requested = false;
                    for ev in &epoll_events[0..ev_cnt] {
                        debug!("Event: ev.data={} ev.fd={}", ev.data(), ev.fd());
                        let evset = EventSet::from_bits(ev.events).unwrap();
                        let id = ev.data();
                        if id == 0 {
                            let _ = self.stop.read();
                            stop_requested = true;
                            continue;
                        }

                        let update = self.proxy_map.read().unwrap().get(&id).map(|proxy_lock| {
                            let mut proxy = proxy_lock.lock().unwrap();
                            proxy.process_event(evset)
                        });

                        if let Some(update) = update {
                            self.process_proxy_update(id, update, &mut thread_rng);
                        }
                    }
                    // epoll has consumed every edge in this batch. Finish it
                    // before pausing so resume cannot lose a proxy's only edge.
                    if stop_requested {
                        return self;
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }
}
