use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crossbeam_channel::{Receiver, RecvTimeoutError};

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{DescriptorChain, FsError, Queue};
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::fuse::{InHeader, Opcode};
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

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

/// At most how many requests of one share of a VM with `vcpus` vCPUs are
/// served at once. A request holds its thread for its whole host call, so a
/// request that waits on slow storage, such as a network filesystem fetching
/// an uncached block, would otherwise hold up every request behind it.
/// Completing requests out of order is allowed: the guest matches each reply
/// to its request by the FUSE unique ID, and this device does not offer
/// VIRTIO_F_IN_ORDER.
///
/// Four covers what serving at once gains on slow storage: a cached read is
/// not held up by a process reading uncached files one after another, and
/// four readers of one uncached file fetch in parallel. A guest with more
/// vCPUs runs more processes at once, each of which may wait on a request, so
/// a share serves up to one request per vCPU. Threads beyond the first exit
/// once the share has had no request for `IDLE_THREAD_EXIT`, so the bound
/// costs only while the share is in use.
///
/// The macOS passthrough keeps per-inode state that its operations do not
/// synchronize with each other (the descriptor kept for an unlinked file), so
/// it serves one request at a time.
#[cfg(target_os = "linux")]
fn max_request_threads(vcpus: u8) -> usize {
    usize::from(vcpus).max(4)
}
#[cfg(target_os = "macos")]
fn max_request_threads(_vcpus: u8) -> usize {
    1
}

/// How long a share must go without a request before its threads other than
/// the first exit. A share that keeps receiving requests keeps its threads,
/// however far apart the requests are. Starting a thread costs tens of
/// microseconds, paid by the first request that waits together with another
/// after the share was idle, so this only needs to keep threads through the
/// pauses within a burst of requests, such as a build or a checkout, not
/// across bursts.
#[cfg(not(test))]
const IDLE_THREAD_EXIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const IDLE_THREAD_EXIT: Duration = Duration::from_millis(100);

/// A popped request and the index of the queue it came from.
type Request<'a> = (usize, DescriptorChain<'a>);

/// What the request threads share while the worker runs.
///
/// The threads take turns as leader, like the threads of a multithreaded
/// FUSE server reading /dev/fuse: the leader alone waits for and pops a
/// request, then hands leadership on and serves the request itself, so an
/// idle share answers a request without first waking another thread.
///
/// Leadership is the one `Leader` value, passed through a channel of
/// capacity one rather than guarded by a mutex, so that a thread waiting for
/// its turn can stop waiting once the share has been idle for
/// `IDLE_THREAD_EXIT`.
struct Pool<'a> {
    /// Hands leadership on.
    hand_on: Sender<Leader>,
    /// Delivers leadership to the next thread waiting for it.
    lead: Receiver<Leader>,
    /// Threads free to take the next request: a thread counts from when it
    /// is started, and from just before it answers its last request, until
    /// it has taken the next one. So the leader waiting for the guest counts,
    /// as do a thread not yet running and one whose answer the guest may
    /// already have. A thread that takes a request and was the last one
    /// counted leaves none to take the next while it serves this one.
    idle: AtomicUsize,
    /// Threads serving this share. A share starts with one and gains one only
    /// when a request is taken while no other thread is idle, up to the
    /// worker's `max_threads`: requests sent one after another keep two
    /// threads, one serving and one leading, and only requests that wait
    /// together start more. One sequential reader may still use two or
    /// three, as the guest's readahead overlaps its requests. Every thread
    /// but the first exits once the share has had no request for
    /// `IDLE_THREAD_EXIT`.
    threads: AtomicUsize,
    /// When the pool started; `last_request` counts from it.
    started: Instant,
    /// Nanoseconds from `started` to when the leader last popped a request.
    last_request: AtomicU64,
    /// Requests that change an inode, kept in the order the guest sent them.
    /// An inode has an entry while a thread serves one of its changes; the
    /// changes popped meanwhile wait in the entry for that same thread.
    ///
    /// One inode's changes must reach the host in order: under writeback
    /// caching the guest sends a file's dirty pages without waiting for them,
    /// then a SETATTR with the mtime it assigned, and a WRITE served after
    /// that SETATTR would leave the host with the time of the write.
    changing: Mutex<HashMap<u64, VecDeque<Request<'a>>>>,
}

struct Leader {
    epoll: Epoll,
    stopping: bool,
}

/// Leadership held by one thread. Dropping it hands it on, also when the
/// thread panics while leading: it then hands it on stopping, so the other
/// threads stop too and joining the worker reports the panic, instead of
/// waiting forever for a leader that unwinding dropped.
struct Leadership<'p> {
    hand_on: &'p Sender<Leader>,
    leader: Option<Leader>,
}

impl std::ops::Deref for Leadership<'_> {
    type Target = Leader;

    fn deref(&self) -> &Leader {
        self.leader.as_ref().unwrap()
    }
}

impl std::ops::DerefMut for Leadership<'_> {
    fn deref_mut(&mut self) -> &mut Leader {
        self.leader.as_mut().unwrap()
    }
}

impl Drop for Leadership<'_> {
    fn drop(&mut self) {
        let mut leader = self.leader.take().unwrap();
        if thread::panicking() {
            leader.stopping = true;
        }
        // Never fails or blocks: the pool holds the receiver, and the one
        // leader is not in the channel while held.
        self.hand_on.send(leader).unwrap();
    }
}

impl<'a> Pool<'a> {
    /// A pool of one thread, the caller, idle and free to lead.
    fn new(epoll: Epoll) -> Self {
        let (hand_on, lead) = crossbeam_channel::bounded(1);
        hand_on
            .send(Leader {
                epoll,
                stopping: false,
            })
            .unwrap();
        Pool {
            hand_on,
            lead,
            idle: AtomicUsize::new(1),
            threads: AtomicUsize::new(1),
            started: Instant::now(),
            last_request: AtomicU64::new(0),
            changing: Mutex::new(HashMap::new()),
        }
    }

    fn saw_request(&self) {
        self.last_request
            .store(self.started.elapsed().as_nanos() as u64, Ordering::Relaxed);
    }

    /// How long the share has gone without a request.
    fn idle_for(&self) -> Duration {
        let last = Duration::from_nanos(self.last_request.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }

    /// How long a thread that may retire waits before trying: until the share
    /// has been idle for `IDLE_THREAD_EXIT`, or another whole period if it
    /// already has and the thread could not retire.
    fn until_retirement(&self) -> Duration {
        IDLE_THREAD_EXIT
            .checked_sub(self.idle_for())
            .filter(|left| !left.is_zero())
            .unwrap_or(IDLE_THREAD_EXIT)
    }

    /// Ends a thread's part in serving this share once the share has had no
    /// request for `IDLE_THREAD_EXIT`, but only while another thread stays
    /// idle to take the next request: one that waits on slow storage would
    /// otherwise hold up every request behind it.
    fn retire(&self) -> bool {
        if self.idle_for() < IDLE_THREAD_EXIT {
            return false;
        }
        let retired = self
            .idle
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |idle| {
                (idle > 1).then_some(idle - 1)
            })
            .is_ok();
        // The retiring thread still runs until it returns, so `threads` may
        // briefly count one fewer than run, and a thread started meanwhile
        // can exceed the bound by the one that is exiting.
        if retired {
            self.threads.fetch_sub(1, Ordering::SeqCst);
        }
        retired
    }

    /// Waits for leadership. Returns None if this thread, if
    /// `exits_when_idle`, retires instead.
    fn wait_to_lead(&self, exits_when_idle: bool) -> Option<Leadership<'_>> {
        let leader = if exits_when_idle {
            loop {
                match self.lead.recv_timeout(self.until_retirement()) {
                    Ok(leader) => break leader,
                    Err(RecvTimeoutError::Timeout) if self.retire() => return None,
                    Err(RecvTimeoutError::Timeout) => {}
                    Err(RecvTimeoutError::Disconnected) => {
                        unreachable!("the pool keeps both ends of its channel")
                    }
                }
            }
        } else {
            self.lead.recv().unwrap()
        };
        Some(Leadership {
            hand_on: &self.hand_on,
            leader: Some(leader),
        })
    }
}

/// The inode whose data or attributes `head` changes, or None for any other
/// request. A request whose header cannot be read is left to `handle` to
/// reject. The serving thread reads the header again; a guest that changes it
/// in between only misorders its own requests.
fn changed_inode(mem: &GuestMemoryMmap, head: &DescriptorChain) -> Option<u64> {
    let header: InHeader = Reader::new(mem, head.clone()).ok()?.read_obj().ok()?;
    [Opcode::Write, Opcode::Setattr, Opcode::Fallocate]
        .iter()
        .any(|opcode| *opcode as u32 == header.opcode)
        .then_some(header.nodeid)
}

pub struct FsWorker {
    queues: Vec<Mutex<Queue>>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    shm_region: Option<VirtioShmRegion>,
    server: FsServer,
    max_threads: usize,
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
        vcpus: u8,
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
            queues: queues.into_iter().map(Mutex::new).collect(),
            queue_evts,
            interrupt,
            mem,
            shm_region,
            server,
            max_threads: max_request_threads(vcpus),
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

    /// Serves requests on this thread and, as needed, up to
    /// `max_threads - 1` others.
    /// Returns once stopped and every popped request is answered, so the
    /// queues can then be captured or reset: requests still in the ring stay
    /// there, and none is half-served.
    fn work(self) -> Self {
        let epoll = Epoll::new().unwrap();
        for fd in [
            self.queue_evts[HPQ_INDEX].as_raw_fd(),
            self.queue_evts[REQ_INDEX].as_raw_fd(),
            self.stop_fd.as_raw_fd(),
        ] {
            // A share whose events are not watched would never answer.
            if let Err(e) = epoll.ctl(
                ControlOperation::Add,
                fd,
                &EpollEvent::new(EventSet::IN, fd as u64),
            ) {
                error!("failed to watch virtio-fs events: {e}");
                std::process::abort();
            }
        }
        let pool = Pool::new(epoll);
        // This thread is the share's first and never exits while it runs: it
        // returns the worker once stopped.
        thread::scope(|scope| self.serve_requests(scope, &pool, false));
        self
    }

    /// Serves requests until the worker stops or, if `exits_when_idle`, until
    /// this thread retires once the share has been idle for
    /// `IDLE_THREAD_EXIT`.
    fn serve_requests<'scope, 'env>(
        &'env self,
        scope: &'scope thread::Scope<'scope, 'env>,
        pool: &'env Pool<'env>,
        exits_when_idle: bool,
    ) {
        while let Some((mut request, inode)) = self.take_request(pool, exits_when_idle) {
            // Start a thread if this one was the last idle one, so that one
            // is left to take the next request while this request is served.
            let grow = pool.idle.fetch_sub(1, Ordering::SeqCst) == 1
                && pool
                    .threads
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |threads| {
                        (threads < self.max_threads).then_some(threads + 1)
                    })
                    .is_ok();
            if grow {
                // Until a failed start is undone below, `idle` counts a thread
                // that never runs, so a request taken meanwhile starts none;
                // the next request taken with no thread idle tries again.
                pool.idle.fetch_add(1, Ordering::SeqCst);
                if let Err(e) = thread::Builder::new()
                    .name("fs request".into())
                    .spawn_scoped(scope, move || self.serve_requests(scope, pool, true))
                {
                    pool.idle.fetch_sub(1, Ordering::SeqCst);
                    pool.threads.fetch_sub(1, Ordering::SeqCst);
                    warn!("virtio-fs serves with fewer threads, one failed to start: {e}");
                }
            }
            loop {
                self.handle(&request.1);
                // Then the changes of this inode popped meanwhile, in order.
                let next = inode.and_then(|inode| {
                    let mut changing = pool.changing.lock().unwrap();
                    // Only this thread removes the entry it created, and it
                    // drains the entry before it leads again, so the entry is
                    // still there.
                    let Entry::Occupied(mut pending) = changing.entry(inode) else {
                        unreachable!("an inode being changed has an entry");
                    };
                    let next = pending.get_mut().pop_front();
                    if next.is_none() {
                        pending.remove();
                    }
                    next
                });
                // Idle again before the guest can see the last answer, so that
                // a request the guest sends in reply finds this thread idle.
                if next.is_none() {
                    pool.idle.fetch_add(1, Ordering::SeqCst);
                }
                self.answer(request);
                let Some(next) = next else { break };
                request = next;
            }
        }
    }

    /// Becomes the leader and pops the next request this thread serves, and
    /// the inode it changes, if any. Returns None once the worker stops or
    /// this thread, if `exits_when_idle`, retires.
    fn take_request<'a>(
        &'a self,
        pool: &Pool<'a>,
        exits_when_idle: bool,
    ) -> Option<(Request<'a>, Option<u64>)> {
        let mut leadership = pool.wait_to_lead(exits_when_idle)?;
        // Dropping the leadership hands it on.
        self.take_request_as_leader(pool, &mut leadership, exits_when_idle)
    }

    fn take_request_as_leader<'a>(
        &'a self,
        pool: &Pool<'a>,
        leader: &mut Leader,
        exits_when_idle: bool,
    ) -> Option<(Request<'a>, Option<u64>)> {
        loop {
            let request = self.next_request(pool, leader, exits_when_idle)?;
            let Some(inode) = changed_inode(&self.mem, &request.1) else {
                return Some((request, None));
            };
            match pool.changing.lock().unwrap().entry(inode) {
                // Another thread is changing this inode: it serves this
                // request after the earlier ones.
                Entry::Occupied(mut pending) => pending.get_mut().push_back(request),
                Entry::Vacant(pending) => {
                    pending.insert(VecDeque::new());
                    return Some((request, Some(inode)));
                }
            }
        }
    }

    /// Pops a request, waiting for the guest to add one if both queues are
    /// empty. Returns None once the worker is stopped, or once this thread, if
    /// `exits_when_idle`, retires because the share has been idle for
    /// `IDLE_THREAD_EXIT`.
    fn next_request<'a>(
        &'a self,
        pool: &Pool,
        leader: &mut Leader,
        exits_when_idle: bool,
    ) -> Option<Request<'a>> {
        loop {
            if leader.stopping {
                return None;
            }
            for queue_index in [HPQ_INDEX, REQ_INDEX] {
                if let Some(head) = self.queues[queue_index].lock().unwrap().pop(&self.mem) {
                    pool.saw_request();
                    return Some((queue_index, head));
                }
            }
            // Both rings are empty: ask the guest for a notification, unless
            // a request arrived meanwhile.
            let mut arrived = false;
            for queue in &self.queues {
                arrived |= queue
                    .lock()
                    .unwrap()
                    .enable_notification(&self.mem)
                    .unwrap();
            }
            let timeout = exits_when_idle.then(|| pool.until_retirement());
            let timed_out = !arrived && self.wait(leader, timeout);
            // Notifications stay off from here until the rings are empty
            // again, including after a stop or a retirement: the next leader
            // pops before it waits.
            for queue in &self.queues {
                queue
                    .lock()
                    .unwrap()
                    .disable_notification(&self.mem)
                    .unwrap();
            }
            if timed_out && pool.retire() {
                return None;
            }
        }
    }

    /// Waits for a queue notification or the stop request, at most `timeout`
    /// if given. Returns whether it timed out.
    fn wait(&self, leader: &mut Leader, timeout: Option<Duration>) -> bool {
        let mut events = vec![EpollEvent::new(EventSet::empty(), 0); 3];
        // Rounded up, so the wait does not end before the share is idle long
        // enough to retire and spin until it is.
        let timeout_ms =
            timeout.map_or(-1, |timeout| timeout.as_nanos().div_ceil(1_000_000) as i32);
        let count = match leader.epoll.wait(events.len(), timeout_ms, &mut events) {
            Ok(count) => count,
            Err(e) => {
                debug!("failed to wait for virtio-fs events: {e}");
                return false;
            }
        };
        for event in &events[..count] {
            let source = event.fd();
            if source == self.stop_fd.as_raw_fd() {
                debug!("stopping worker thread");
                let _ = self.stop_fd.read();
                leader.stopping = true;
            } else if let Some(queue_evt) = self
                .queue_evts
                .iter()
                .find(|queue_evt| queue_evt.as_raw_fd() == source)
            {
                if let Err(e) = queue_evt.read() {
                    error!("Failed to get queue event: {e:?}");
                }
            } else {
                log::warn!(
                    "Received unknown event: {:?} from fd: {source:?}",
                    event.event_set()
                );
            }
        }
        count == 0
    }

    /// Serves the request `head` on the host, writing the reply into its
    /// buffers. The guest sees the reply only once it is answered.
    fn handle(&self, head: &DescriptorChain) {
        match (
            Reader::new(&self.mem, head.clone()),
            Writer::new(&self.mem, head.clone()),
        ) {
            (Ok(reader), Ok(writer)) => {
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
            }
            // Returned unanswered: the guest broke the descriptor format.
            (Err(e), _) => error!("{:?}", FsError::QueueReader(e)),
            (_, Err(e)) => error!("{:?}", FsError::QueueWriter(e)),
        }
    }

    /// Hands a handled request back to the guest.
    fn answer(&self, (queue_index, head): Request) {
        let needs_notification = {
            let mut queue = self.queues[queue_index].lock().unwrap();
            if let Err(e) = queue.add_used(&self.mem, head.index, 0) {
                error!("failed to add used elements to the queue: {e:?}");
            }
            queue.needs_notification(&self.mem).unwrap()
        };
        if needs_notification {
            self.interrupt.signal_used_queue();
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
        let payload = bincode::serde::encode_to_vec(
            (state, options, matches!(self.server, FsServer::ReadOnly(_))),
            bincode::config::standard(),
        )
        .map_err(io::Error::other)?;
        Ok(crate::virtio::DeviceSnapshot {
            queues: self
                .queues
                .iter()
                .map(|queue| queue.lock().unwrap().capture_state())
                .collect(),
            payload,
        })
    }

    pub fn restore_state(&mut self, payload: &[u8], directory: &std::path::Path) -> io::Result<()> {
        use super::passthrough::checkpoint::FilesystemState;
        use std::sync::atomic::Ordering;
        let ((state, options, read_only), consumed): ((FilesystemState, u64, bool), usize) =
            bincode::serde::decode_from_slice(
                payload,
                bincode::config::standard().with_limit::<67108864>(),
            )
            .map_err(io::Error::other)?;
        if consumed != payload.len() || read_only != matches!(self.server, FsServer::ReadOnly(_)) {
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
    use std::mem::size_of;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, Instant};

    use utils::eventfd::EventFd;
    use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemoryMmap};

    use super::super::fuse::{
        EntryOut, GetattrIn, InHeader, InitInCompat, Opcode, OpenIn, SetattrIn,
        KERNEL_MINOR_VERSION, KERNEL_VERSION, ROOT_ID,
    };
    use super::*;
    use crate::legacy::DummyIrqChip;
    use crate::virtio::queue::tests::VirtQueue;
    use crate::virtio::queue::{VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE};

    const RING_SIZE: u16 = 64;
    /// The vCPUs of the tests' VM, whose shares serve up to four requests at once.
    const VCPUS: u8 = 2;
    const THREADS: usize = 4;
    const BUFFERS: u64 = 0x10000;
    const BUFFER_SIZE: u64 = 0x1000;

    /// Held by every test that starts a worker, so that a test can count the
    /// request threads of its own worker as those of the process.
    static ONE_WORKER: Mutex<()> = Mutex::new(());

    fn one_worker() -> std::sync::MutexGuard<'static, ()> {
        ONE_WORKER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// How many "fs request" threads the process runs.
    fn request_threads() -> usize {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter(|task| {
                let comm = task.as_ref().unwrap().path().join("comm");
                std::fs::read_to_string(comm).is_ok_and(|name| name == "fs request\n")
            })
            .count()
    }

    /// The guest driver's side of the request queue: one request per pair of
    /// descriptors, a readable request and a writable reply buffer.
    struct Guest<'a> {
        mem: &'a GuestMemoryMmap,
        queue: VirtQueue<'a>,
        kick: Arc<EventFd>,
        sent: u16,
    }

    impl Guest<'_> {
        fn send(&mut self, opcode: Opcode, nodeid: u64, body: &[u8]) {
            let request = GuestAddress(BUFFERS + u64::from(self.sent) * 2 * BUFFER_SIZE);
            let reply = GuestAddress(request.0 + BUFFER_SIZE);
            let len = size_of::<InHeader>() + body.len();
            let header = InHeader {
                len: len as u32,
                opcode: opcode as u32,
                unique: u64::from(self.sent) + 1,
                nodeid,
                ..Default::default()
            };
            self.mem.write_obj(header, request).unwrap();
            self.mem
                .write_slice(body, GuestAddress(request.0 + size_of::<InHeader>() as u64))
                .unwrap();
            let head = 2 * self.sent;
            self.queue.dtable[head as usize].set(
                request.0,
                len as u32,
                VIRTQ_DESC_F_NEXT,
                head + 1,
            );
            self.queue.dtable[head as usize + 1].set(
                reply.0,
                BUFFER_SIZE as u32,
                VIRTQ_DESC_F_WRITE,
                0,
            );
            self.queue.avail.ring[self.sent as usize].set(head);
            self.sent += 1;
            self.queue.avail.idx.set(self.sent);
            self.kick.write(1).unwrap();
        }

        /// Whether the device has answered `count` requests within a second.
        /// It spins rather than sleeps, so that the next request follows an
        /// answer as closely as a guest process's would: a thread that counts
        /// itself idle only after answering would then start threads.
        fn answered(&self, count: u16) -> bool {
            let deadline = Instant::now() + Duration::from_secs(1);
            while self.queue.used.idx.get() < count {
                if Instant::now() > deadline {
                    return false;
                }
                thread::yield_now();
            }
            true
        }

        /// The reply body of the `index`th request, after its out header.
        fn reply<T: ByteValued>(&self, index: u16) -> T {
            let reply = BUFFERS + (2 * u64::from(index) + 1) * BUFFER_SIZE;
            self.mem.read_obj(GuestAddress(reply + 16)).unwrap()
        }
    }

    /// Starts a worker serving `dir` and initializes the connection.
    fn start<'a>(
        dir: &std::path::Path,
        mem: &'a GuestMemoryMmap,
    ) -> (thread::JoinHandle<FsWorker>, EventFd, Guest<'a>) {
        let hiprio = VirtQueue::new(GuestAddress(0), mem, RING_SIZE);
        let requests = VirtQueue::new(GuestAddress(0x8000), mem, RING_SIZE);
        let queue_evts = vec![
            Arc::new(EventFd::new(0).unwrap()),
            Arc::new(EventFd::new(0).unwrap()),
        ];
        let stop = EventFd::new(0).unwrap();
        let worker = FsWorker::new(
            vec![hiprio.create_queue(), requests.create_queue()],
            queue_evts.clone(),
            InterruptTransport::new(DummyIrqChip::new().into(), "fs".into()).unwrap(),
            mem.clone(),
            None,
            passthrough::Config {
                root_dir: dir.to_str().unwrap().to_string(),
                ..Default::default()
            },
            false,
            VCPUS,
            stop.try_clone().unwrap(),
            Arc::new(AtomicI32::new(0)),
        )
        .unwrap()
        .run();
        let mut guest = Guest {
            mem,
            queue: requests,
            kick: queue_evts[REQ_INDEX].clone(),
            sent: 0,
        };
        let init = InitInCompat {
            major: KERNEL_VERSION,
            minor: KERNEL_MINOR_VERSION,
            max_readahead: 0,
            flags: 0,
        };
        // Like the kernel, send nothing else until INIT is answered.
        guest.send(Opcode::Init, 0, init.as_slice());
        assert!(guest.answered(1));
        (worker, stop, guest)
    }

    #[test]
    fn a_blocked_request_does_not_hold_up_later_requests() {
        let _one_worker = one_worker();
        let dir = std::env::temp_dir().join(format!("krun-fs-worker-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fifo = std::ffi::CString::new(dir.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let (worker, stop, mut guest) = start(&dir, &mem);
        guest.send(Opcode::Lookup, ROOT_ID, b"fifo\0");
        assert!(guest.answered(2));
        let fifo = guest.reply::<EntryOut>(1).nodeid;

        // Opening a FIFO for reading blocks the host call until a writer opens it.
        let open = OpenIn {
            flags: libc::O_RDONLY as u32,
            open_flags: 0,
        };
        guest.send(Opcode::Open, fifo, open.as_slice());
        guest.send(Opcode::Getattr, ROOT_ID, GetattrIn::default().as_slice());
        assert!(guest.answered(3), "getattr waited for the blocked open");

        // Stopping waits for the request in flight: a checkpoint taken after
        // stop must see every popped request answered.
        stop.write(1).unwrap();
        thread::sleep(Duration::from_millis(100));
        assert!(!worker.is_finished(), "stopped with the open unanswered");
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("fifo"))
            .unwrap();
        worker.join().unwrap();
        assert_eq!(guest.queue.used.idx.get(), 4);
        drop(writer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn writes_and_attribute_changes_name_the_inode_they_change() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let ring = VirtQueue::new(GuestAddress(0), &mem, RING_SIZE);
        let mut queue = ring.create_queue();
        let mut guest = Guest {
            mem: &mem,
            queue: ring,
            kick: Arc::new(EventFd::new(0).unwrap()),
            sent: 0,
        };
        guest.send(Opcode::Write, 7, &[0; 64]);
        guest.send(Opcode::Setattr, 7, &[0; 64]);
        guest.send(Opcode::Fallocate, 8, &[0; 64]);
        guest.send(Opcode::Read, 7, &[0; 64]);
        guest.send(Opcode::Getattr, 7, &[0; 64]);

        let changed: Vec<_> = std::iter::from_fn(|| queue.pop(&mem))
            .map(|head| changed_inode(&mem, &head))
            .collect();
        assert_eq!(changed, [Some(7), Some(7), Some(8), None, None]);
    }

    #[test]
    fn one_inodes_attribute_changes_reach_the_host_in_order() {
        let _one_worker = one_worker();
        let dir = std::env::temp_dir().join(format!("krun-fs-order-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("file"), b"").unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let (worker, stop, mut guest) = start(&dir, &mem);
        guest.send(Opcode::Lookup, ROOT_ID, b"file\0");
        assert!(guest.answered(2));
        let file = guest.reply::<EntryOut>(1).nodeid;

        for mtime in 1..=16 {
            let setattr = SetattrIn {
                valid: 32, // FATTR_MTIME
                mtime,
                ..Default::default()
            };
            guest.send(Opcode::Setattr, file, setattr.as_slice());
        }
        assert!(guest.answered(18));
        let mtime = std::fs::metadata(dir.join("file")).unwrap().mtime();
        assert_eq!(mtime, 16, "a SETATTR overtook a later one");

        stop.write(1).unwrap();
        worker.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_share_starts_threads_only_for_requests_that_wait_together() {
        let _one_worker = one_worker();
        let dir = std::env::temp_dir().join(format!("krun-fs-threads-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fifo = std::ffi::CString::new(dir.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let (worker, stop, mut guest) = start(&dir, &mem);
        guest.send(Opcode::Lookup, ROOT_ID, b"fifo\0");
        assert!(guest.answered(2));
        let fifo = guest.reply::<EntryOut>(1).nodeid;

        // Each request is sent as soon as the one before is answered, as by a
        // process reading a file: one thread leads while the other serves.
        for sent in 3..=12 {
            guest.send(Opcode::Getattr, ROOT_ID, GetattrIn::default().as_slice());
            assert!(guest.answered(sent));
        }
        // The thread started for the first request may not be running yet.
        assert!(
            request_threads() <= 1,
            "requests sent one by one started threads"
        );

        // Each open holds its thread until a writer opens the FIFO, so the
        // opens leave no thread idle and the share grows to its limit; the
        // GETATTR behind them then waits for a thread.
        let open = OpenIn {
            flags: libc::O_RDONLY as u32,
            open_flags: 0,
        };
        for _ in 0..THREADS {
            guest.send(Opcode::Open, fifo, open.as_slice());
        }
        guest.send(Opcode::Getattr, ROOT_ID, GetattrIn::default().as_slice());
        assert!(
            !guest.answered(13),
            "more than four threads serve the share"
        );
        assert_eq!(
            request_threads(),
            THREADS - 1,
            "the worker's own thread and the request threads"
        );

        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("fifo"))
            .unwrap();
        assert!(guest.answered(13 + THREADS as u16));
        stop.write(1).unwrap();
        worker.join().unwrap();
        drop(writer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_share_serves_at_least_four_and_up_to_one_request_per_vcpu() {
        assert_eq!(max_request_threads(1), 4);
        assert_eq!(max_request_threads(4), 4);
        assert_eq!(max_request_threads(8), 8);
    }

    #[test]
    fn idle_threads_exit_and_the_first_serves_on() {
        let _one_worker = one_worker();
        let dir = std::env::temp_dir().join(format!("krun-fs-idle-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fifo = std::ffi::CString::new(dir.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let (worker, stop, mut guest) = start(&dir, &mem);
        guest.send(Opcode::Lookup, ROOT_ID, b"fifo\0");
        assert!(guest.answered(2));
        let fifo = guest.reply::<EntryOut>(1).nodeid;

        // Opens blocked together grow the share to its limit.
        let open = OpenIn {
            flags: libc::O_RDONLY as u32,
            open_flags: 0,
        };
        for _ in 0..THREADS {
            guest.send(Opcode::Open, fifo, open.as_slice());
        }
        assert!(!guest.answered(3));
        assert_eq!(request_threads(), THREADS - 1);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("fifo"))
            .unwrap();
        assert!(guest.answered(2 + THREADS as u16));
        drop(writer);

        // Once idle, every thread but the worker's own exits.
        let deadline = Instant::now() + IDLE_THREAD_EXIT * 20;
        while request_threads() != 0 {
            assert!(
                Instant::now() < deadline,
                "idle request threads kept running"
            );
            thread::sleep(IDLE_THREAD_EXIT / 10);
        }
        guest.send(Opcode::Getattr, ROOT_ID, GetattrIn::default().as_slice());
        assert!(
            guest.answered(3 + THREADS as u16),
            "no thread left to serve"
        );

        // Requests that wait together start threads again.
        for _ in 0..THREADS {
            guest.send(Opcode::Open, fifo, open.as_slice());
        }
        assert!(!guest.answered(4 + THREADS as u16));
        assert_eq!(request_threads(), THREADS - 1);
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("fifo"))
            .unwrap();
        assert!(guest.answered(3 + 2 * THREADS as u16));

        stop.write(1).unwrap();
        worker.join().unwrap();
        drop(writer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_share_keeps_its_threads_while_requests_keep_coming() {
        let _one_worker = one_worker();
        let dir = std::env::temp_dir().join(format!("krun-fs-trickle-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let fifo = std::ffi::CString::new(dir.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x40000)]).unwrap();
        let (worker, stop, mut guest) = start(&dir, &mem);
        guest.send(Opcode::Lookup, ROOT_ID, b"fifo\0");
        assert!(guest.answered(2));
        let fifo = guest.reply::<EntryOut>(1).nodeid;
        let open = OpenIn {
            flags: libc::O_RDONLY as u32,
            open_flags: 0,
        };
        for _ in 0..THREADS {
            guest.send(Opcode::Open, fifo, open.as_slice());
        }
        assert!(!guest.answered(3));
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("fifo"))
            .unwrap();
        assert!(guest.answered(2 + THREADS as u16));

        // Requests further apart than any one thread waits, but each well
        // within the idle period of the share, keep every thread.
        let mut answered = 2 + THREADS as u16;
        for _ in 0..10 {
            thread::sleep(IDLE_THREAD_EXIT / 4);
            guest.send(Opcode::Getattr, ROOT_ID, GetattrIn::default().as_slice());
            answered += 1;
            assert!(guest.answered(answered));
        }
        assert_eq!(request_threads(), THREADS - 1);

        // They exit once the share has had no request for the idle period.
        let deadline = Instant::now() + IDLE_THREAD_EXIT * 20;
        while request_threads() != 0 {
            assert!(
                Instant::now() < deadline,
                "idle request threads kept running"
            );
            thread::sleep(IDLE_THREAD_EXIT / 10);
        }

        stop.write(1).unwrap();
        worker.join().unwrap();
        drop(writer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_leader_that_panics_hands_on_leadership_that_stops_the_others() {
        let pool = Pool::new(Epoll::new().unwrap());

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _leadership = pool.wait_to_lead(false).unwrap();
            panic!("a bug while leading");
        }));

        assert!(panicked.is_err());
        let leader = pool.lead.try_recv().expect("leadership was dropped");
        assert!(leader.stopping, "the other threads would keep serving");
    }
}
