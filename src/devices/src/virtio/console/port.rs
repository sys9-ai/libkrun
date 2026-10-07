use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{mem, thread};

use vm_memory::GuestMemoryMmap;

use crate::virtio::console::console_control::ConsoleControl;
use crate::virtio::console::port_io::{PortInput, PortOutput};
use crate::virtio::console::process_rx::process_rx;
use crate::virtio::console::process_tx::process_tx;
use crate::virtio::port_io::PortTerminalProperties;
use crate::virtio::{InterruptTransport, Queue};

pub struct PortDescription {
    pub name: Cow<'static, str>,
    pub input: Option<Box<dyn PortInput + Send>>,
    pub output: Option<Box<dyn PortOutput + Send>>,
    pub terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl PortDescription {
    pub fn console(
        input: Option<Box<dyn PortInput + Send>>,
        output: Option<Box<dyn PortOutput + Send>>,
        terminal: Box<dyn PortTerminalProperties>,
    ) -> Self {
        Self {
            name: "".into(),
            input,
            output,
            terminal: Some(terminal),
        }
    }

    pub fn output_pipe(
        name: impl Into<Cow<'static, str>>,
        output: Box<dyn PortOutput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: None,
            output: Some(output),
            terminal: None,
        }
    }

    pub fn input_pipe(
        name: impl Into<Cow<'static, str>>,
        input: Box<dyn PortInput + Send>,
    ) -> Self {
        Self {
            name: name.into(),
            input: Some(input),
            output: None,
            terminal: None,
        }
    }
}

enum PortQueue {
    Worker(JoinHandle<Queue>),
    Idle(Queue),
}

enum PortState {
    Inactive,
    Active {
        stopfd: utils::eventfd::EventFd,
        stop: Arc<AtomicBool>,
        rx: PortQueue,
        tx: PortQueue,
    },
}

pub(crate) struct Port {
    port_id: u32,
    /// Empty if no name given
    name: Cow<'static, str>,
    state: PortState,
    input: Option<Arc<Mutex<Box<dyn PortInput + Send>>>>,
    output: Option<Arc<Mutex<Box<dyn PortOutput + Send>>>>,
    terminal: Option<Box<dyn PortTerminalProperties>>,
}

impl Port {
    pub(crate) fn new(port_id: u32, description: PortDescription) -> Self {
        Self {
            port_id,
            name: description.name,
            state: PortState::Inactive,
            input: description.input.map(|input| Arc::new(Mutex::new(input))),
            output: description
                .output
                .map(|output| Arc::new(Mutex::new(output))),
            terminal: description.terminal,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn terminal(&self) -> Option<&dyn PortTerminalProperties> {
        self.terminal.as_deref()
    }

    pub fn notify_rx(&self) {
        if let PortState::Active {
            rx: PortQueue::Worker(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn notify_tx(&self) {
        if let PortState::Active {
            tx: PortQueue::Worker(handle),
            ..
        } = &self.state
        {
            handle.thread().unpark()
        }
    }

    pub fn start(
        &mut self,
        mem: GuestMemoryMmap,
        rx_queue: Queue,
        tx_queue: Queue,
        interrupt: InterruptTransport,
        control: Arc<ConsoleControl>,
    ) {
        if let PortState::Active { .. } = &mut self.state {
            self.shutdown();
        };

        let input = self.input.as_ref().cloned();
        let output = self.output.as_ref().cloned();

        let stopfd = utils::eventfd::EventFd::new(utils::eventfd::EFD_NONBLOCK)
            .expect("Failed to create EventFd for interrupt_evt");
        let stop = Arc::new(AtomicBool::new(false));

        let rx = if let Some(input) = input {
            let mem = mem.clone();
            let interrupt = interrupt.clone();
            let port_id = self.port_id;
            let stopfd = stopfd.try_clone().unwrap();
            let stop = stop.clone();
            PortQueue::Worker(
                thread::Builder::new()
                    .name("console port".into())
                    .spawn(move || {
                        process_rx(
                            mem, rx_queue, interrupt, input, control, port_id, stopfd, stop,
                        )
                    })
                    .unwrap(),
            )
        } else {
            PortQueue::Idle(rx_queue)
        };

        let tx = if let Some(output) = output {
            let stop = stop.clone();
            PortQueue::Worker(thread::spawn(move || {
                process_tx(mem, tx_queue, interrupt, output, stop)
            }))
        } else {
            PortQueue::Idle(tx_queue)
        };

        self.state = PortState::Active {
            stopfd,
            stop,
            rx,
            tx,
        }
    }

    pub fn quiesce(&mut self) -> std::io::Result<Option<(Queue, Queue)>> {
        let state = mem::replace(&mut self.state, PortState::Inactive);
        let PortState::Active {
            stopfd,
            stop,
            rx,
            tx,
        } = state
        else {
            return Ok(None);
        };
        stop.store(true, Ordering::Release);
        stopfd.write(1)?;
        if let PortQueue::Worker(thread) = &rx {
            thread.thread().unpark();
        }
        if let PortQueue::Worker(thread) = &tx {
            thread.thread().unpark();
        }
        let rx = match rx {
            PortQueue::Worker(thread) => thread
                .join()
                .map_err(|_| std::io::Error::other("console input worker panicked"))?,
            PortQueue::Idle(queue) => queue,
        };
        let tx = match tx {
            PortQueue::Worker(thread) => thread
                .join()
                .map_err(|_| std::io::Error::other("console output worker panicked"))?,
            PortQueue::Idle(queue) => queue,
        };
        Ok(Some((rx, tx)))
    }

    pub fn shutdown(&mut self) {
        if let Err(error) = self.quiesce() {
            log::error!("console shutdown failed: {error}");
        }
    }
}
