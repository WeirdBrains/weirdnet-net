//! What a running node reports (W5): an [`Event`] stream and a [`Status`] watch, for apps
//! that show connectivity, and the lifecycle calls a mobile or desktop app makes
//! ([`Node::pause`], [`Node::resume`], [`Node::network_changed`]).
//!
//! [`Node::pause`]: crate::Node::pause
//! [`Node::resume`]: crate::Node::resume
//! [`Node::network_changed`]: crate::Node::network_changed
use crate::node::Status;
use crate::stream::Path;
use futures::StreamExt;
use futures::channel::mpsc;
use libp2p::{Multiaddr, PeerId};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Something that changed in the node.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// Listening on an address (a circuit through a relay included).
    Listening(Multiaddr),
    /// An address stopped being listened on.
    ListenClosed(Multiaddr),
    /// Others confirmed they reach us here (`true`), or no longer do (`false`).
    External {
        addr: Multiaddr,
        confirmed: bool,
    },
    /// A connection to `peer` came up.
    Connected {
        peer: PeerId,
        path: Path,
    },
    /// A connection to `peer` went away; `remaining` are still open.
    Disconnected {
        peer: PeerId,
        path: Path,
        remaining: u32,
    },
    /// A relay holds a reservation for us.
    Reserved {
        relay: PeerId,
    },
    /// A relay's reservation is gone (the node asks again while it isn't paused).
    ReservationLost {
        relay: PeerId,
    },
    /// AutoNAT's verdict: `public`, `private` or `unknown`.
    Nat(String),
    Paused,
    Resumed,
    NetworkChanged,
}

/// Where the loop sends events: every live [`Events`] gets each one.
#[derive(Clone, Default)]
pub(crate) struct Hub {
    subs: Arc<Mutex<Vec<mpsc::UnboundedSender<Event>>>>,
}

impl Hub {
    pub(crate) fn send(&self, e: Event) {
        if let Ok(mut s) = self.subs.lock() {
            s.retain(|t| t.unbounded_send(e.clone()).is_ok());
        }
    }

    pub(crate) fn subscribe(&self) -> Events {
        let (tx, rx) = mpsc::unbounded();
        if let Ok(mut s) = self.subs.lock() {
            s.push(tx);
        }
        Events { rx }
    }
}

/// The node's events from when this was made on, as a `futures` stream or by blocking.
pub struct Events {
    rx: mpsc::UnboundedReceiver<Event>,
}

impl Events {
    /// The next event, waiting at most `d` (`None`: none in time, or the node stopped).
    pub fn next_timeout(&mut self, d: Duration) -> Option<Event> {
        let end = Instant::now() + d;
        loop {
            match self.rx.try_recv() {
                Ok(e) => return Some(e),
                Err(mpsc::TryRecvError::Closed) => return None,
                Err(mpsc::TryRecvError::Empty) if Instant::now() >= end => return None,
                Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }

    /// Wait (at most `d`) for an event `f` picks.
    pub fn wait_for(&mut self, d: Duration, mut f: impl FnMut(&Event) -> bool) -> Option<Event> {
        let end = Instant::now() + d;
        while let Some(e) = self.next_timeout(end.saturating_duration_since(Instant::now())) {
            if f(&e) {
                return Some(e);
            }
        }
        None
    }
}

impl futures::Stream for Events {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Event>> {
        self.rx.poll_next_unpin(cx)
    }
}

/// The latest [`Status`], with a way to wait for the next change.
#[derive(Clone)]
pub struct StatusWatch {
    pub(crate) rx: tokio::sync::watch::Receiver<Status>,
}

impl StatusWatch {
    pub fn get(&self) -> Status {
        self.rx.borrow().clone()
    }

    /// Wait for the status to change (any executor); `None` once the node has stopped.
    pub async fn changed(&mut self) -> Option<Status> {
        self.rx.changed().await.ok()?;
        Some(self.rx.borrow_and_update().clone())
    }

    /// Block until the status changes, at most `d`.
    pub fn wait_change(&mut self, d: Duration) -> Option<Status> {
        let end = Instant::now() + d;
        loop {
            if self.rx.has_changed().ok()? {
                return Some(self.rx.borrow_and_update().clone());
            }
            if Instant::now() >= end {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
