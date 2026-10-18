//! AIO admission and descriptor scheduling, independent of ABI interposition.
//!
//! The live worker engine and the integration test compile this same module.
//! An entry owns its payload; descriptor/state metadata can be inspected
//! without dereferencing a caller's control block or buffer.

use std::ffi::c_int;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum State {
    Queued,
    Running,
    Canceled,
}

pub(super) struct Pending<T> {
    pub(super) request: T,
    pub(super) fd: c_int,
    pub(super) state: State,
}

pub(super) struct Queue<T> {
    pub(super) pending: Vec<Pending<T>>,
    // Includes workers whose creation has been reserved by a submitter.
    pub(super) workers: usize,
    pub(super) limit: usize,
    pub(super) expected: usize,
    pub(super) idle: Duration,
    pub(super) started: bool,
}

impl<T> Queue<T> {
    pub(super) const fn new() -> Self {
        Self {
            pending: Vec::new(),
            workers: 0,
            limit: 20,
            expected: 64,
            idle: Duration::from_secs(1),
            started: false,
        }
    }

    pub(super) fn runnable(&self) -> Option<usize> {
        self.pending.iter().enumerate().find_map(|(index, entry)| {
            (entry.state == State::Queued
                && !self.pending[..index].iter().any(|earlier| {
                    earlier.state != State::Canceled && earlier.fd == entry.fd
                }))
            .then_some(index)
        })
    }

    pub(super) fn needs_worker(&self) -> bool {
        let running = self.pending.iter().filter(|p| p.state == State::Running).count();
        let ready = self.pending.iter().enumerate().filter(|(index, entry)| {
            entry.state == State::Queued
                && !self.pending[..*index].iter().any(|earlier| {
                    earlier.state != State::Canceled && earlier.fd == entry.fd
                })
        }).count();
        self.workers < self.limit && ready > self.workers - running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(fd: c_int, state: State) -> Pending<c_int> {
        Pending { request: fd, fd, state }
    }

    #[test]
    fn empty_pool_has_gnu_defaults_and_needs_no_worker() {
        let q = Queue::<c_int>::new();
        assert_eq!(q.runnable(), None);
        assert!(!q.needs_worker());
        assert_eq!(q.limit, 20);
        assert_eq!(q.expected, 64);
        assert_eq!(q.idle, Duration::from_secs(1));
        assert!(!q.started);
    }

    #[test]
    fn startup_reservations_do_not_starve_other_descriptors() {
        let mut q = Queue::new();
        q.workers = 1; // reserved but not yet scheduled by the kernel
        q.pending.push(pending(10, State::Queued));
        assert!(!q.needs_worker());
        q.pending.push(pending(11, State::Queued));
        assert!(q.needs_worker());
    }

    #[test]
    fn same_descriptor_backlog_does_not_allocate_workers() {
        let mut q = Queue::new();
        q.workers = 1;
        q.pending.push(pending(10, State::Running));
        for _ in 0..1024 {
            q.pending.push(pending(10, State::Queued));
        }
        assert_eq!(q.runnable(), None);
        assert!(!q.needs_worker());
        q.pending.push(pending(11, State::Queued));
        assert_eq!(q.runnable(), Some(1025));
        assert!(q.needs_worker());
    }

    #[test]
    fn cap_and_idle_capacity_are_both_respected() {
        let mut q = Queue::new();
        q.limit = 1;
        q.workers = 1;
        q.pending.push(pending(10, State::Running));
        q.pending.push(pending(11, State::Queued));
        assert!(!q.needs_worker());
        q.limit = 2;
        assert!(q.needs_worker());
        q.workers = 2;
        assert!(!q.needs_worker());
    }

    #[test]
    fn canceled_snapshot_does_not_block_descriptor_reuse() {
        let mut q = Queue::new();
        q.pending.push(pending(10, State::Canceled));
        q.pending.push(pending(10, State::Queued));
        assert_eq!(q.runnable(), Some(1));
        assert!(q.needs_worker());
        assert_eq!(q.pending.remove(0).request, 10);
        assert_eq!(q.runnable(), Some(0));
    }

    #[test]
    fn queued_fd_order_survives_independent_progress() {
        let mut q = Queue::new();
        q.workers = 1;
        q.pending.push(pending(10, State::Running));
        q.pending.push(pending(10, State::Queued));
        q.pending.push(pending(11, State::Queued));
        q.pending.push(pending(10, State::Queued));
        assert_eq!(q.runnable(), Some(2));
        q.pending.remove(0); // completion of the first fd 10 request
        assert_eq!(q.runnable(), Some(0));
        q.pending[0].state = State::Running;
        assert_eq!(q.runnable(), Some(1));
        assert!(q.needs_worker());
    }
}
