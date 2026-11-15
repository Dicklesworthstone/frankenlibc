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
    /// Submitter's scheduling priority minus aio_reqprio; larger runs first.
    pub(super) priority: c_int,
    /// fsync/fdatasync must wait for all earlier requests on this descriptor.
    pub(super) barrier: bool,
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
        // Keep the vector in admission order. Equal priorities remain FIFO,
        // but a more urgent request may pass queued I/O on the same fd until
        // a durability barrier. A running request can be anywhere in the
        // vector after priority selection, so inspect the whole descriptor.
        let mut best = None;
        for (index, entry) in self.pending.iter().enumerate() {
            if entry.state != State::Queued
                || self
                    .pending
                    .iter()
                    .any(|other| other.fd == entry.fd && other.state == State::Running)
                || self.pending[..index].iter().any(|earlier| {
                    earlier.fd == entry.fd
                        && earlier.state != State::Canceled
                        && (entry.barrier || earlier.barrier)
                })
            {
                continue;
            }
            if best.is_none_or(|previous: usize| entry.priority > self.pending[previous].priority) {
                best = Some(index);
            }
        }
        best
    }

    pub(super) fn needs_worker(&self) -> bool {
        let running = self
            .pending
            .iter()
            .filter(|p| p.state == State::Running)
            .count();
        let ready = self
            .pending
            .iter()
            .enumerate()
            .filter(|(index, entry)| {
                entry.state == State::Queued
                    && !self.pending[..*index]
                        .iter()
                        .any(|earlier| earlier.state == State::Queued && earlier.fd == entry.fd)
                    && !self
                        .pending
                        .iter()
                        .any(|other| other.state == State::Running && other.fd == entry.fd)
            })
            .count();
        self.workers < self.limit && ready > self.workers - running
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(fd: c_int, state: State) -> Pending<c_int> {
        Pending {
            request: fd,
            fd,
            state,
            priority: 0,
            barrier: false,
        }
    }

    fn prioritized(fd: c_int, priority: c_int, barrier: bool) -> Pending<c_int> {
        Pending {
            priority,
            barrier,
            ..pending(fd, State::Queued)
        }
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

    #[test]
    fn most_urgent_descriptor_runs_first_with_stable_ties() {
        let mut q = Queue::new();
        q.pending.push(prioritized(10, -20, false));
        q.pending.push(prioritized(11, 10, false));
        q.pending.push(prioritized(12, 10, false));
        q.pending.push(prioritized(13, 0, false));
        assert_eq!(q.runnable(), Some(1));
        q.pending.remove(1);
        assert_eq!(q.runnable(), Some(1));
        q.pending.remove(1);
        assert_eq!(q.runnable(), Some(1));
        q.pending.remove(1);
        assert_eq!(q.runnable(), Some(0));
    }

    #[test]
    fn queued_priority_can_pass_same_fd_but_never_its_running_request() {
        let mut q = Queue::new();
        q.workers = 1;
        q.pending.push(prioritized(10, -20, false));
        q.pending.push(prioritized(10, 0, false));
        q.pending.push(prioritized(10, -5, false));
        assert_eq!(q.runnable(), Some(1));
        q.pending[1].state = State::Running;
        assert_eq!(q.runnable(), None);
        assert!(!q.needs_worker());
        q.pending.remove(1);
        assert_eq!(q.runnable(), Some(1));
        q.pending.remove(1);
        assert_eq!(q.runnable(), Some(0));
    }

    #[test]
    fn durability_barrier_keeps_earlier_io_and_later_priority_in_separate_epochs() {
        let mut q = Queue::new();
        q.pending.push(prioritized(10, -20, false));
        q.pending.push(prioritized(10, 0, true));
        q.pending.push(prioritized(10, 90, false));
        q.pending.push(prioritized(10, 99, false));
        assert_eq!(q.runnable(), Some(0));
        q.pending.remove(0);
        assert_eq!(q.runnable(), Some(0));
        q.pending[0].state = State::Running;
        assert_eq!(q.runnable(), None);
        q.pending.remove(0);
        assert_eq!(q.runnable(), Some(1));
    }

    #[test]
    fn canceled_barrier_releases_priority_without_waiting_for_notification_drain() {
        let mut q = Queue::new();
        q.pending.push(prioritized(10, -20, false));
        q.pending.push(prioritized(10, 0, true));
        q.pending.push(prioritized(10, 10, false));
        assert_eq!(q.runnable(), Some(0));
        q.pending[1].state = State::Canceled;
        assert_eq!(q.runnable(), Some(2));
        q.pending[2].state = State::Canceled;
        assert_eq!(q.runnable(), Some(0));
    }

    #[test]
    fn unrelated_descriptor_can_progress_while_high_priority_fd_is_running() {
        let mut q = Queue::new();
        q.workers = 1;
        q.pending.push(prioritized(10, 50, false));
        q.pending.push(prioritized(11, -20, false));
        q.pending.push(prioritized(10, 60, false));
        assert_eq!(q.runnable(), Some(2));
        q.pending[2].state = State::Running;
        assert_eq!(q.runnable(), Some(1));
        assert!(q.needs_worker());
        q.workers = 2;
        assert!(!q.needs_worker());
    }

    #[test]
    fn queued_priority_backlog_counts_one_descriptor_of_worker_capacity() {
        let mut q = Queue::new();
        q.workers = 1;
        for priority in -20..=20 {
            q.pending.push(prioritized(10, priority, false));
        }
        assert_eq!(q.runnable(), Some(40));
        assert!(!q.needs_worker());
        q.pending.push(prioritized(11, -20, true));
        assert!(q.needs_worker());
    }
}
