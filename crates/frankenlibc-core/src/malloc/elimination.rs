//! Elimination backoff for allocator free-list handoff.
//!
//! Complementary operations can exchange a pointer directly through a bounded
//! slot array instead of touching the shared central bins.  This keeps the
//! implementation in safe Rust while still giving the allocator a low-contention
//! handoff path for small objects.

use std::array;
use std::cell::Cell;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, WaitTimeoutResult};
use std::time::{Duration, Instant};

pub const DEFAULT_ELIMINATION_SLOTS: usize = 8;

const DEFAULT_WAIT_BUDGET: Duration = Duration::from_micros(100);
const ADAPTIVE_WINDOW: u64 = 1_000;
const ADAPTIVE_DISABLE_WINDOW: u64 = 1_000;
const SUCCESS_THRESHOLD_PPM: u64 = 100_000;
const SUMMARY_INTERVAL: u64 = 5_000;

thread_local! {
    static SLOT_HINT: Cell<usize> = const { Cell::new(0) };
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EliminationOp {
    Publish,
    Push,
    Pop,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EliminationOutcome {
    Matched,
    Parked,
    Timeout,
    Empty,
    Collision,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EliminationSlotStats {
    pub publishes: u64,
    pub matches: u64,
    pub collisions: u64,
    pub timeouts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EliminationStats {
    pub attempts: u64,
    pub successes: u64,
    pub success_rate_ppm: u32,
    pub enabled: bool,
    pub disabled_remaining: u64,
    pub disabled_skips: u64,
    pub published_slots: usize,
    pub slots: Vec<EliminationSlotStats>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EliminationExchangeMeta {
    pub slot_index: Option<usize>,
    pub wait_cycles: u64,
    pub partner_thread: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferOutcome<T> {
    Matched(EliminationExchangeMeta),
    Fallback {
        value: T,
        meta: EliminationExchangeMeta,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakeOutcome<T> {
    Matched {
        value: T,
        meta: EliminationExchangeMeta,
    },
    Fallback {
        meta: EliminationExchangeMeta,
    },
}

enum SlotState<T> {
    Empty,
    Offered {
        offer_id: u64,
        producer_thread: u64,
        wait_for_match: bool,
        value: T,
    },
    Taken {
        consumer_thread: u64,
    },
}

struct Slot<T> {
    state: Mutex<SlotState<T>>,
    condvar: Condvar,
    publishes: AtomicU64,
    matches: AtomicU64,
    collisions: AtomicU64,
    timeouts: AtomicU64,
}

impl<T> Slot<T> {
    fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::Empty),
            condvar: Condvar::new(),
            publishes: AtomicU64::new(0),
            matches: AtomicU64::new(0),
            collisions: AtomicU64::new(0),
            timeouts: AtomicU64::new(0),
        }
    }
}

#[derive(Debug, Default)]
struct AdaptiveController {
    observed: u64,
    attempts: u64,
    successes: u64,
    window_attempts: u64,
    window_successes: u64,
    disabled_skips: u64,
    disabled_remaining: u64,
}

#[derive(Debug, Clone, Copy)]
struct AttemptGate {
    allowed: bool,
    should_log_summary: bool,
}

impl AdaptiveController {
    fn begin(&mut self) -> AttemptGate {
        self.observed = self.observed.saturating_add(1);
        let should_log_summary = self.observed.is_multiple_of(SUMMARY_INTERVAL);

        if self.disabled_remaining > 0 {
            self.disabled_remaining -= 1;
            self.disabled_skips = self.disabled_skips.saturating_add(1);
            return AttemptGate {
                allowed: false,
                should_log_summary,
            };
        }

        AttemptGate {
            allowed: true,
            should_log_summary,
        }
    }

    fn finish(&mut self, success: bool) -> bool {
        self.attempts = self.attempts.saturating_add(1);
        self.window_attempts = self.window_attempts.saturating_add(1);

        if success {
            self.successes = self.successes.saturating_add(1);
            self.window_successes = self.window_successes.saturating_add(1);
        }

        if self.window_attempts >= ADAPTIVE_WINDOW {
            let rate_ppm = self
                .window_successes
                .saturating_mul(1_000_000)
                .checked_div(self.window_attempts)
                .unwrap_or(0);
            if rate_ppm < SUCCESS_THRESHOLD_PPM {
                self.disabled_remaining = ADAPTIVE_DISABLE_WINDOW;
            }
            self.window_attempts = 0;
            self.window_successes = 0;
        }

        self.observed.is_multiple_of(SUMMARY_INTERVAL)
    }

    fn success_rate_ppm(&self) -> u32 {
        if self.attempts == 0 {
            return 0;
        }
        ((self.successes.saturating_mul(1_000_000)) / self.attempts) as u32
    }
}

pub struct EliminationArray<T, const SLOTS: usize> {
    slots: [Slot<T>; SLOTS],
    offer_sequence: AtomicU64,
    wait_budget: Duration,
    controller: Mutex<AdaptiveController>,
}

impl<T: Send, const SLOTS: usize> EliminationArray<T, SLOTS> {
    #[must_use]
    pub fn new() -> Self {
        Self::with_wait_budget(DEFAULT_WAIT_BUDGET)
    }

    #[must_use]
    pub fn with_wait_budget(wait_budget: Duration) -> Self {
        assert!(SLOTS > 0, "elimination array requires at least one slot");
        Self {
            slots: array::from_fn(|_| Slot::new()),
            offer_sequence: AtomicU64::new(1),
            wait_budget,
            controller: Mutex::new(AdaptiveController::default()),
        }
    }

    #[allow(dead_code)]
    pub fn publish(&self, value: T) -> Result<(), T> {
        let gate = self.begin_attempt();
        if !gate.allowed {
            self.record_skip(gate.should_log_summary);
            self.log_event(
                EliminationOp::Publish,
                EliminationOutcome::Disabled,
                0,
                current_thread_tag(),
                0,
            );
            return Err(value);
        }

        let offer_id = self.next_offer_id();
        let producer_thread = current_thread_tag();
        let mut value = Some(value);
        let base = slot_hint::<SLOTS>();

        for step in 0..SLOTS {
            let slot_index = (base + step) % SLOTS;
            let slot = &self.slots[slot_index];
            let mut state = lock_no_poison(&slot.state);

            if matches!(*state, SlotState::Empty) {
                slot.publishes.fetch_add(1, Ordering::Relaxed);
                *state = SlotState::Offered {
                    offer_id,
                    producer_thread,
                    wait_for_match: false,
                    value: value.take().expect("publish must have a value"),
                };
                drop(state);
                remember_next_slot::<SLOTS>(slot_index + 1);
                self.record_attempt(true, gate.should_log_summary);
                self.log_event(
                    EliminationOp::Publish,
                    EliminationOutcome::Parked,
                    slot_index,
                    producer_thread,
                    (step + 1) as u64,
                );
                return Ok(());
            }

            slot.collisions.fetch_add(1, Ordering::Relaxed);
            remember_next_slot::<SLOTS>(slot_index + 1);
        }

        self.record_attempt(false, gate.should_log_summary);
        self.log_event(
            EliminationOp::Publish,
            EliminationOutcome::Collision,
            base,
            producer_thread,
            SLOTS as u64,
        );
        Err(value.expect("publish collision must return the original value"))
    }

    pub fn offer(&self, value: T) -> Result<(), T> {
        let gate = self.begin_attempt();
        if !gate.allowed {
            self.record_skip(gate.should_log_summary);
            self.log_event(
                EliminationOp::Push,
                EliminationOutcome::Disabled,
                0,
                current_thread_tag(),
                0,
            );
            return Err(value);
        }

        let offer_id = self.next_offer_id();
        let producer_thread = current_thread_tag();
        let mut value = Some(value);
        let base = slot_hint::<SLOTS>();

        for step in 0..SLOTS {
            let slot_index = (base + step) % SLOTS;
            let slot = &self.slots[slot_index];
            let mut state = lock_no_poison(&slot.state);

            if matches!(*state, SlotState::Empty) {
                slot.publishes.fetch_add(1, Ordering::Relaxed);
                *state = SlotState::Offered {
                    offer_id,
                    producer_thread,
                    wait_for_match: true,
                    value: value.take().expect("offer must have a value"),
                };

                let (mut state, _) =
                    wait_timeout_no_poison(&slot.condvar, state, self.wait_budget, |state| {
                        matches!(
                            state,
                            SlotState::Offered {
                                offer_id: current_offer,
                                wait_for_match: true,
                                ..
                            } if *current_offer == offer_id
                        )
                    });

                let outcome = std::mem::replace(&mut *state, SlotState::Empty);
                drop(state);
                remember_next_slot::<SLOTS>(slot_index + 1);

                match outcome {
                    SlotState::Taken { .. } => {
                        self.record_attempt(true, gate.should_log_summary);
                        self.log_event(
                            EliminationOp::Push,
                            EliminationOutcome::Matched,
                            slot_index,
                            producer_thread,
                            (step + 1) as u64,
                        );
                        return Ok(());
                    }
                    SlotState::Offered {
                        offer_id: current_offer,
                        value,
                        ..
                    } if current_offer == offer_id => {
                        slot.timeouts.fetch_add(1, Ordering::Relaxed);
                        self.record_attempt(false, gate.should_log_summary);
                        self.log_event(
                            EliminationOp::Push,
                            EliminationOutcome::Timeout,
                            slot_index,
                            producer_thread,
                            (step + 1) as u64,
                        );
                        return Err(value);
                    }
                    SlotState::Empty => {
                        self.record_attempt(true, gate.should_log_summary);
                        self.log_event(
                            EliminationOp::Push,
                            EliminationOutcome::Matched,
                            slot_index,
                            producer_thread,
                            (step + 1) as u64,
                        );
                        return Ok(());
                    }
                    other => {
                        if let SlotState::Offered { value, .. } = other {
                            self.record_attempt(false, gate.should_log_summary);
                            self.log_event(
                                EliminationOp::Push,
                                EliminationOutcome::Collision,
                                slot_index,
                                producer_thread,
                                (step + 1) as u64,
                            );
                            return Err(value);
                        }
                    }
                }
            }

            slot.collisions.fetch_add(1, Ordering::Relaxed);
            remember_next_slot::<SLOTS>(slot_index + 1);
        }

        self.record_attempt(false, gate.should_log_summary);
        self.log_event(
            EliminationOp::Push,
            EliminationOutcome::Collision,
            base,
            producer_thread,
            SLOTS as u64,
        );
        Err(value.expect("offer collision must return the original value"))
    }

    pub fn try_offer(&self, _slot_bias: usize, value: T) -> OfferOutcome<T> {
        match self.offer(value) {
            Ok(()) => OfferOutcome::Matched(EliminationExchangeMeta::default()),
            Err(value) => OfferOutcome::Fallback {
                value,
                meta: EliminationExchangeMeta::default(),
            },
        }
    }

    #[must_use]
    #[allow(dead_code)]
    pub fn pop(&self) -> Option<T> {
        let gate = self.begin_attempt();
        let consumer_thread = current_thread_tag();

        if !gate.allowed {
            self.record_skip(gate.should_log_summary);
            self.log_event(
                EliminationOp::Pop,
                EliminationOutcome::Disabled,
                0,
                consumer_thread,
                0,
            );
            return None;
        }

        let base = slot_hint::<SLOTS>();

        for step in 0..SLOTS {
            let slot_index = (base + step) % SLOTS;
            let slot = &self.slots[slot_index];
            let mut state = lock_no_poison(&slot.state);

            let replaced = std::mem::replace(&mut *state, SlotState::Empty);
            match replaced {
                SlotState::Offered {
                    producer_thread,
                    wait_for_match,
                    value,
                    ..
                } => {
                    slot.matches.fetch_add(1, Ordering::Relaxed);
                    if wait_for_match {
                        *state = SlotState::Taken { consumer_thread };
                        slot.condvar.notify_all();
                    }
                    drop(state);
                    remember_next_slot::<SLOTS>(slot_index + 1);
                    self.record_attempt(true, gate.should_log_summary);
                    self.log_event(
                        EliminationOp::Pop,
                        EliminationOutcome::Matched,
                        slot_index,
                        producer_thread,
                        (step + 1) as u64,
                    );
                    return Some(value);
                }
                SlotState::Empty => {
                    *state = SlotState::Empty;
                }
                SlotState::Taken { consumer_thread } => {
                    *state = SlotState::Taken { consumer_thread };
                }
            }

            slot.collisions.fetch_add(1, Ordering::Relaxed);
            remember_next_slot::<SLOTS>(slot_index + 1);
        }

        self.record_attempt(false, gate.should_log_summary);
        self.log_event(
            EliminationOp::Pop,
            EliminationOutcome::Empty,
            base,
            consumer_thread,
            SLOTS as u64,
        );
        None
    }

    pub fn try_take(&self, slot_bias: usize) -> TakeOutcome<T> {
        let gate = self.begin_attempt();
        let consumer_thread = current_thread_tag();

        if !gate.allowed {
            self.record_skip(gate.should_log_summary);
            self.log_event(
                EliminationOp::Pop,
                EliminationOutcome::Disabled,
                0,
                consumer_thread,
                0,
            );
            return TakeOutcome::Fallback {
                meta: EliminationExchangeMeta::default(),
            };
        }

        let deadline = Instant::now() + self.wait_budget;
        let base = slot_base::<SLOTS>(slot_bias);
        let mut wait_cycles = 0u64;

        loop {
            for step in 0..SLOTS {
                let slot_index = (base + step) % SLOTS;
                let slot = &self.slots[slot_index];
                let mut state = lock_no_poison(&slot.state);

                let replaced = std::mem::replace(&mut *state, SlotState::Empty);
                match replaced {
                    SlotState::Offered {
                        producer_thread,
                        wait_for_match,
                        value,
                        ..
                    } => {
                        slot.matches.fetch_add(1, Ordering::Relaxed);
                        if wait_for_match {
                            *state = SlotState::Taken { consumer_thread };
                            slot.condvar.notify_all();
                        }
                        drop(state);
                        remember_next_slot::<SLOTS>(slot_index + 1);
                        let meta = EliminationExchangeMeta {
                            slot_index: Some(slot_index),
                            wait_cycles: wait_cycles + (step + 1) as u64,
                            partner_thread: Some(producer_thread),
                        };
                        self.record_attempt(true, gate.should_log_summary);
                        self.log_event(
                            EliminationOp::Pop,
                            EliminationOutcome::Matched,
                            slot_index,
                            producer_thread,
                            meta.wait_cycles,
                        );
                        return TakeOutcome::Matched { value, meta };
                    }
                    SlotState::Empty => {
                        *state = SlotState::Empty;
                    }
                    SlotState::Taken { consumer_thread } => {
                        *state = SlotState::Taken { consumer_thread };
                    }
                }

                slot.collisions.fetch_add(1, Ordering::Relaxed);
                remember_next_slot::<SLOTS>(slot_index + 1);
            }

            wait_cycles = wait_cycles.saturating_add(SLOTS as u64);
            if Instant::now() >= deadline {
                self.record_attempt(false, gate.should_log_summary);
                self.log_event(
                    EliminationOp::Pop,
                    EliminationOutcome::Timeout,
                    base,
                    consumer_thread,
                    wait_cycles,
                );
                return TakeOutcome::Fallback {
                    meta: EliminationExchangeMeta {
                        slot_index: None,
                        wait_cycles,
                        partner_thread: None,
                    },
                };
            }

            std::thread::yield_now();
        }
    }

    #[must_use]
    pub fn stats(&self) -> EliminationStats {
        let controller = lock_no_poison(&self.controller);
        let mut slots = Vec::with_capacity(SLOTS);
        let mut published_slots = 0usize;

        for slot in &self.slots {
            let state = lock_no_poison(&slot.state);
            if matches!(*state, SlotState::Offered { .. } | SlotState::Taken { .. }) {
                published_slots += 1;
            }
            drop(state);
            slots.push(EliminationSlotStats {
                publishes: slot.publishes.load(Ordering::Relaxed),
                matches: slot.matches.load(Ordering::Relaxed),
                collisions: slot.collisions.load(Ordering::Relaxed),
                timeouts: slot.timeouts.load(Ordering::Relaxed),
            });
        }

        EliminationStats {
            attempts: controller.attempts,
            successes: controller.successes,
            success_rate_ppm: controller.success_rate_ppm(),
            enabled: controller.disabled_remaining == 0,
            disabled_remaining: controller.disabled_remaining,
            disabled_skips: controller.disabled_skips,
            published_slots,
            slots,
        }
    }

    fn begin_attempt(&self) -> AttemptGate {
        lock_no_poison(&self.controller).begin()
    }

    fn record_attempt(&self, success: bool, force_summary: bool) {
        let should_log = {
            let mut controller = lock_no_poison(&self.controller);
            controller.finish(success) || force_summary
        };
        if should_log {
            self.log_summary();
        }
    }

    fn record_skip(&self, force_summary: bool) {
        if force_summary {
            self.log_summary();
        }
    }

    fn next_offer_id(&self) -> u64 {
        self.offer_sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn log_event(
        &self,
        op: EliminationOp,
        outcome: EliminationOutcome,
        slot_index: usize,
        partner_thread: u64,
        wait_cycles: u64,
    ) {
        let op_type = match op {
            EliminationOp::Publish => "publish",
            EliminationOp::Push => "push",
            EliminationOp::Pop => "pop",
        };
        let outcome = match outcome {
            EliminationOutcome::Matched => "matched",
            EliminationOutcome::Parked => "parked",
            EliminationOutcome::Timeout => "timeout",
            EliminationOutcome::Empty => "empty",
            EliminationOutcome::Collision => "collision",
            EliminationOutcome::Disabled => "disabled",
        };
        let trace_id = format!(
            "elimination::{op_type}::{slot_index}::{:016x}",
            current_thread_tag()
        );
        tracing::trace!(
            target: "elimination",
            trace_id = %trace_id,
            mode = "shared",
            api_family = "malloc",
            symbol = "allocator_elimination",
            decision_path = "core::malloc::elimination",
            healing_action = "none",
            errno = 0,
            latency_ns = self.wait_budget.as_nanos() as u64,
            artifact_refs = "crates/frankenlibc-core/src/malloc/elimination.rs",
            slot_index,
            op_type,
            outcome,
            partner_thread,
            wait_cycles,
        );
    }

    fn log_summary(&self) {
        let stats = self.stats();
        let per_slot_utilization = stats
            .slots
            .iter()
            .map(|slot| format!("{}/{}", slot.matches, slot.publishes))
            .collect::<Vec<_>>()
            .join(",");

        tracing::info!(
            target: "elimination",
            trace_id = "elimination::summary",
            mode = "shared",
            api_family = "malloc",
            symbol = "allocator_elimination",
            decision_path = "core::malloc::elimination::summary",
            healing_action = "none",
            errno = 0,
            latency_ns = 0u64,
            artifact_refs = "crates/frankenlibc-core/src/malloc/elimination.rs",
            elimination_success_rate_ppm = stats.success_rate_ppm,
            published_slots = stats.published_slots,
            disabled_remaining = stats.disabled_remaining,
            adaptive_state = if stats.enabled { "enabled" } else { "disabled" },
            per_slot_utilization = %per_slot_utilization,
        );
    }
}

impl<T: Send, const SLOTS: usize> Default for EliminationArray<T, SLOTS> {
    fn default() -> Self {
        Self::new()
    }
}

fn lock_no_poison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_timeout_no_poison<'a, T, F>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
    condition: F,
) -> (MutexGuard<'a, T>, WaitTimeoutResult)
where
    F: FnMut(&mut T) -> bool,
{
    condvar
        .wait_timeout_while(guard, timeout, condition)
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn current_thread_tag() -> u64 {
    let mut hasher = DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish()
}

fn slot_hint<const SLOTS: usize>() -> usize {
    SLOT_HINT.with(|hint| hint.get() % SLOTS)
}

fn remember_next_slot<const SLOTS: usize>(next: usize) {
    SLOT_HINT.with(|hint| hint.set(next % SLOTS));
}

fn slot_base<const SLOTS: usize>(bias: usize) -> usize {
    (slot_hint::<SLOTS>() + bias) % SLOTS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn publish_then_pop_claims_parked_value() {
        let array = EliminationArray::<usize, 4>::new();
        array.publish(0xCAFE).expect("publish should succeed");
        assert_eq!(array.pop(), Some(0xCAFE));

        let stats = array.stats();
        assert!(stats.successes >= 2, "publish + pop should both succeed");
        assert_eq!(stats.published_slots, 0);
    }

    #[test]
    fn offer_matches_pop_across_threads() {
        let array = Arc::new(EliminationArray::<usize, 4>::with_wait_budget(
            Duration::from_millis(5),
        ));
        let producer = Arc::clone(&array);

        let handle = std::thread::spawn(move || producer.offer(0xDEAD_BEEF));
        std::thread::sleep(Duration::from_millis(1));

        let mut observed = None;
        for _ in 0..64 {
            if let Some(value) = array.pop() {
                observed = Some(value);
                break;
            }
            std::thread::yield_now();
        }

        assert_eq!(observed, Some(0xDEAD_BEEF));
        assert!(handle.join().expect("producer joins").is_ok());

        let stats = array.stats();
        assert!(
            stats.success_rate_ppm >= 500_000,
            "expected direct exchange to succeed often enough: {stats:?}"
        );
    }

    #[test]
    fn adaptive_disable_after_one_sided_pop_pressure() {
        let array = EliminationArray::<usize, 2>::new();
        for _ in 0..ADAPTIVE_WINDOW {
            assert!(array.pop().is_none());
        }

        let stats = array.stats();
        assert!(
            !stats.enabled,
            "one-sided empty pop pressure should disable elimination: {stats:?}"
        );
        assert!(stats.disabled_remaining > 0);
    }

    #[test]
    fn symmetric_workload_exceeds_target_success_rate() {
        let array = Arc::new(EliminationArray::<usize, 8>::with_wait_budget(
            Duration::from_millis(2),
        ));
        let ready = Arc::new(Barrier::new(5));
        let rounds = 200usize;
        let mut handles = Vec::new();

        for producer_id in 0..4usize {
            let array = Arc::clone(&array);
            let ready = Arc::clone(&ready);
            handles.push(std::thread::spawn(move || {
                ready.wait();
                for round in 0..rounds {
                    let value = producer_id * 10_000 + round;
                    let mut pending = value;
                    loop {
                        match array.offer(pending) {
                            Ok(()) => break,
                            Err(value) => {
                                pending = value;
                                std::thread::yield_now();
                            }
                        }
                    }
                }
            }));
        }

        ready.wait();
        std::thread::sleep(Duration::from_millis(1));

        for _ in 0..4usize {
            let array = Arc::clone(&array);
            handles.push(std::thread::spawn(move || {
                let mut claimed = 0usize;
                while claimed < rounds {
                    if array.pop().is_some() {
                        claimed += 1;
                    } else {
                        std::thread::yield_now();
                    }
                }
            }));
        }

        for handle in handles {
            handle.join().expect("worker joins");
        }

        let stats = array.stats();
        assert!(
            stats.success_rate_ppm >= 300_000,
            "expected symmetric workload success rate above 30%: {stats:?}"
        );
    }

    #[test]
    fn repeated_exchange_cycles_leave_no_parked_slots() {
        let array = Arc::new(EliminationArray::<usize, 4>::with_wait_budget(
            Duration::from_millis(2),
        ));
        let producer = Arc::clone(&array);
        let consumer = Arc::clone(&array);

        let producer_handle = std::thread::spawn(move || {
            for round in 0..10_000usize {
                let mut pending = round;
                loop {
                    match producer.offer(pending) {
                        Ok(()) => break,
                        Err(value) => {
                            pending = value;
                            std::thread::yield_now();
                        }
                    }
                }
            }
        });

        let consumer_handle = std::thread::spawn(move || {
            let mut claimed = 0usize;
            while claimed < 10_000 {
                if consumer.pop().is_some() {
                    claimed += 1;
                } else {
                    std::thread::yield_now();
                }
            }
        });

        producer_handle.join().expect("producer joins");
        consumer_handle.join().expect("consumer joins");

        let stats = array.stats();
        assert_eq!(stats.published_slots, 0, "all slots should drain cleanly");
        assert!(
            stats.successes >= 20_000,
            "10K offer/pop cycles should succeed on both sides: {stats:?}"
        );
    }
}
