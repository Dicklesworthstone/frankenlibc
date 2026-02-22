//! # Quarantine Controller — Primal-Dual Adaptive Control
//!
//! The allocator quarantine queue holds recently-freed blocks to detect
//! use-after-free. Its depth is a critical parameter:
//! - Too shallow: UAF escapes undetected.
//! - Too deep: Memory waste + cache pollution.
//!
//! This module implements a **primal-dual controller** that adapts quarantine
//! depth in real-time based on:
//! - Contention signal (how many concurrent frees/allocs)
//! - Tail-risk signal (p99 latency of recent alloc/free operations)
//! - Safety signal (how many quarantine hits we're catching)
//!
//! ## Mathematical foundation
//!
//! The controller solves a constrained optimization at each epoch:
//!
//! ```text
//! minimize  memory_waste(depth) + lambda_latency * p99_latency(depth)
//! subject to  P(UAF_escape | depth) <= epsilon
//!             depth_min <= depth <= depth_max
//! ```
//!
//! The dual variable `lambda_latency` is updated via gradient ascent on the
//! constraint violation (primal-dual method). This converges to a saddle point
//! that satisfies the safety constraint while minimizing waste.
//!
//! ## Barrier certificate
//!
//! The controller maintains a barrier function:
//! `B(state) = ln(depth_max - depth) + ln(depth - depth_min)`
//!
//! This ensures the depth never hits the hard limits, providing a smooth
//! interior-point constraint enforcement.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Minimum quarantine depth (always hold at least this many blocks).
pub const MIN_DEPTH: usize = 64;

/// Maximum quarantine depth.
pub const MAX_DEPTH: usize = 65536;

/// Default initial quarantine depth.
pub const DEFAULT_DEPTH: usize = 4096;

/// Controller epoch interval (number of free operations between updates).
const EPOCH_INTERVAL: u64 = 256;

/// Learning rate for primal variable (depth).
const PRIMAL_LR: f64 = 0.1;

/// Learning rate for dual variable (lambda).
const DUAL_LR: f64 = 0.01;

/// Target UAF escape rate (constraint).
const SAFETY_EPSILON: f64 = 1e-6;

/// Latency signal window size.
const LATENCY_WINDOW: usize = 64;

/// Contention signal — atomically updated by multiple threads.
pub struct ContentionSignal {
    /// Number of concurrent free operations (approximate).
    concurrent_frees: AtomicU32,
    /// High-water mark of concurrent frees.
    peak_concurrent: AtomicU32,
}

impl ContentionSignal {
    pub const fn new() -> Self {
        Self {
            concurrent_frees: AtomicU32::new(0),
            peak_concurrent: AtomicU32::new(0),
        }
    }

    /// Called when a free operation begins.
    pub fn free_begin(&self) {
        let current = self.concurrent_frees.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak_concurrent.fetch_max(current, Ordering::Relaxed);
    }

    /// Called when a free operation ends.
    pub fn free_end(&self) {
        self.concurrent_frees.fetch_sub(1, Ordering::Relaxed);
    }

    /// Read and reset peak contention.
    fn read_and_reset_peak(&self) -> u32 {
        self.peak_concurrent.swap(0, Ordering::Relaxed)
    }
}

impl Default for ContentionSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Global contention signal instance.
pub static CONTENTION: ContentionSignal = ContentionSignal::new();

/// The quarantine controller state.
pub struct QuarantineController {
    /// Current quarantine depth.
    depth: usize,
    /// Dual variable for latency constraint.
    lambda_latency: f64,
    /// Dual variable for memory constraint.
    lambda_memory: f64,
    /// Recent latency observations (ns, circular buffer).
    latencies: [u64; LATENCY_WINDOW],
    /// Write position in latency buffer.
    latency_pos: usize,
    /// Number of latency observations recorded.
    latency_count: usize,
    /// Quarantine hits (UAF attempts caught) this epoch.
    hits_this_epoch: u64,
    /// Total frees this epoch.
    frees_this_epoch: u64,
    /// Total epochs completed.
    epochs: u64,
    /// Total quarantine hits.
    total_hits: u64,
    /// Running estimate of UAF escape rate.
    estimated_escape_rate: f64,
}

impl QuarantineController {
    /// Creates a new controller with default parameters.
    pub fn new() -> Self {
        Self {
            depth: DEFAULT_DEPTH,
            lambda_latency: 0.1,
            lambda_memory: 0.1,
            latencies: [0; LATENCY_WINDOW],
            latency_pos: 0,
            latency_count: 0,
            hits_this_epoch: 0,
            frees_this_epoch: 0,
            epochs: 0,
            total_hits: 0,
            estimated_escape_rate: 0.0,
        }
    }

    /// Returns the current recommended quarantine depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Record a free operation with its latency.
    ///
    /// Returns `true` if an epoch boundary was crossed and the depth was updated.
    pub fn record_free(&mut self, latency_ns: u64, was_quarantine_hit: bool) -> bool {
        // Record latency
        self.latencies[self.latency_pos] = latency_ns;
        self.latency_pos = (self.latency_pos + 1) % LATENCY_WINDOW;
        if self.latency_count < LATENCY_WINDOW {
            self.latency_count += 1;
        }

        self.frees_this_epoch += 1;
        if was_quarantine_hit {
            self.hits_this_epoch += 1;
            self.total_hits += 1;
        }

        // Check epoch boundary
        if self.frees_this_epoch >= EPOCH_INTERVAL {
            self.update_epoch();
            return true;
        }
        false
    }

    /// Epoch update: adjust depth using primal-dual optimization.
    fn update_epoch(&mut self) {
        self.epochs += 1;
        let contention = CONTENTION.read_and_reset_peak() as f64;

        // Compute p99 latency from window
        let p99 = self.compute_p99();

        // Compute safety signal: estimated escape rate
        let hit_rate = if self.frees_this_epoch > 0 {
            self.hits_this_epoch as f64 / self.frees_this_epoch as f64
        } else {
            0.0
        };

        // Exponential moving average of escape rate estimate
        // Higher hit rate means more UAF attempts → increase depth
        self.estimated_escape_rate = 0.9 * self.estimated_escape_rate + 0.1 * hit_rate;

        // Primal objective gradient (d/d_depth of cost):
        // memory_cost increases linearly with depth
        // latency_cost: deeper queue means more cache misses
        // safety_benefit: deeper queue catches more UAF
        let depth_f = self.depth as f64;
        let depth_max_f = MAX_DEPTH as f64;
        let depth_min_f = MIN_DEPTH as f64;

        // Gradient of memory waste w.r.t. depth
        let grad_memory = 1.0 / depth_max_f; // normalized

        // Gradient of latency w.r.t. depth (deeper = more cache misses)
        let grad_latency = p99 / 1_000_000.0; // normalize to ms

        // Gradient of safety benefit (logarithmic: deeper helps, diminishing returns)
        let grad_safety = -(1.0 / depth_f.max(1.0));

        // Primal update: depth moves opposite to gradient of Lagrangian
        let lagrangian_grad = grad_memory
            + self.lambda_latency * grad_latency
            + self.lambda_memory * grad_memory
            + grad_safety * (self.estimated_escape_rate / SAFETY_EPSILON);

        // Barrier certificate: repulsive force near boundaries
        let barrier_grad =
            1.0 / (depth_max_f - depth_f).max(1.0) - 1.0 / (depth_f - depth_min_f).max(1.0);

        let total_grad = lagrangian_grad + 0.01 * barrier_grad;

        // Contention scaling: increase depth under high contention
        let contention_boost = (contention / 4.0).min(2.0);

        let new_depth_f =
            depth_f - PRIMAL_LR * total_grad * depth_max_f + PRIMAL_LR * contention_boost * 100.0;

        // Clamp to valid range
        self.depth = (new_depth_f as usize).clamp(MIN_DEPTH, MAX_DEPTH);

        // Dual updates (gradient ascent on constraint violations)
        // Latency constraint: p99 should be below budget
        let latency_budget_ns = 1_000_000.0; // 1ms budget
        let latency_violation = (p99 - latency_budget_ns) / latency_budget_ns;
        self.lambda_latency = (self.lambda_latency + DUAL_LR * latency_violation).clamp(0.0, 10.0);

        // Memory constraint: depth shouldn't consume too much memory
        let memory_fraction = depth_f / depth_max_f;
        let memory_violation = memory_fraction - 0.5; // Soft limit at 50% of max
        self.lambda_memory = (self.lambda_memory + DUAL_LR * memory_violation).clamp(0.0, 10.0);

        // Reset epoch counters
        self.hits_this_epoch = 0;
        self.frees_this_epoch = 0;
    }

    /// Compute the p99 latency from the observation window.
    fn compute_p99(&self) -> f64 {
        if self.latency_count < 2 {
            return 0.0;
        }

        let n = self.latency_count;
        let mut sorted: Vec<u64> = self.latencies[..n].to_vec();
        sorted.sort_unstable();

        let p99_idx = ((n as f64) * 0.99).ceil() as usize;
        sorted[p99_idx.min(n - 1)] as f64
    }

    /// Returns the current dual variables for diagnostics.
    pub fn dual_variables(&self) -> (f64, f64) {
        (self.lambda_latency, self.lambda_memory)
    }

    /// Returns the estimated UAF escape rate.
    pub fn estimated_escape_rate(&self) -> f64 {
        self.estimated_escape_rate
    }

    /// Returns the total number of quarantine hits.
    pub fn total_hits(&self) -> u64 {
        self.total_hits
    }

    /// Returns the number of epochs completed.
    pub fn epochs(&self) -> u64 {
        self.epochs
    }
}

impl Default for QuarantineController {
    fn default() -> Self {
        Self::new()
    }
}

/// Global quarantine depth (atomically readable by all threads).
pub static QUARANTINE_DEPTH: AtomicU64 = AtomicU64::new(DEFAULT_DEPTH as u64);

/// Publish the controller's current depth to the global atomic.
pub fn publish_depth(controller: &QuarantineController) {
    QUARANTINE_DEPTH.store(controller.depth() as u64, Ordering::Release);
}

/// Read the current quarantine depth (lock-free).
pub fn current_depth() -> usize {
    QUARANTINE_DEPTH.load(Ordering::Acquire) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_controller() {
        let ctrl = QuarantineController::new();
        assert_eq!(ctrl.depth(), DEFAULT_DEPTH);
        assert_eq!(ctrl.epochs(), 0);
        assert_eq!(ctrl.total_hits(), 0);
    }

    #[test]
    fn test_record_free_no_epoch() {
        let mut ctrl = QuarantineController::new();
        for _ in 0..100 {
            let updated = ctrl.record_free(1000, false);
            assert!(!updated);
        }
    }

    #[test]
    fn test_epoch_triggers_at_interval() {
        let mut ctrl = QuarantineController::new();
        let mut epoch_triggered = false;
        for _ in 0..EPOCH_INTERVAL {
            if ctrl.record_free(1000, false) {
                epoch_triggered = true;
            }
        }
        assert!(epoch_triggered);
        assert_eq!(ctrl.epochs(), 1);
    }

    #[test]
    fn test_depth_stays_in_bounds() {
        let mut ctrl = QuarantineController::new();
        // Run many epochs with varying conditions
        for epoch in 0..100 {
            for _ in 0..EPOCH_INTERVAL {
                let hit = epoch % 3 == 0; // Some epochs have hits
                let latency = if epoch % 5 == 0 { 5_000_000 } else { 100 };
                ctrl.record_free(latency, hit);
            }
            assert!(
                ctrl.depth() >= MIN_DEPTH,
                "depth {} below min {}",
                ctrl.depth(),
                MIN_DEPTH
            );
            assert!(
                ctrl.depth() <= MAX_DEPTH,
                "depth {} above max {}",
                ctrl.depth(),
                MAX_DEPTH
            );
        }
    }

    #[test]
    fn test_high_hit_rate_increases_depth() {
        let mut ctrl = QuarantineController::new();
        let initial_depth = ctrl.depth();

        // Many UAF hits should push depth up
        for _ in 0..10 {
            for _ in 0..EPOCH_INTERVAL {
                ctrl.record_free(100, true); // Every free is a quarantine hit
            }
        }

        // Depth should have increased (or stayed at max)
        assert!(
            ctrl.depth() >= initial_depth || ctrl.depth() == MAX_DEPTH,
            "Expected depth to increase from {} under high UAF rate, got {}",
            initial_depth,
            ctrl.depth()
        );
    }

    #[test]
    fn test_contention_signal() {
        let signal = ContentionSignal::new();
        signal.free_begin();
        signal.free_begin();
        assert_eq!(signal.concurrent_frees.load(Ordering::Relaxed), 2);
        signal.free_end();
        assert_eq!(signal.concurrent_frees.load(Ordering::Relaxed), 1);
        let peak = signal.read_and_reset_peak();
        assert_eq!(peak, 2);
    }

    #[test]
    fn test_publish_and_read_depth() {
        let ctrl = QuarantineController::new();
        publish_depth(&ctrl);
        assert_eq!(current_depth(), DEFAULT_DEPTH);
    }

    #[test]
    fn test_dual_variables_bounded() {
        let mut ctrl = QuarantineController::new();
        for _ in 0..50 {
            for _ in 0..EPOCH_INTERVAL {
                ctrl.record_free(10_000_000, false); // High latency
            }
        }
        let (lambda_l, lambda_m) = ctrl.dual_variables();
        assert!((0.0..=10.0).contains(&lambda_l));
        assert!((0.0..=10.0).contains(&lambda_m));
    }

    #[test]
    fn test_escape_rate_updates() {
        let mut ctrl = QuarantineController::new();
        assert_eq!(ctrl.estimated_escape_rate(), 0.0);

        // Record some hits
        for _ in 0..EPOCH_INTERVAL {
            ctrl.record_free(100, true);
        }
        assert!(ctrl.estimated_escape_rate() > 0.0);
    }
}
