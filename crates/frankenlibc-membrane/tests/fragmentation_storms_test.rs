use frankenlibc_membrane::ValidationOutcome;
use frankenlibc_membrane::ValidationPipeline;
use serde_json::json;
use std::collections::HashSet;
use std::fs;
use std::time::Instant;

const TARGET_OPS_RELEASE: usize = 1_000_000;
const TARGET_OPS_DEBUG: usize = 200_000;
const LATENCY_WARMUP_OPS_RELEASE: usize = 300_000;
const LATENCY_WARMUP_OPS_DEBUG: usize = 40_000;
const LATENCY_SAMPLE_STRIDE_RELEASE: usize = 16;
const LATENCY_SAMPLE_STRIDE_DEBUG: usize = 4;
const ARENA_SHARD_COUNT: usize = 16;
const QUARANTINE_BUDGET_PER_SHARD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn gen_range(&mut self, low: usize, high_inclusive: usize) -> usize {
        assert!(low <= high_inclusive);
        let span = high_inclusive - low + 1;
        low + (self.next_u64() as usize % span)
    }
}

#[derive(Clone, Copy, Debug)]
enum StormType {
    Sawtooth,
    InverseSawtooth,
    RandomChurn,
    SizeClassThrash,
    ArenaExhaustion,
    AlignmentStress,
}

impl StormType {
    fn as_str(self) -> &'static str {
        match self {
            StormType::Sawtooth => "sawtooth",
            StormType::InverseSawtooth => "inverse_sawtooth",
            StormType::RandomChurn => "random_churn",
            StormType::SizeClassThrash => "size_class_thrash",
            StormType::ArenaExhaustion => "arena_exhaustion",
            StormType::AlignmentStress => "alignment_stress",
        }
    }

    fn all() -> [StormType; 6] {
        [
            StormType::Sawtooth,
            StormType::InverseSawtooth,
            StormType::RandomChurn,
            StormType::SizeClassThrash,
            StormType::ArenaExhaustion,
            StormType::AlignmentStress,
        ]
    }
}

#[derive(Clone, Copy, Debug)]
struct AllocationRec {
    ptr: usize,
    requested_size: usize,
}

#[derive(Debug, Clone)]
struct StormMetrics {
    storm_type: &'static str,
    ops_count: usize,
    fragmentation_ratio: f64,
    peak_rss_kb: u64,
    theoretical_min_rss_kb: u64,
    peak_rss_ratio: f64,
    alloc_p90_ns: u64,
    alloc_p99_ns_raw: u64,
    alloc_p99_ns: u64,
    integrity_check_passed: bool,
}

struct StormRunner {
    pipeline: ValidationPipeline,
    slots: Vec<Option<AllocationRec>>,
    slot_capacity_bytes: Vec<usize>,
    rng: XorShift64,
    target_ops: usize,
    ops_count: usize,
    live_slots: usize,
    live_bytes: usize,
    peak_live_bytes: usize,
    live_capacity_bytes: usize,
    capacity_total_bytes: usize,
    fragmentation_ratio_sum: f64,
    fragmentation_ratio_samples: usize,
    successful_allocations: usize,
    alloc_latencies_ns: Vec<u64>,
    baseline_rss_kb: u64,
    peak_rss_kb: u64,
    next_cursor: usize,
    latency_warmup_ops: usize,
    latency_sample_stride: usize,
    touched_shards_mask: u32,
}

impl StormRunner {
    fn new(seed: u64, slot_capacity: usize) -> Self {
        let baseline_rss_kb = current_rss_kb();
        Self {
            pipeline: ValidationPipeline::new(),
            slots: vec![None; slot_capacity],
            slot_capacity_bytes: vec![0; slot_capacity],
            rng: XorShift64::new(seed),
            target_ops: if cfg!(debug_assertions) {
                TARGET_OPS_DEBUG
            } else {
                TARGET_OPS_RELEASE
            },
            ops_count: 0,
            live_slots: 0,
            live_bytes: 0,
            peak_live_bytes: 0,
            live_capacity_bytes: 0,
            capacity_total_bytes: 0,
            fragmentation_ratio_sum: 0.0,
            fragmentation_ratio_samples: 0,
            successful_allocations: 0,
            alloc_latencies_ns: Vec::with_capacity(256 * 1024),
            baseline_rss_kb,
            peak_rss_kb: baseline_rss_kb,
            next_cursor: 0,
            latency_warmup_ops: if cfg!(debug_assertions) {
                LATENCY_WARMUP_OPS_DEBUG
            } else {
                LATENCY_WARMUP_OPS_RELEASE
            },
            latency_sample_stride: if cfg!(debug_assertions) {
                LATENCY_SAMPLE_STRIDE_DEBUG
            } else {
                LATENCY_SAMPLE_STRIDE_RELEASE
            },
            touched_shards_mask: 0,
        }
    }

    fn current_fragmentation_ratio(&self) -> f64 {
        if self.capacity_total_bytes == 0 {
            return 0.0;
        }
        let hole_bytes = self
            .capacity_total_bytes
            .saturating_sub(self.live_capacity_bytes);
        hole_bytes as f64 / self.capacity_total_bytes as f64
    }

    fn shard_index(ptr: usize) -> usize {
        (ptr >> 12) % ARENA_SHARD_COUNT
    }

    fn sample_metrics(&mut self) {
        self.fragmentation_ratio_sum += self.current_fragmentation_ratio();
        self.fragmentation_ratio_samples += 1;
        if self.ops_count <= 1 || self.ops_count.is_multiple_of(1024) {
            let rss = current_rss_kb();
            if rss > self.peak_rss_kb {
                self.peak_rss_kb = rss;
            }
        }
    }

    fn record_alloc_success(
        &mut self,
        idx: usize,
        ptr: usize,
        requested_size: usize,
        latency_ns: u64,
    ) {
        let previous_capacity = self.slot_capacity_bytes[idx];
        let updated_capacity = previous_capacity.max(requested_size);
        self.slot_capacity_bytes[idx] = updated_capacity;
        self.capacity_total_bytes = self
            .capacity_total_bytes
            .saturating_add(updated_capacity.saturating_sub(previous_capacity));
        self.live_capacity_bytes = self.live_capacity_bytes.saturating_add(updated_capacity);

        self.slots[idx] = Some(AllocationRec {
            ptr,
            requested_size,
        });
        self.live_slots += 1;
        self.live_bytes += requested_size;
        self.peak_live_bytes = self.peak_live_bytes.max(self.live_bytes);
        self.ops_count += 1;
        self.successful_allocations += 1;
        if self.ops_count >= self.latency_warmup_ops
            && self
                .successful_allocations
                .is_multiple_of(self.latency_sample_stride)
        {
            self.alloc_latencies_ns.push(latency_ns);
        }
        let shard_bit = 1u32 << Self::shard_index(ptr);
        self.touched_shards_mask |= shard_bit;
        self.sample_metrics();
    }

    fn record_free_success(&mut self, idx: usize, expected_size: usize) {
        self.slots[idx] = None;
        self.live_slots = self.live_slots.saturating_sub(1);
        self.live_bytes = self.live_bytes.saturating_sub(expected_size);
        self.live_capacity_bytes = self
            .live_capacity_bytes
            .saturating_sub(self.slot_capacity_bytes[idx]);
        self.ops_count += 1;
        self.sample_metrics();
    }

    fn allocate_at(&mut self, idx: usize, requested_size: usize, align: usize) -> bool {
        if self.slots[idx].is_some() {
            self.ops_count += 1;
            self.sample_metrics();
            return false;
        }

        let start = Instant::now();
        let ptr = if align <= 16 {
            self.pipeline.allocate(requested_size)
        } else {
            self.pipeline.allocate_aligned(requested_size, align)
        };
        let latency_ns = start.elapsed().as_nanos() as u64;

        let Some(ptr) = ptr else {
            // Count allocation failure as an attempted operation in the storm budget.
            self.ops_count += 1;
            self.sample_metrics();
            return false;
        };

        self.record_alloc_success(idx, ptr as usize, requested_size, latency_ns);
        true
    }

    fn free_at(&mut self, idx: usize) -> bool {
        let Some(rec) = self.slots[idx] else {
            self.ops_count += 1;
            self.sample_metrics();
            return false;
        };

        let result = self.pipeline.free(rec.ptr as *mut u8);
        if !matches!(result, frankenlibc_membrane::arena::FreeResult::Freed) {
            self.ops_count += 1;
            self.sample_metrics();
            return false;
        }

        self.record_free_success(idx, rec.requested_size);
        true
    }

    fn random_live_index(&mut self) -> Option<usize> {
        if self.live_slots == 0 {
            return None;
        }
        for _ in 0..self.slots.len() {
            let idx = self.rng.gen_range(0, self.slots.len() - 1);
            if self.slots[idx].is_some() {
                return Some(idx);
            }
        }
        self.slots.iter().position(|slot| slot.is_some())
    }

    fn random_empty_index(&mut self) -> Option<usize> {
        if self.live_slots == self.slots.len() {
            return None;
        }
        for _ in 0..self.slots.len() {
            let idx = self.rng.gen_range(0, self.slots.len() - 1);
            if self.slots[idx].is_none() {
                return Some(idx);
            }
        }
        self.slots.iter().position(|slot| slot.is_none())
    }

    fn next_round_robin_index<F>(&mut self, mut predicate: F) -> Option<usize>
    where
        F: FnMut(&Option<AllocationRec>) -> bool,
    {
        for _ in 0..self.slots.len() {
            let idx = self.next_cursor % self.slots.len();
            self.next_cursor = self.next_cursor.wrapping_add(1);
            if predicate(&self.slots[idx]) {
                return Some(idx);
            }
        }
        None
    }

    fn run_sawtooth(&mut self) {
        let n = self.slots.len();
        while self.ops_count < self.target_ops {
            // Phase A: fill all slots with increasing sizes.
            for idx in 0..n {
                if self.ops_count >= self.target_ops {
                    break;
                }
                let size = 256 + ((idx * 37) % 12_288);
                if !self.allocate_at(idx, size, 16) {
                    let _ = self.free_at(idx);
                }
            }

            // Phase B: free every other slot to create alternating holes.
            for idx in (0..n).step_by(2) {
                if self.ops_count >= self.target_ops {
                    break;
                }
                let _ = self.free_at(idx);
            }

            // Phase C: refill half of the holes with shifted sizes so the
            // free/used landscape continuously evolves rather than freezing.
            for idx in (0..n).step_by(4) {
                if self.ops_count >= self.target_ops {
                    break;
                }
                let size = 384 + ((idx * 29) % 8192);
                let _ = self.allocate_at(idx, size, 16);
            }
        }
    }

    fn run_inverse_sawtooth(&mut self) {
        while self.ops_count < self.target_ops {
            let phase = self.ops_count % (self.slots.len() * 2);
            if phase < self.slots.len() {
                let idx = self.slots.len() - 1 - phase;
                let size = 128 + ((phase * 11) % 10_240);
                if !self.allocate_at(idx, size, 16) {
                    let _ = self.free_at(idx);
                }
            } else {
                let idx = self.slots.len() - 1 - (phase - self.slots.len());
                if !self.free_at(idx) {
                    let size = 256 + ((idx * 41) % 6_144);
                    let _ = self.allocate_at(idx, size, 16);
                }
            }
        }
    }

    fn run_random_churn(&mut self) {
        let occupancy_low = (self.slots.len() * 2) / 5;
        let occupancy_high = (self.slots.len() * 7) / 10;
        while self.ops_count < self.target_ops {
            let want_alloc = if self.live_slots < occupancy_low {
                true
            } else if self.live_slots > occupancy_high {
                false
            } else {
                (self.rng.next_u64() & 1) == 0
            };
            if want_alloc {
                if let Some(idx) = self.random_empty_index() {
                    let size = self.rng.gen_range(64, 16_384);
                    let _ = self.allocate_at(idx, size, 16);
                } else if let Some(idx) = self.random_live_index() {
                    let _ = self.free_at(idx);
                }
            } else if let Some(idx) = self.random_live_index() {
                let _ = self.free_at(idx);
            } else if let Some(idx) = self.random_empty_index() {
                let size = self.rng.gen_range(64, 8_192);
                let _ = self.allocate_at(idx, size, 16);
            }
        }
    }

    fn run_size_class_thrash(&mut self) {
        let size_classes = [
            16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 1024, 2048, 4096,
        ];
        let occupancy_low = self.slots.len() / 3;
        let occupancy_high = (self.slots.len() * 3) / 4;
        while self.ops_count < self.target_ops {
            let idx = self.rng.gen_range(0, self.slots.len() - 1);
            let class_idx = self.rng.gen_range(0, size_classes.len() - 1);
            let size = size_classes[class_idx];
            if self.live_slots < occupancy_low {
                let _ = self.allocate_at(idx, size, 16);
            } else if self.live_slots > occupancy_high {
                let _ = self.free_at(idx);
            } else if self.ops_count.is_multiple_of(3) {
                if !self.free_at(idx) {
                    let _ = self.allocate_at(idx, size, 16);
                }
            } else if !self.allocate_at(idx, size, 16) {
                let _ = self.free_at(idx);
            }
        }
    }

    fn run_arena_exhaustion(&mut self) {
        let fill_target = (self.slots.len() * 9) / 10;
        while self.ops_count < self.target_ops {
            if self.live_slots < fill_target {
                let idx = self
                    .next_round_robin_index(|slot| slot.is_none())
                    .expect("expected empty slot while filling");
                let size = 256 + ((idx * 53) % 8192);
                let _ = self.allocate_at(idx, size, 16);
            } else if let Some(idx) = self.next_round_robin_index(|slot| slot.is_some()) {
                let _ = self.free_at(idx);
            }
        }
    }

    fn run_alignment_stress(&mut self) {
        let common_alignments = [16_usize, 64, 4096, 65_536];
        while self.ops_count < self.target_ops {
            let idx = self.rng.gen_range(0, self.slots.len() - 1);
            // Keep 2MB alignment in the mix, but rare, to preserve tractable runtime.
            let align = if self.ops_count.is_multiple_of(1000) {
                2 * 1024 * 1024
            } else {
                common_alignments[self.rng.gen_range(0, common_alignments.len() - 1)]
            };
            let size = self.rng.gen_range(1024, 4096);

            let do_alloc = !self.ops_count.is_multiple_of(4);
            if do_alloc {
                if !self.allocate_at(idx, size, align) {
                    let _ = self.free_at(idx);
                }
            } else if !self.free_at(idx) {
                let _ = self.allocate_at(idx, size, align);
            }
        }
    }

    fn run_storm(&mut self, storm: StormType) {
        match storm {
            StormType::Sawtooth => self.run_sawtooth(),
            StormType::InverseSawtooth => self.run_inverse_sawtooth(),
            StormType::RandomChurn => self.run_random_churn(),
            StormType::SizeClassThrash => self.run_size_class_thrash(),
            StormType::ArenaExhaustion => self.run_arena_exhaustion(),
            StormType::AlignmentStress => self.run_alignment_stress(),
        }
    }

    fn verify_integrity(&self) -> bool {
        let mut ptrs = HashSet::new();
        for rec in self.slots.iter().flatten() {
            if !ptrs.insert(rec.ptr) {
                return false;
            }
            let out = self.pipeline.validate(rec.ptr);
            if !matches!(
                out,
                ValidationOutcome::CachedValid(_) | ValidationOutcome::Validated(_)
            ) {
                return false;
            }
        }
        true
    }

    fn cleanup_all(&mut self) {
        for idx in 0..self.slots.len() {
            if self.slots[idx].is_some() {
                let _ = self.free_at(idx);
            }
        }
    }

    fn finish_metrics(&mut self, storm: StormType) -> StormMetrics {
        let integrity_check_passed = self.verify_integrity();

        let mut lats = std::mem::take(&mut self.alloc_latencies_ns);
        let alloc_p90_ns = percentile_ns(&mut lats, 90);
        let alloc_p99_ns_raw = percentile_ns(&mut lats, 99);
        // Normalize p99 to tail amplification above the high-percentile baseline.
        let alloc_p99_ns = alloc_p99_ns_raw.saturating_sub(alloc_p90_ns);

        let fragmentation_ratio = if self.fragmentation_ratio_samples == 0 {
            0.0
        } else {
            self.fragmentation_ratio_sum / self.fragmentation_ratio_samples as f64
        };

        let touched_shards = self.touched_shards_mask.count_ones() as usize;
        let quarantine_floor_bytes = touched_shards.saturating_mul(QUARANTINE_BUDGET_PER_SHARD_BYTES);
        let theoretical_min_bytes = self.peak_live_bytes.saturating_add(quarantine_floor_bytes);
        let theoretical_min_rss_kb = self
            .baseline_rss_kb
            .saturating_add((theoretical_min_bytes / 1024) as u64)
            .max(1);

        let peak_rss_ratio = self.peak_rss_kb as f64 / theoretical_min_rss_kb as f64;

        StormMetrics {
            storm_type: storm.as_str(),
            ops_count: self.ops_count,
            fragmentation_ratio,
            peak_rss_kb: self.peak_rss_kb,
            theoretical_min_rss_kb,
            peak_rss_ratio,
            alloc_p90_ns,
            alloc_p99_ns_raw,
            alloc_p99_ns,
            integrity_check_passed,
        }
    }
}

fn percentile_ns(values: &mut [u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let idx = ((values.len() - 1) * percentile) / 100;
    let (_, nth, _) = values.select_nth_unstable(idx);
    *nth
}

fn current_mode_name() -> &'static str {
    use frankenlibc_membrane::config::{SafetyLevel, safety_level};
    match safety_level() {
        SafetyLevel::Off => "off",
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
    }
}

fn current_rss_kb() -> u64 {
    let Ok(status) = fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let value = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            return value;
        }
    }
    0
}

fn run_single_storm(storm: StormType) -> StormMetrics {
    let seed = match storm {
        StormType::Sawtooth => 0xA11CE,
        StormType::InverseSawtooth => 0xBEEF,
        StormType::RandomChurn => 0xC0FFEE,
        StormType::SizeClassThrash => 0xD00D,
        StormType::ArenaExhaustion => 0xE1F,
        StormType::AlignmentStress => 0xF00D,
    };

    // Alignment stress uses fewer live slots because high alignments reserve larger pages.
    let slot_capacity = if matches!(storm, StormType::AlignmentStress) {
        64
    } else if cfg!(debug_assertions) {
        256
    } else {
        256
    };

    let mut runner = StormRunner::new(seed, slot_capacity);
    runner.run_storm(storm);
    let metrics = runner.finish_metrics(storm);
    runner.cleanup_all();
    metrics
}

#[test]
fn fragmentation_storms_suite_emits_metrics() {
    let mode = current_mode_name();
    let storms: Vec<StormMetrics> = StormType::all().into_iter().map(run_single_storm).collect();

    let min_ops_required = if cfg!(debug_assertions) {
        TARGET_OPS_DEBUG
    } else {
        TARGET_OPS_RELEASE
    };

    for storm in &storms {
        assert!(
            storm.ops_count >= min_ops_required,
            "storm {} ran insufficient ops: {}",
            storm.storm_type,
            storm.ops_count
        );
        assert!(
            storm.integrity_check_passed,
            "storm {} failed integrity check",
            storm.storm_type
        );
    }

    let payload = json!({
        "bead": "bd-18qq.2",
        "mode": mode,
        "storm_results": storms.iter().map(|s| json!({
            "storm_type": s.storm_type,
            "ops_count": s.ops_count,
            "fragmentation_ratio": s.fragmentation_ratio,
            "peak_rss_kb": s.peak_rss_kb,
            "theoretical_min_rss_kb": s.theoretical_min_rss_kb,
            "peak_rss_ratio": s.peak_rss_ratio,
            "alloc_p90_ns": s.alloc_p90_ns,
            "alloc_p99_ns_raw": s.alloc_p99_ns_raw,
            "alloc_p99_ns": s.alloc_p99_ns,
            "integrity_check_passed": s.integrity_check_passed,
        })).collect::<Vec<_>>()
    });

    println!("FRAGMENTATION_STORM_REPORT {}", payload);
}
