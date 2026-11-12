//! Exercise real arena retirement feedback with the library built without cfg(test).
//! Each scenario runs alone because quarantine depth and mode are process-global.

#![cfg(target_os = "linux")]

use frankenlibc_membrane::ValidationPipeline;
use frankenlibc_membrane::arena::FreeResult;
use frankenlibc_membrane::config::{SafetyLevel, safety_level};
use frankenlibc_membrane::fingerprint::FINGERPRINT_SIZE;
use frankenlibc_membrane::lattice::SafetyState;
use frankenlibc_membrane::quarantine_controller::{DEFAULT_DEPTH, MAX_DEPTH, current_depth};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, RUNTIME_MATH_PRODUCTION_ENABLED, RuntimeMathEnvironmentGuard, RuntimeMathKernel,
    ValidationProfile,
};
use frankenlibc_membrane::tls_cache::{NUM_TLS_CACHE_SHARDS, tls_cache_shard_for};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::marker::PhantomData;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_ENV: &str = "FRANKENLIBC_TEST_QUARANTINE_FEEDBACK_CHILD";
const TEST_NAME: &str = "completed_arena_frees_drive_quarantine";

#[derive(Clone, Copy)]
struct ProbeState {
    active: bool,
    allocations: usize,
    kernel: *const RuntimeMathKernel,
}

impl ProbeState {
    const DISABLED: Self = Self {
        active: false,
        allocations: 0,
        kernel: std::ptr::null(),
    };
}

thread_local! {
    // Constant, destructor-free TLS keeps the allocator callback allocation-free.
    static PROBE: Cell<ProbeState> = const { Cell::new(ProbeState::DISABLED) };
}

fn note_allocation() {
    let _ = PROBE.try_with(|cell| {
        let mut state = cell.get();
        if !state.active {
            return;
        }
        state.allocations += 1;
        cell.set(state);
        if !state.kernel.is_null() {
            // SAFETY: AllocationProbe borrows this kernel until it disables the
            // thread-local callback. No pointer or guard escapes this call.
            // An allocation while holding the controller mutex would reenter
            // that same lock here; the parent bounds the child execution.
            let _ = unsafe { &*state.kernel }.quarantine_snapshot();
        }
    });
}

struct ProbeAllocator;

// SAFETY: every operation is forwarded to System with its original arguments.
// The callback only observes thread-local counters and a borrowed live kernel.
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        note_allocation();
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

struct AllocationProbe<'a>(PhantomData<&'a RuntimeMathKernel>);

impl<'a> AllocationProbe<'a> {
    fn start(kernel: Option<&'a RuntimeMathKernel>) -> Self {
        PROBE.with(|cell| {
            cell.set(ProbeState {
                active: true,
                allocations: 0,
                kernel: kernel.map_or(std::ptr::null(), std::ptr::from_ref),
            });
        });
        Self(PhantomData)
    }

    fn finish(self) -> usize {
        PROBE.with(|cell| cell.replace(ProbeState::DISABLED).allocations)
    }
}

impl Drop for AllocationProbe<'_> {
    fn drop(&mut self) {
        let _ = PROBE.try_with(|cell| cell.set(ProbeState::DISABLED));
    }
}

fn classification_case() {
    assert_eq!(safety_level(), SafetyLevel::Hardened);
    let pipeline = ValidationPipeline::with_runtime_math(true);
    let anchor = pipeline.allocate(16).expect("anchor allocation");
    let canary = pipeline.allocate(16).expect("canary allocation");
    let header = pipeline.allocate(16).expect("header allocation");
    assert_eq!(
        pipeline
            .runtime_math
            .quarantine_snapshot()
            .retirement_attempts,
        0
    );
    assert_eq!(pipeline.free(anchor), FreeResult::Freed);

    // SAFETY: these live arena allocations have a mapped fingerprint header
    // and trailing redzone. Toggle one bit so corruption is deterministic.
    unsafe {
        *canary.add(16) ^= 1;
        *header.sub(FINGERPRINT_SIZE) ^= 1;
    }
    assert_eq!(pipeline.free(canary), FreeResult::FreedWithCanaryCorruption);
    assert_eq!(
        pipeline.free(header),
        FreeResult::FreedWithFingerprintCorruption
    );
    assert_eq!(pipeline.free(anchor), FreeResult::DoubleFree);
    let mut foreign = [0_u8; 16];
    assert_eq!(
        pipeline.free(foreign.as_mut_ptr()),
        FreeResult::ForeignPointer
    );
    pipeline.runtime_math.observe_allocator_free(
        SafetyLevel::Hardened,
        FreeResult::InvalidPointer,
        20,
    );

    let snapshot = pipeline.runtime_math.quarantine_snapshot();
    assert_eq!(snapshot.retirement_attempts, 4);
    assert_eq!(snapshot.successful_frees, 3);
    assert_eq!(snapshot.quarantine_hits, 1);
    assert_eq!(snapshot.epochs, 0);

    // Generic observations have no allocation/free identity. They must not
    // contribute invented frees or turn generic adverse events into UAF hits.
    for _ in 0..16 {
        pipeline.runtime_math.observe_validation_result(
            SafetyLevel::Hardened,
            ApiFamily::Allocator,
            ValidationProfile::Full,
            20,
            true,
        );
    }
    for mode in [SafetyLevel::Strict, SafetyLevel::Off] {
        pipeline
            .runtime_math
            .observe_allocator_free(mode, FreeResult::DoubleFree, 20);
    }
    assert_eq!(pipeline.runtime_math.quarantine_snapshot(), snapshot);

    for _ in 0..251 {
        let ptr = pipeline.allocate(16).expect("epoch allocation");
        assert_eq!(pipeline.free(ptr), FreeResult::Freed);
    }
    assert_eq!(pipeline.runtime_math.quarantine_snapshot().epochs, 0);
    let ptr = pipeline.allocate(0).expect("zero-size allocation");
    assert_eq!(pipeline.free(ptr), FreeResult::Freed);
    let snapshot = pipeline.runtime_math.quarantine_snapshot();
    assert_eq!(snapshot.retirement_attempts, 256);
    assert_eq!(snapshot.successful_frees, 255);
    assert_eq!(snapshot.quarantine_hits, 1);
    assert_eq!(snapshot.epochs, 1);
    assert!((snapshot.quarantine_hit_rate_ewma - 0.1 / 256.0).abs() < 1e-12);
    assert!(snapshot.depth > DEFAULT_DEPTH);
    assert_eq!(current_depth(), snapshot.depth);
}

#[cfg(target_arch = "x86_64")]
fn fenv_words() -> (u32, u16, u16) {
    let (mut mxcsr, mut control, mut status) = (0_u32, 0_u16, 0_u16);
    // SAFETY: each instruction writes exactly one correctly sized local word.
    unsafe {
        core::arch::asm!(
            "stmxcsr [{mxcsr}]", "fnstcw [{control}]", "fnstsw [{status}]",
            mxcsr = in(reg) &mut mxcsr,
            control = in(reg) &mut control,
            status = in(reg) &mut status,
            options(nostack, preserves_flags),
        );
    }
    (mxcsr, control, status)
}

fn allocation_and_environment_case() {
    let control = AllocationProbe::start(None);
    let allocation = std::hint::black_box(Box::new([0_u8; 128]));
    drop(allocation);
    assert!(
        control.finish() > 0,
        "allocation counter positive control did not run"
    );

    for caller_errno in [0, libc::EACCES] {
        let kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Hardened);
        let _restore = RuntimeMathEnvironmentGuard::enter();
        #[cfg(target_arch = "x86_64")]
        let before_fenv = {
            // All exceptions masked, toward-zero rounding, selected sticky flags.
            let mxcsr = 0x7fa5_u32;
            // SAFETY: this is a valid MXCSR value; the outer guard restores it.
            unsafe {
                core::arch::asm!("ldmxcsr [{mxcsr}]", mxcsr = in(reg) &mxcsr, options(nostack, preserves_flags));
            }
            fenv_words()
        };
        // SAFETY: access only the current thread's live errno slot.
        unsafe { *libc::__errno_location() = caller_errno };
        let probe = AllocationProbe::start(Some(&kernel));
        for _ in 0..256 {
            kernel.observe_allocator_free(SafetyLevel::Hardened, FreeResult::Freed, 20);
        }
        let allocations = probe.finish();
        let after_errno = unsafe { *libc::__errno_location() };
        #[cfg(target_arch = "x86_64")]
        let after_fenv = fenv_words();
        assert_eq!(allocations, 0, "quarantine epoch allocated under its mutex");
        assert_eq!(after_errno, caller_errno);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(after_fenv, before_fenv);
        let snapshot = kernel.quarantine_snapshot();
        assert_eq!(snapshot.retirement_attempts, 256);
        assert_eq!(snapshot.epochs, 1);
    }
}

fn concurrent_case() {
    const THREADS: usize = 8;
    const FREES: usize = 257;
    let pipeline = ValidationPipeline::with_runtime_math(true);
    let start = std::sync::Barrier::new(THREADS);
    std::thread::scope(|scope| {
        for worker in 0..THREADS {
            let pipeline = &pipeline;
            let start = &start;
            scope.spawn(move || {
                start.wait();
                for _ in 0..FREES {
                    let ptr = pipeline.allocate(16 + worker).expect("worker allocation");
                    // SAFETY: current-thread errno, checked immediately after free.
                    unsafe { *libc::__errno_location() = libc::EACCES };
                    let result = pipeline.free(ptr);
                    let errno = unsafe { *libc::__errno_location() };
                    assert_eq!(result, FreeResult::Freed);
                    assert_eq!(errno, libc::EACCES);
                }
            });
        }
    });
    let snapshot = pipeline.runtime_math.quarantine_snapshot();
    assert_eq!(snapshot.retirement_attempts, (THREADS * FREES) as u64);
    assert_eq!(snapshot.successful_frees, snapshot.retirement_attempts);
    assert_eq!(snapshot.quarantine_hits, 0);
    assert_eq!(snapshot.epochs, (THREADS * FREES / 256) as u64);
    assert_eq!(snapshot.depth, current_depth());
}

fn retention_case(enabled: bool) {
    assert_eq!(current_depth(), DEFAULT_DEPTH);
    let pipeline = ValidationPipeline::with_runtime_math(enabled);
    let anchor = pipeline.allocate(16).expect("retention anchor");
    assert_eq!(pipeline.free(anchor), FreeResult::Freed);
    for _ in 0..255 {
        assert_eq!(pipeline.free(anchor), FreeResult::DoubleFree);
    }
    let trained = pipeline.runtime_math.quarantine_snapshot();
    if enabled {
        assert_eq!(trained.retirement_attempts, 256);
        assert_eq!(trained.successful_frees, 1);
        assert_eq!(trained.quarantine_hits, 255);
        assert_eq!(trained.epochs, 1);
        assert_eq!(trained.depth, MAX_DEPTH);
    } else {
        assert_eq!(trained.retirement_attempts, 0);
        assert_eq!(trained.epochs, 0);
        assert_eq!(current_depth(), DEFAULT_DEPTH);
    }

    // Use actual small allocations, not synthetic arena slots. By the
    // pigeonhole principle one shard must reach DEFAULT_DEPTH + 1 within
    // DEFAULT_DEPTH * NUM_TLS_CACHE_SHARDS + 1 allocations.
    let mut buckets: [Vec<*mut u8>; NUM_TLS_CACHE_SHARDS] = std::array::from_fn(|_| Vec::new());
    let mut selected = None;
    for _ in 0..=DEFAULT_DEPTH * NUM_TLS_CACHE_SHARDS {
        let ptr = pipeline.allocate(16).expect("retention allocation");
        let shard = tls_cache_shard_for(ptr as usize);
        buckets[shard].push(ptr);
        if buckets[shard].len() > DEFAULT_DEPTH {
            selected = Some(shard);
            break;
        }
    }
    let bucket = &buckets[selected.expect("one shard must exceed the default depth")];
    let oldest = bucket[0];
    for &ptr in bucket {
        assert_eq!(pipeline.free(ptr), FreeResult::Freed);
    }
    let observed = pipeline.arena.lookup(oldest as usize);
    if enabled {
        assert!(current_depth() > DEFAULT_DEPTH);
        assert_eq!(
            observed
                .expect("adapted quarantine retains the oldest block")
                .state,
            SafetyState::Quarantined
        );
        let final_snapshot = pipeline.runtime_math.quarantine_snapshot();
        assert_eq!(
            final_snapshot.retirement_attempts,
            256 + bucket.len() as u64
        );
        assert_eq!(final_snapshot.successful_frees, 1 + bucket.len() as u64);
        assert_eq!(final_snapshot.quarantine_hits, 255);
    } else {
        assert!(
            observed.is_none(),
            "unchanged default depth must drain the oldest block"
        );
        assert_eq!(pipeline.runtime_math.quarantine_snapshot(), trained);
    }
}

fn disabled_case(enabled: bool) {
    let pipeline = ValidationPipeline::with_runtime_math(enabled);
    let before = pipeline.runtime_math.quarantine_snapshot();
    for _ in 0..256 {
        let ptr = pipeline.allocate(16).expect("disabled-mode allocation");
        assert_eq!(pipeline.free(ptr), FreeResult::Freed);
    }
    assert_eq!(pipeline.runtime_math.quarantine_snapshot(), before);
    assert_eq!(current_depth(), DEFAULT_DEPTH);
}

fn run_child(case: &str, mode: &str) {
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, case)
        .env("FRANKENLIBC_MODE", mode)
        .env_remove("FRANKENLIBC_LOG")
        .env_remove("FRANKENLIBC_HEAL_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated feedback case");
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("poll feedback child").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("quarantine case {case} exceeded 30 seconds (possible allocator reentry)");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect feedback child");
    assert!(
        output.status.success(),
        "quarantine case {case} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("quarantine feedback case completed"));
}

#[test]
fn completed_arena_frees_drive_quarantine() {
    if let Ok(case) = std::env::var(CHILD_ENV) {
        if !RUNTIME_MATH_PRODUCTION_ENABLED {
            disabled_case(true);
        } else {
            match case.as_str() {
                "classification" => classification_case(),
                "allocation-environment" => allocation_and_environment_case(),
                "concurrent" => concurrent_case(),
                "retention-enabled" => retention_case(true),
                "retention-disabled" => retention_case(false),
                "strict" => disabled_case(true),
                _ => panic!("unknown quarantine case {case}"),
            }
        }
        println!("quarantine feedback case completed: {case}");
        return;
    }
    for case in [
        "classification",
        "allocation-environment",
        "concurrent",
        "retention-enabled",
        "retention-disabled",
    ] {
        run_child(case, "hardened");
    }
    run_child("strict", "strict");
}
