//! Runtime evidence remains usable across allocation failures and TLS teardown.
//! Neither failed slot allocation nor a destroyed Rust thread handle may abort libc.

use frankenlibc_membrane::config::SafetyLevel;
use frankenlibc_membrane::runtime_math::evidence::{
    DecisionCardRingBuffer, DecisionCardV1, EVIDENCE_SYMBOL_SIZE_T, EvidenceRingBuffer,
    EvidenceSymbolRecord, FLAG_SYSTEMATIC, SystematicEvidenceLog,
};
use frankenlibc_membrane::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, RuntimeMathKernel,
    ValidationProfile,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::marker::PhantomData;

const CAPACITY: usize = 512;

#[derive(Clone, Copy, Default)]
struct FailureState {
    active: bool,
    fail_at: usize,
    only_size: usize,
    attempts: usize,
    rejected: usize,
    rejected_bytes: usize,
    deallocations: usize,
}

thread_local! {
    // Const, destructor-free TLS: the allocator hook must never allocate.
    static FAILURE: Cell<FailureState> = const { Cell::new(FailureState {
        active: false,
        fail_at: 0,
        only_size: 0,
        attempts: 0,
        rejected: 0,
        rejected_bytes: 0,
        deallocations: 0,
    }) };
}

fn reject_allocation(size: usize) -> bool {
    FAILURE
        .try_with(|cell| {
            let mut state = cell.get();
            if !state.active || (state.only_size != 0 && state.only_size != size) {
                return false;
            }
            state.attempts += 1;
            let reject = state.fail_at == 0 || state.attempts == state.fail_at;
            if reject {
                state.rejected += 1;
                state.rejected_bytes = size;
            }
            cell.set(state);
            reject
        })
        .unwrap_or(false)
}

struct FailingAllocator;

// SAFETY: successful operations are forwarded to System with their original
// arguments; rejected allocation/reallocation requests return null and leave
// existing storage untouched. Hooks only update this thread's scalar state.
unsafe impl GlobalAlloc for FailingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if reject_allocation(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if reject_allocation(layout.size()) {
            return std::ptr::null_mut();
        }
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if reject_allocation(size) {
            return std::ptr::null_mut();
        }
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = FAILURE.try_with(|cell| {
            let mut state = cell.get();
            if state.active {
                state.deallocations += 1;
                cell.set(state);
            }
        });
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: FailingAllocator = FailingAllocator;

struct FailureGuard(PhantomData<*mut ()>);

impl Drop for FailureGuard {
    fn drop(&mut self) {
        FAILURE.with(|cell| cell.set(FailureState::default()));
    }
}

fn under_failure<R>(fail_at: usize, operation: impl FnOnce() -> R) -> (R, FailureState) {
    under_sized_failure(fail_at, 0, operation)
}

fn under_sized_failure<R>(
    fail_at: usize,
    only_size: usize,
    operation: impl FnOnce() -> R,
) -> (R, FailureState) {
    FAILURE.with(|cell| {
        cell.set(FailureState {
            active: true,
            fail_at,
            only_size,
            ..FailureState::default()
        });
    });
    let guard = FailureGuard(PhantomData);
    let result = operation();
    let state = FAILURE.with(Cell::get);
    drop(guard);
    (result, state)
}

fn check_rejection(state: FailureState, fail_at: usize) {
    assert_eq!(state.attempts, fail_at, "reached the requested allocation");
    assert_eq!(
        state.rejected, 1,
        "failure injection actually rejected memory"
    );
    if fail_at == 1 {
        assert!(state.rejected_bytes > std::mem::size_of::<Vec<u8>>());
        assert_eq!(state.deallocations, 0);
    } else {
        assert_eq!(state.rejected_bytes, std::mem::size_of::<Vec<u8>>());
        assert_eq!(state.deallocations, 1, "uninstalled slot buffer was freed");
    }
}

fn card(id: u64) -> DecisionCardV1 {
    DecisionCardV1 {
        decision_id: id,
        ..DecisionCardV1::zeroed()
    }
}

fn symbol(seqno: u64) -> EvidenceSymbolRecord {
    EvidenceSymbolRecord::build_v1(
        1,
        seqno,
        2,
        ApiFamily::Allocator,
        SafetyLevel::Strict,
        MembraneAction::Deny,
        ValidationProfile::Full,
        FLAG_SYSTEMATIC,
        0,
        256,
        0,
        0,
        &[7; EVIDENCE_SYMBOL_SIZE_T],
        None,
    )
}

fn decision_card_failure(fail_at: usize) {
    let ring = DecisionCardRingBuffer::<CAPACITY>::new();
    let id = ring.allocate_decision_id();
    let (published, failure) = under_failure(fail_at, || ring.publish(id, card(id)));
    assert!(!published);
    check_rejection(failure, fail_at);
    assert!(ring.snapshot_sorted().is_empty());

    let recovered = ring.allocate_decision_id();
    assert_eq!(recovered, id + 1);
    assert!(ring.publish(recovered, card(recovered)));
    assert_eq!(ring.snapshot_sorted()[0].decision_id, recovered);
    let next = ring.allocate_decision_id();
    let (published, warmed) = under_failure(0, || ring.publish(next, card(next)));
    assert!(published);
    assert_eq!(
        warmed.attempts, 0,
        "initialized publication is allocation-free"
    );
    assert_eq!(ring.snapshot_sorted().len(), 2);
}

fn evidence_symbol_failure(fail_at: usize) {
    let ring = EvidenceRingBuffer::<CAPACITY>::new();
    let seqno = ring.allocate_seqno();
    let record = symbol(seqno);
    let (published, failure) = under_failure(fail_at, || ring.publish(seqno, record));
    assert!(!published);
    check_rejection(failure, fail_at);
    assert!(ring.snapshot_sorted().is_empty());

    let recovered = ring.allocate_seqno();
    assert_eq!(recovered, seqno + 1);
    assert!(ring.publish(recovered, symbol(recovered)));
    assert_eq!(ring.snapshot_sorted()[0].seqno(), recovered);
    let next = ring.allocate_seqno();
    let record = symbol(next);
    let (published, warmed) = under_failure(0, || ring.publish(next, record));
    assert!(published);
    assert_eq!(
        warmed.attempts, 0,
        "initialized publication is allocation-free"
    );
    assert_eq!(ring.snapshot_sorted().len(), 2);
}

#[test]
fn decision_cards_recover_from_slot_buffer_failure() {
    decision_card_failure(1);
}

#[test]
fn decision_cards_recover_from_owning_box_failure() {
    decision_card_failure(2);
}

#[test]
fn evidence_symbols_recover_from_slot_buffer_failure() {
    evidence_symbol_failure(1);
}

#[test]
fn evidence_symbols_recover_from_owning_box_failure() {
    evidence_symbol_failure(2);
}

fn record(log: &SystematicEvidenceLog<CAPACITY>) -> u64 {
    log.record_decision(
        SafetyLevel::Strict,
        RuntimeContext::pointer_validation(0x1234, true),
        RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Deny,
            policy_id: 17,
            risk_upper_bound_ppm: 950_000,
            evidence_seqno: 0,
        },
        42,
        true,
        None,
        0,
        None,
    )
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod thread_identity {
    use super::*;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

    struct TeardownProbe {
        log: SystematicEvidenceLog<CAPACITY>,
        key: libc::pthread_key_t,
        tid: AtomicU64,
        setup_error: AtomicI32,
        rust_tls_destroyed: AtomicBool,
        destructor_after_rust_tls: AtomicBool,
        destructor_seqno: AtomicU64,
        destructor_errno: AtomicI32,
    }

    struct TeardownMarker(Cell<*const TeardownProbe>);

    impl Drop for TeardownMarker {
        fn drop(&mut self) {
            let probe = self.0.get();
            if !probe.is_null() {
                // SAFETY: the parent retains the probe through pthread_join,
                // including all compiler-TLS and POSIX-key destructors.
                unsafe { &*probe }
                    .rust_tls_destroyed
                    .store(true, Ordering::Release);
            }
        }
    }

    thread_local! {
        static TEARDOWN_MARKER: TeardownMarker = const {
            TeardownMarker(Cell::new(std::ptr::null()))
        };
    }

    #[inline(never)]
    fn record_from_another_frame(log: &SystematicEvidenceLog<CAPACITY>) -> u64 {
        let padding = [0u8; 4096];
        std::hint::black_box(&padding);
        let seqno = record(log);
        std::hint::black_box(&padding);
        seqno
    }

    unsafe extern "C" fn record_after_rust_tls(argument: *mut c_void) {
        // SAFETY: pthread invokes this with the registered probe, whose parent
        // waits for this callback to finish before accessing or releasing it.
        let probe = unsafe { &*argument.cast::<TeardownProbe>() };
        probe.destructor_after_rust_tls.store(
            probe.rust_tls_destroyed.load(Ordering::Acquire),
            Ordering::Relaxed,
        );
        // No assertions, formatting or snapshot allocations run during teardown.
        // The rings were initialized before the foreign thread was created.
        // SAFETY: glibc's errno cell remains valid through its key destructors.
        let errno = unsafe { libc::__errno_location() };
        // SAFETY: this live thread owns its errno cell.
        unsafe { *errno = libc::ENOTTY };
        let seqno = record_from_another_frame(&probe.log);
        // SAFETY: the callback has not ended this thread or invalidated its TCB.
        probe
            .destructor_errno
            .store(unsafe { *errno }, Ordering::Relaxed);
        probe.destructor_seqno.store(seqno, Ordering::Release);
    }

    extern "C" fn foreign_thread(argument: *mut c_void) -> *mut c_void {
        // SAFETY: the parent retains its probe until this pthread is joined.
        let probe = unsafe { &*argument.cast::<TeardownProbe>() };
        // Initialize the Rust thread handle which the old logger depended on.
        // GNU pthread teardown destroys compiler TLS before POSIX key values.
        drop(std::thread::current());
        TEARDOWN_MARKER.with(|marker| marker.0.set(probe));
        // SAFETY: gettid has no arguments; this independently checks the
        // production direct-syscall identity against the host syscall wrapper.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        probe.tid.store(tid, Ordering::Release);
        // SAFETY: the key is live and the probe outlives all teardown callbacks.
        let result = unsafe { libc::pthread_setspecific(probe.key, argument.cast_const()) };
        probe.setup_error.store(result, Ordering::Release);
        if result == 0 {
            record(&probe.log);
            record_from_another_frame(&probe.log);
        }
        std::ptr::null_mut()
    }

    #[test]
    fn evidence_records_after_rust_tls_teardown_with_real_thread_identity() {
        const CHILD: &str = "FRANKENLIBC_EVIDENCE_TLS_TEARDOWN_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "thread_identity::evidence_records_after_rust_tls_teardown_with_real_thread_identity",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "TLS teardown evidence child failed: {:?}\n{}\n{}",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"),
                "the exact subprocess regression must execute once"
            );
            assert!(
                output.stderr.is_empty(),
                "unexpected stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        // SAFETY: this isolated subprocess owns the default SIGALRM disposition.
        unsafe { libc::alarm(10) };
        let no_core = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: valid limit storage; a broken implementation should abort this
        // isolated child without writing a potentially large core dump.
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CORE, &no_core) }, 0);
        let mut key = 0;
        // SAFETY: writable key storage and a valid destructor with the C ABI.
        assert_eq!(
            unsafe { libc::pthread_key_create(&mut key, Some(record_after_rust_tls)) },
            0
        );
        let probe = TeardownProbe {
            log: SystematicEvidenceLog::new(123),
            key,
            tid: AtomicU64::new(0),
            setup_error: AtomicI32::new(-1),
            rust_tls_destroyed: AtomicBool::new(false),
            destructor_after_rust_tls: AtomicBool::new(false),
            destructor_seqno: AtomicU64::new(0),
            destructor_errno: AtomicI32::new(0),
        };
        assert_eq!(record(&probe.log), 1);
        // SAFETY: gettid has no arguments and cannot affect the worker's state.
        let parent_tid = unsafe { libc::syscall(libc::SYS_gettid) } as u64;
        let mut thread = std::mem::MaybeUninit::<libc::pthread_t>::uninit();
        // SAFETY: the new thread receives a live probe which stays in this frame
        // until join completes; only atomics and synchronized rings are shared.
        let created = unsafe {
            libc::pthread_create(
                thread.as_mut_ptr(),
                std::ptr::null(),
                foreign_thread,
                std::ptr::from_ref(&probe).cast_mut().cast(),
            )
        };
        if created != 0 {
            // SAFETY: no thread was created, so no callback can use this key.
            unsafe { libc::pthread_key_delete(key) };
            assert_eq!(created, 0, "foreign pthread creation");
        }
        // SAFETY: successful creation initialized the handle; this is its sole join.
        let joined = unsafe { libc::pthread_join(thread.assume_init(), std::ptr::null_mut()) };
        if joined != 0 {
            // SAFETY: an unexpected join failure must not drop the probe while
            // a foreign thread could still access it. Terminate the isolated child.
            unsafe { libc::_exit(94) };
        }
        // SAFETY: the thread and all callbacks are finished, so the key is unused.
        assert_eq!(unsafe { libc::pthread_key_delete(key) }, 0);
        assert_eq!(probe.setup_error.load(Ordering::Acquire), 0);
        assert!(probe.rust_tls_destroyed.load(Ordering::Acquire));
        assert!(probe.destructor_after_rust_tls.load(Ordering::Relaxed));
        assert_eq!(probe.destructor_seqno.load(Ordering::Acquire), 4);
        assert_eq!(probe.destructor_errno.load(Ordering::Relaxed), libc::ENOTTY);
        let tid = probe.tid.load(Ordering::Acquire);
        assert!(tid > 0);
        assert_ne!(
            tid, parent_tid,
            "simultaneously live threads have distinct IDs"
        );
        let cards = probe.log.decision_cards_snapshot_sorted();
        assert_eq!(cards.len(), 4);
        assert_eq!(cards[0].thread_id, parent_tid);
        assert!(
            cards[1..].iter().all(|card| card.thread_id == tid),
            "thread identity must survive stack changes and Rust TLS destruction"
        );
        assert_eq!(probe.log.publication_loss_count(), 0);
        // SAFETY: disable this isolated subprocess's watchdog after its checks.
        unsafe { libc::alarm(0) };
    }
}

#[test]
fn incomplete_decisions_count_once_and_keep_the_hash_chain_after_recovery() {
    // The healthy stream also warms thread identity and hashing before failure
    // injection, and supplies an independent uninterrupted chain to compare.
    let healthy = SystematicEvidenceLog::<CAPACITY>::new(123);
    assert_eq!(record(&healthy), 1);
    assert_eq!(record(&healthy), 2);
    let expected = healthy.snapshot_sorted()[1];

    for fail_at in [0, 1, 2, 3, 4] {
        let log = SystematicEvidenceLog::<CAPACITY>::new(123);
        let (seqno, failure) = under_failure(fail_at, || record(&log));
        assert_eq!(seqno, 1);
        assert_eq!(failure.rejected, if fail_at == 0 { 2 } else { 1 });
        assert_eq!(log.publication_loss_count(), 1);
        assert_eq!(
            log.snapshot_sorted().len(),
            usize::from(fail_at >= 3),
            "evidence-ring partial publication, failure {fail_at}"
        );
        assert_eq!(
            log.decision_cards_snapshot_sorted().len(),
            usize::from(fail_at == 1 || fail_at == 2),
            "decision-card partial publication, failure {fail_at}"
        );

        assert_eq!(record(&log), 2);
        assert_eq!(log.publication_loss_count(), 1);
        let recovered = *log.snapshot_sorted().last().unwrap();
        assert_eq!(recovered.as_bytes(), expected.as_bytes());
        let cards = log.decision_cards_snapshot_sorted();
        assert_eq!(cards.last().unwrap().decision_id, 2);
        assert_eq!(cards.last().unwrap().evidence_seqno, 2);
    }
}

#[test]
fn kernel_reports_dropped_evidence_without_changing_the_decision() {
    let _ = std::thread::current();
    let ctx = RuntimeContext {
        family: ApiFamily::Allocator,
        addr_hint: 0xABCD,
        requested_bytes: 512 * 1024 * 1024,
        is_write: true,
        contention_hint: 3,
        bloom_negative: false,
    };
    let healthy = RuntimeMathKernel::new_for_mode(SafetyLevel::Strict);
    let expected = healthy.decide(SafetyLevel::Strict, ctx);
    let kernel = RuntimeMathKernel::new_for_mode(SafetyLevel::Strict);
    let (denied, failure) = under_failure(0, || kernel.decide(SafetyLevel::Strict, ctx));
    assert_eq!(failure.rejected, 2);
    assert_eq!(denied.action, MembraneAction::Deny);
    assert_eq!(denied.action, expected.action);
    assert_eq!(denied.profile, expected.profile);
    assert_eq!(denied.policy_id, expected.policy_id);
    assert_eq!(denied.risk_upper_bound_ppm, expected.risk_upper_bound_ppm);
    assert_eq!(denied.evidence_seqno, 1);
    let snapshot = kernel.evidence_contract_snapshot();
    assert_eq!(snapshot.evidence_seqno, 1);
    assert_eq!(snapshot.evidence_loss_count, 1);

    let recovered = kernel.decide(SafetyLevel::Strict, ctx);
    assert_eq!(recovered.action, denied.action);
    assert_eq!(recovered.profile, denied.profile);
    assert_eq!(recovered.evidence_seqno, 2);
    assert_eq!(kernel.evidence_contract_snapshot().evidence_loss_count, 1);
}

#[test]
fn failed_journal_replay_preserves_identifiers_and_reports_out_of_memory() {
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-evidence-replay-{}-{}.jsonl",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let source = SystematicEvidenceLog::<CAPACITY>::new(123);
    assert_eq!(source.enable_decision_card_journal(&path, 1).unwrap(), 0);
    for _ in 0..3 {
        record(&source);
    }
    source.flush_decision_card_journal_for_tests().unwrap();
    let last_original_card = *source.decision_cards_snapshot_sorted().last().unwrap();
    drop(source);

    // Measure this exact ring's buffer request. Reject only that layout during
    // replay, leaving the journal parser and its ordinary I/O buffers usable.
    let ring = DecisionCardRingBuffer::<CAPACITY>::new();
    let (_, measured) = under_failure(1, || ring.publish(1, card(1)));
    assert_eq!(measured.rejected, 1);
    let replay = SystematicEvidenceLog::<CAPACITY>::new(123);
    let (opened, failure) = under_sized_failure(0, measured.rejected_bytes, || {
        replay.enable_decision_card_journal(&path, 1)
    });
    assert_eq!(failure.rejected, 1);
    assert_eq!(opened.unwrap_err().kind(), std::io::ErrorKind::OutOfMemory);
    assert_eq!(
        replay.publication_loss_count(),
        0,
        "replay is not a new decision"
    );

    assert_eq!(record(&replay), 1);
    let cards = replay.decision_cards_snapshot_sorted();
    assert_eq!(cards.len(), 1);
    assert_eq!(cards[0].decision_id, last_original_card.decision_id + 1);
    assert!(cards[0].timestamp_mono_ns > last_original_card.timestamp_mono_ns);
    assert_eq!(replay.publication_loss_count(), 0);
    drop(replay);
}
