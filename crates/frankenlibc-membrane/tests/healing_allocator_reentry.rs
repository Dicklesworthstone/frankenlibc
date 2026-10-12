//! Real allocator-callback regression for the healing evidence path.
//!
//! Run with: cargo test -p frankenlibc-membrane --test healing_allocator_reentry
//! A separate executable is necessary because this test installs a global
//! allocator. The child is bounded so a recursive-lock regression fails the
//! test rather than hanging the whole test runner.

use frankenlibc_membrane::heal::{
    HealingAction, RepairLogContext, RuntimeSignalContext, append_runtime_log_record,
    global_healing_policy, initialize_runtime_log, install_signal_context_probe,
    runtime_log_snapshot,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};

const COUNT: u8 = 1;
const REENTER: u8 = 2;
const OUTER_RECORDS: usize = 1088; // exceeds the healing ring's 1024 rows
const CHILD_ENV: &str = "FRANKENLIBC_TEST_HEAL_ALLOCATOR_CHILD";
static MODE: AtomicU8 = AtomicU8::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static CALLBACKS: AtomicU64 = AtomicU64::new(0);
static IN_CALLBACK: AtomicBool = AtomicBool::new(false);
static SIGNAL_CONTEXT: AtomicU8 = AtomicU8::new(0);

fn test_signal_context() -> RuntimeSignalContext {
    match SIGNAL_CONTEXT.load(Ordering::Relaxed) {
        1 => RuntimeSignalContext::Inside,
        2 => RuntimeSignalContext::Unknown,
        _ => RuntimeSignalContext::Outside,
    }
}

struct ReenteringAllocator;

fn callback(allocating: bool) {
    let mode = MODE.load(Ordering::Relaxed);
    if mode & COUNT != 0 && allocating {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
    }
    if mode & REENTER == 0 || IN_CALLBACK.swap(true, Ordering::Relaxed) {
        return;
    }
    CALLBACKS.fetch_add(1, Ordering::Relaxed);
    global_healing_policy().record(
        "allocator",
        "free",
        &HealingAction::IgnoreForeignFree,
        RepairLogContext::new(0, None),
    );
    IN_CALLBACK.store(false, Ordering::Relaxed);
}

// SAFETY: every allocation operation is forwarded unchanged to System, with
// exactly the caller's pointer, layout and new size. The callback neither
// reads nor takes ownership of caller memory. No assertion/panic is performed
// in the allocator; all observations are checked after disabling the hook.
unsafe impl GlobalAlloc for ReenteringAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        callback(true);
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        callback(true);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        callback(true);
        unsafe { System.realloc(ptr, layout, size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        callback(false);
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: ReenteringAllocator = ReenteringAllocator;

fn child_probe() {
    // No previous call to the global healing policy in this process. The
    // pre-fix LazyLock + VecDeque::with_capacity performed an allocation here.
    ALLOCATIONS.store(0, Ordering::Relaxed);
    MODE.store(COUNT, Ordering::Relaxed);
    let policy = std::hint::black_box(global_healing_policy());
    MODE.store(0, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "first policy access allocated"
    );
    policy.set_healing_logging_enabled(true);
    initialize_runtime_log();

    // Initialization may allocate. After opening, the actual write path must
    // not allocate a String just to add a newline or call through libc write.
    append_runtime_log_record("{\"warmup\":true}");
    let before = runtime_log_snapshot();
    assert_eq!(before.written_records, 1);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    MODE.store(COUNT, Ordering::Relaxed);
    append_runtime_log_record("{\"probe\":true}");
    MODE.store(0, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "initialized sink allocated"
    );
    assert_eq!(runtime_log_snapshot().written_records, 2);

    // The signal-selected repair producer must bypass heap-backed formatting,
    // the evidence ledger, and the diagnostic ring. Its sole output is the
    // preopened raw-fd JSONL record.
    install_signal_context_probe(test_signal_context);
    ALLOCATIONS.store(0, Ordering::Relaxed);
    MODE.store(COUNT, Ordering::Relaxed);
    SIGNAL_CONTEXT.store(1, Ordering::Relaxed);
    policy.record(
        "string_memory",
        "strlen",
        &HealingAction::ReturnSafeDefault,
        RepairLogContext::new(0, Some(0)),
    );
    SIGNAL_CONTEXT.store(0, Ordering::Relaxed);
    MODE.store(0, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "signal-selected repair path allocated"
    );
    assert!(policy.export_healing_log_jsonl().is_empty());
    assert_eq!(runtime_log_snapshot().written_records, 3);

    // A bounded ABI slot lookup can fail without proving that execution is
    // outside a signal handler. Force that exact unknown result: it must take
    // the same allocation/TLS-free path while reporting the uncertainty
    // honestly instead of fabricating signal_context=false as known fact.
    ALLOCATIONS.store(0, Ordering::Relaxed);
    MODE.store(COUNT, Ordering::Relaxed);
    SIGNAL_CONTEXT.store(2, Ordering::Relaxed);
    policy.record(
        "string_memory",
        "memcpy",
        &HealingAction::ClampSize {
            requested: 8,
            clamped: 0,
        },
        RepairLogContext::new(0, Some(0)),
    );
    SIGNAL_CONTEXT.store(0, Ordering::Relaxed);
    MODE.store(0, Ordering::Relaxed);
    assert_eq!(
        ALLOCATIONS.load(Ordering::Relaxed),
        0,
        "unknown signal context entered the allocating evidence path"
    );
    assert!(policy.export_healing_log_jsonl().is_empty());
    assert_eq!(runtime_log_snapshot().written_records, 4);

    // Exercise first ring growth, ledger initialization, formatting, eviction,
    // export allocations and clear-time deallocation. Each real allocator
    // callback records a nested repair. Missing any of the guards can try to
    // acquire a ring/ledger lock that the interrupted outer operation holds.
    MODE.store(REENTER, Ordering::Relaxed);
    for size in 0..OUTER_RECORDS {
        policy.record(
            "allocator",
            "realloc",
            &HealingAction::ReallocAsMalloc { size },
            RepairLogContext::new(0, None),
        );
    }
    let rows = policy.export_healing_log_jsonl();
    policy.clear_healing_logs();
    MODE.store(0, Ordering::Relaxed);

    assert!(
        CALLBACKS.load(Ordering::Relaxed) > 0,
        "allocator injector never ran"
    );
    assert!(policy.healing_log_reentry_drops.load(Ordering::Relaxed) > 0);
    assert_eq!(rows.lines().count(), 1024);
    for (index, line) in rows.lines().enumerate() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(row["healing_action"], "ReallocAsMalloc");
        assert_eq!(
            row["details"]["size"].as_u64(),
            Some((OUTER_RECORDS - 1024 + index) as u64)
        );
    }
    assert!(policy.export_healing_log_jsonl().is_empty());
    // The guard must have been restored, not left permanently suppressing logs.
    policy.record(
        "allocator",
        "free",
        &HealingAction::ReturnSafeDefault,
        RepairLogContext::new(0, None),
    );
    let last = policy.export_healing_log_jsonl();
    let row: serde_json::Value = serde_json::from_str(&last).unwrap();
    assert_eq!(row["healing_action"], "ReturnSafeDefault");
    let sink = runtime_log_snapshot();
    let attempted_records = OUTER_RECORDS as u64 + 5;
    assert_eq!(
        sink.written_records + sink.dropped_records,
        attempted_records
    );
    assert_eq!(
        sink.dropped_records,
        sink.rate_limited_records + sink.admission_clock_failures
    );
    assert_eq!(sink.short_writes, 0);
    assert_eq!(sink.open_failures, 0);
}

#[test]
fn allocator_callbacks_do_not_reenter_evidence_locks() {
    if std::env::var_os(CHILD_ENV).is_some() {
        child_probe();
        return;
    }

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "frankenlibc-allocator-reentry-{}-{stamp}.jsonl",
        std::process::id()
    ));
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "allocator_callbacks_do_not_reenter_evidence_locks",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, "1")
        .env("FRANKENLIBC_MODE", "hardened")
        .env("FRANKENLIBC_HEAL_LOG", "1")
        .env("FRANKENLIBC_LOG", &path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("healing allocator callback deadlocked; child exceeded 30 seconds");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "child failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let contents = std::fs::read_to_string(path).unwrap();
    assert!(contents.ends_with('\n'));
    let rows: Vec<serde_json::Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).expect("damaged runtime JSONL"))
        .collect();
    assert!((1024..=OUTER_RECORDS + 5).contains(&rows.len()));
    assert_eq!(rows[0]["warmup"], true);
    assert_eq!(rows[1]["probe"], true);
    assert_eq!(rows[2]["api_family"], "string_memory");
    assert_eq!(rows[2]["symbol"], "strlen");
    assert_eq!(rows[2]["healing_action"], "ReturnSafeDefault");
    assert_eq!(rows[2]["signal_context"], true);
    assert_eq!(rows[2]["signal_context_known"], true);
    assert_eq!(rows[3]["api_family"], "string_memory");
    assert_eq!(rows[3]["symbol"], "memcpy");
    assert_eq!(rows[3]["healing_action"], "ClampSize");
    assert_eq!(rows[3]["signal_context"], false);
    assert_eq!(rows[3]["signal_context_known"], false);
    let mut previous_size = None;
    for (index, row) in rows[4..].iter().enumerate() {
        if row["healing_action"] == "ReturnSafeDefault" {
            assert_eq!(index + 4, rows.len() - 1);
            continue;
        }
        assert_eq!(row["healing_action"], "ReallocAsMalloc");
        let size = row["details"]["size"].as_u64().unwrap();
        if let Some(previous) = previous_size {
            assert!(size > previous);
        }
        previous_size = Some(size);
    }
}
