//! Self-healing policy engine.
//!
//! When the membrane detects an invalid operation, instead of crashing or
//! invoking undefined behavior, it applies a deterministic healing action.
//! Every libc function has defined healing for every class of invalid input.

#[path = "runtime_log.rs"]
mod runtime_log;
pub use runtime_log::{RuntimeLogSnapshot, next_runtime_log_sequence, runtime_log_snapshot};

use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION};
use crate::util::NoPoisonMutex as Mutex;
use std::collections::VecDeque;
use std::fmt::{self, Write as _};
use std::sync::atomic::{AtomicI32, AtomicU8, AtomicU64, AtomicUsize, Ordering};

/// Actions the membrane can take to heal an unsafe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealingAction {
    /// Clamp a size/length parameter to fit within known bounds.
    ClampSize { requested: usize, clamped: usize },
    /// Truncate output and ensure null termination for string ops.
    TruncateWithNull { requested: usize, truncated: usize },
    /// Silently ignore a double-free (already freed pointer).
    IgnoreDoubleFree,
    /// Silently ignore a free of a pointer we don't own.
    IgnoreForeignFree,
    /// Treat realloc of a freed/unknown pointer as malloc.
    ReallocAsMalloc { size: usize },
    /// Return a safe default value instead of performing the operation.
    ReturnSafeDefault,
    /// Upgrade a known-unsafe function call to its safe variant.
    /// e.g., strcpy -> strncpy with bounds.
    UpgradeToSafeVariant,
    /// No healing needed — operation is valid.
    None,
}

impl HealingAction {
    /// Returns true if this action represents an actual healing (not None).
    #[must_use]
    pub const fn is_heal(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Explicit provenance attached to a repair evidence row.
///
/// `errno` is the value selected by the repair decision itself. Zero means
/// that the decision selected no errno; the ambient thread-local errno is
/// never sampled or cleared. `address`, when present, is the primary address
/// implicated by the repair. It is intentionally optional because some
/// repairs concern only scalar arguments, and it is not complete provenance
/// for operations involving multiple pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairLogContext {
    pub errno: i32,
    pub address: Option<usize>,
}

impl RepairLogContext {
    #[must_use]
    pub const fn new(errno: i32, address: Option<usize>) -> Self {
        Self { errno, address }
    }
}

const HEALING_LOG_CAPACITY: usize = 1024;
const HEALING_BEAD_ID: &str = "bd-32e.4";

thread_local! {
    // Guard the WHOLE evidence operation, not just its final file write.
    // Formatting, ledger initialization, ring growth, and dropping old rows
    // can all enter the interposed allocator/string functions and heal again.
    static EMITTING_HEALING_LOG: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static WRITING_RUNTIME_LOG: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

// The ABI owns the signal trampoline and its fixed, atomically keyed
// per-thread marker. Keeping only a function pointer here avoids touching
// Rust's global-dynamic TLS while executing a signal handler.
static SIGNAL_CONTEXT_PROBE: AtomicUsize = AtomicUsize::new(0);

const RUNTIME_LOG_BUFFER_BYTES: usize = 1024;

/// Fixed-capacity JSONL record buffer. Formatting through `core::fmt::Write`
/// copies only into these stack bytes; it never grows or allocates.
pub struct RuntimeLogBuffer {
    bytes: [std::mem::MaybeUninit<u8>; RUNTIME_LOG_BUFFER_BYTES],
    len: usize,
}

impl RuntimeLogBuffer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // Leaving the backing bytes uninitialized is load-bearing: zeroing
            // a 1 KiB array lowers to this DSO's interposed `memset`, which can
            // enter validation TLS in a signal handler.
            bytes: [std::mem::MaybeUninit::uninit(); RUNTIME_LOG_BUFFER_BYTES],
            len: 0,
        }
    }

    #[must_use]
    #[allow(unsafe_code)]
    pub fn as_str(&self) -> &str {
        // SAFETY: `write_str` initializes exactly `0..len` from valid UTF-8
        // fragments and advances `len` only after all bytes are stored.
        let initialized =
            unsafe { std::slice::from_raw_parts(self.bytes.as_ptr().cast::<u8>(), self.len) };
        // SAFETY: concatenating valid UTF-8 fragments remains valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(initialized) }
    }
}

impl Default for RuntimeLogBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Write for RuntimeLogBuffer {
    #[allow(unsafe_code)]
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let Some(end) = self.len.checked_add(value.len()) else {
            return Err(fmt::Error);
        };
        // Keep one byte of headroom for the newline written by writev.
        if end >= self.bytes.len() {
            return Err(fmt::Error);
        }
        // A normal slice copy can lower to this DSO's interposed `memcpy`,
        // which enters validation TLS before it notices signal context. Keep
        // this tiny adverse-event path compiler-proof and leaf-like: volatile
        // byte stores cannot be coalesced into a libc call.
        for (offset, byte) in value.bytes().enumerate() {
            // SAFETY: `end < self.bytes.len()` above proves every indexed byte
            // lies inside the fixed buffer, and `&mut self` gives unique access.
            unsafe {
                std::ptr::write_volatile(
                    self.bytes.as_mut_ptr().add(self.len + offset).cast::<u8>(),
                    byte,
                );
            }
        }
        self.len = end;
        Ok(())
    }
}

/// Write one JSON string, including quotes, without allocating.
pub fn write_runtime_log_json_string(output: &mut impl fmt::Write, value: &str) -> fmt::Result {
    output.write_char('"')?;
    for character in value.chars() {
        match character {
            '"' => output.write_str("\\\"")?,
            '\\' => output.write_str("\\\\")?,
            '\u{08}' => output.write_str("\\b")?,
            '\u{0c}' => output.write_str("\\f")?,
            '\n' => output.write_str("\\n")?,
            '\r' => output.write_str("\\r")?,
            '\t' => output.write_str("\\t")?,
            control if control <= '\u{1f}' => {
                write!(output, "\\u{:04x}", control as u32)?;
            }
            printable => output.write_char(printable)?,
        }
    }
    output.write_char('"')
}

/// What the allocation-free ABI probe knows about the calling context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeSignalContext {
    Outside,
    Inside,
    /// The bounded allocator-slot lookup could not identify the thread.
    Unknown,
}

impl RuntimeSignalContext {
    /// Unknown context takes the same allocation/TLS-free path as a confirmed
    /// signal handler; only `Outside` may enter normal logging machinery.
    #[must_use]
    pub const fn requires_signal_safe_path(self) -> bool {
        !matches!(self, Self::Outside)
    }

    #[must_use]
    const fn is_inside(self) -> bool {
        matches!(self, Self::Inside)
    }

    #[must_use]
    const fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Install the allocation-free ABI probe that classifies whether the calling
/// thread is currently executing a user signal handler. Startup must install
/// it before user code can register or run handlers.
pub fn install_signal_context_probe(probe: fn() -> RuntimeSignalContext) {
    SIGNAL_CONTEXT_PROBE.store(probe as *const () as usize, Ordering::Release);
}

#[inline]
#[allow(unsafe_code)]
fn runtime_signal_context() -> RuntimeSignalContext {
    let address = SIGNAL_CONTEXT_PROBE.load(Ordering::Acquire);
    if address == 0 {
        return RuntimeSignalContext::Outside;
    }
    // SAFETY: `install_signal_context_probe` stores only a live function with
    // this exact signature, and the ABI that installs it remains loaded for
    // the life of this membrane instance.
    let probe = unsafe { std::mem::transmute::<usize, fn() -> RuntimeSignalContext>(address) };
    probe()
}

/// Read the startup-installed signal-context probe without allocation, locks,
/// environment access, or Rust TLS.
#[must_use]
pub fn runtime_log_signal_context() -> RuntimeSignalContext {
    runtime_signal_context()
}

/// A thread-bound reentry guard. A rejected nested entry must not clear the
/// outer operation's flag. Drop also restores the flag on an unwind.
struct LogReentryGuard {
    flag: &'static std::thread::LocalKey<std::cell::Cell<bool>>,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl LogReentryGuard {
    fn enter(flag: &'static std::thread::LocalKey<std::cell::Cell<bool>>) -> Option<Self> {
        flag.try_with(|active| {
            if active.replace(true) {
                None
            } else {
                Some(Self {
                    flag,
                    _not_send: std::marker::PhantomData,
                })
            }
        })
        .ok()
        .flatten()
    }
}

impl Drop for LogReentryGuard {
    fn drop(&mut self) {
        let _ = self.flag.try_with(|active| active.set(false));
    }
}

/// Policy engine that decides which healing action to apply.
pub struct HealingPolicy {
    /// Total heals applied.
    pub total_heals: AtomicU64,
    /// Size clamps applied.
    pub size_clamps: AtomicU64,
    /// Null truncations applied.
    pub null_truncations: AtomicU64,
    /// Double frees ignored.
    pub double_frees: AtomicU64,
    /// Foreign frees ignored.
    pub foreign_frees: AtomicU64,
    /// Reallocs treated as malloc.
    pub realloc_as_mallocs: AtomicU64,
    /// Safe defaults returned.
    pub safe_defaults: AtomicU64,
    /// Safe variant upgrades.
    pub variant_upgrades: AtomicU64,
    /// Repairs counted but not logged because this thread was already
    /// generating evidence (or its TLS was unavailable during teardown).
    pub healing_log_reentry_drops: AtomicU64,
    /// Structured healing logging: 0 = follow `FRANKENLIBC_HEAL_LOG`
    /// (resolved lazily), 1 = forced off, 2 = forced on.
    healing_logging: AtomicU8,
    /// Monotone decision id for healing evidence rows.
    healing_log_decision_seq: AtomicU64,
    /// Bounded JSONL healing evidence ring buffer.
    healing_logs: Mutex<VecDeque<String>>,
}

impl HealingPolicy {
    /// Create a policy without allocating, reading the environment, or
    /// entering libc. It must be usable from the very first allocation heal.
    #[must_use]
    pub const fn new() -> Self {
        // VecDeque::with_capacity here allocated while GLOBAL_POLICY's old
        // LazyLock was initializing. A repair during that allocation tried
        // to initialize the same LazyLock and deadlocked. Allocate the ring
        // only when emitting, after the reentry guard is established.
        Self {
            total_heals: AtomicU64::new(0),
            size_clamps: AtomicU64::new(0),
            null_truncations: AtomicU64::new(0),
            double_frees: AtomicU64::new(0),
            foreign_frees: AtomicU64::new(0),
            realloc_as_mallocs: AtomicU64::new(0),
            safe_defaults: AtomicU64::new(0),
            variant_upgrades: AtomicU64::new(0),
            healing_log_reentry_drops: AtomicU64::new(0),
            healing_logging: AtomicU8::new(0),
            healing_log_decision_seq: AtomicU64::new(0),
            healing_logs: Mutex::new(VecDeque::new()),
        }
    }

    /// Enable or disable structured healing evidence logging.
    pub fn set_healing_logging_enabled(&self, enabled: bool) {
        self.healing_logging
            .store(if enabled { 2 } else { 1 }, Ordering::Relaxed);
    }

    #[inline]
    fn healing_logging_active(&self) -> bool {
        match self.healing_logging.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => heal_logging_env_enabled(),
        }
    }

    /// This policy's counters and process-wide runtime-file sink counters as
    /// the fields of one JSON object (no braces), also used by exit summaries.
    #[must_use]
    pub fn counters_json_fields(&self) -> String {
        let mut fields = String::new();
        let _ = self.write_counters_json_fields(&mut fields);
        fields
    }

    /// Write the counter fields without requiring a heap-backed destination.
    pub fn write_counters_json_fields(&self, output: &mut impl fmt::Write) -> fmt::Result {
        let _guard = LogReentryGuard::enter(&EMITTING_HEALING_LOG);
        let n = |c: &AtomicU64| c.load(Ordering::Relaxed);
        let sink = runtime_log_snapshot();
        write!(
            output,
            "\"total_heals\":{},\"size_clamps\":{},\"null_truncations\":{},\
\"double_frees\":{},\"foreign_frees\":{},\"realloc_as_mallocs\":{},\
\"safe_defaults\":{},\"variant_upgrades\":{},\"healing_log_reentry_drops\":{},\
\"runtime_log_written_records\":{},\"runtime_log_dropped_records\":{},\
\"runtime_log_rate_limited_records\":{},\"runtime_log_admission_clock_failures\":{},\
\"runtime_log_short_writes\":{},\
\"runtime_log_open_failures\":{}",
            n(&self.total_heals),
            n(&self.size_clamps),
            n(&self.null_truncations),
            n(&self.double_frees),
            n(&self.foreign_frees),
            n(&self.realloc_as_mallocs),
            n(&self.safe_defaults),
            n(&self.variant_upgrades),
            n(&self.healing_log_reentry_drops),
            sink.written_records,
            sink.dropped_records,
            sink.rate_limited_records,
            sink.admission_clock_failures,
            sink.short_writes,
            sink.open_failures,
        )
    }

    /// Clear buffered healing evidence rows. A recursive diagnostic request
    /// is ignored rather than attempting to acquire a lock already held here.
    pub fn clear_healing_logs(&self) {
        let Some(_guard) = LogReentryGuard::enter(&EMITTING_HEALING_LOG) else {
            return;
        };
        self.healing_logs.lock().clear();
    }

    /// Export buffered healing evidence as deterministic JSONL. Recursive
    /// export returns an empty snapshot instead of locking the active writer.
    #[must_use]
    pub fn export_healing_log_jsonl(&self) -> String {
        let Some(_guard) = LogReentryGuard::enter(&EMITTING_HEALING_LOG) else {
            return String::new();
        };
        self.healing_logs
            .lock()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Record a healing action.
    ///
    /// @separation-pre: `Owns(HealingCounters) * Action(action)` with frame `F`.
    /// @separation-post: `Owns(HealingCounters')` where only relevant counters advance;
    /// frame `F` is preserved.
    /// @separation-frame: `F` (non-counter memory is untouched).
    /// @separation-alias: `repair_apply`.
    pub fn record(
        &self,
        api_family: &'static str,
        symbol: &'static str,
        action: &HealingAction,
        context: RepairLogContext,
    ) {
        if action.is_heal() {
            self.total_heals.fetch_add(1, Ordering::Relaxed);
        }

        match action {
            HealingAction::ClampSize { .. } => {
                self.size_clamps.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::TruncateWithNull { .. } => {
                self.null_truncations.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::IgnoreDoubleFree => {
                self.double_frees.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::IgnoreForeignFree => {
                self.foreign_frees.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::ReallocAsMalloc { .. } => {
                self.realloc_as_mallocs.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::ReturnSafeDefault => {
                self.safe_defaults.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::UpgradeToSafeVariant => {
                self.variant_upgrades.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::None => {}
        }

        self.emit_healing_log(api_family, symbol, action, context);
    }

    /// Decide healing for a copy/memory operation with bounds.
    #[must_use]
    pub fn heal_copy_bounds(
        &self,
        requested: usize,
        src_remaining: Option<usize>,
        dst_remaining: Option<usize>,
    ) -> HealingAction {
        let available = match (src_remaining, dst_remaining) {
            (Some(s), Some(d)) => s.min(d),
            (Some(s), None) => s,
            (None, Some(d)) => d,
            (None, None) => return HealingAction::None,
        };

        if requested > available {
            HealingAction::ClampSize {
                requested,
                clamped: available,
            }
        } else {
            HealingAction::None
        }
    }

    /// Decide healing for a string operation with destination bounds.
    #[must_use]
    pub fn heal_string_bounds(
        &self,
        src_len: usize,
        dst_remaining: Option<usize>,
    ) -> HealingAction {
        match dst_remaining {
            Some(0) => HealingAction::ClampSize {
                requested: src_len,
                clamped: 0,
            },
            Some(remaining) if src_len >= remaining => HealingAction::TruncateWithNull {
                requested: src_len,
                truncated: remaining.saturating_sub(1), // leave room for null
            },
            _ => HealingAction::None,
        }
    }

    fn emit_healing_log(
        &self,
        api_family: &'static str,
        symbol: &'static str,
        action: &HealingAction,
        context: RepairLogContext,
    ) {
        if !action.is_heal() {
            return;
        }
        let signal_context = runtime_signal_context();
        let signal_safe_path = signal_context.requires_signal_safe_path();
        if signal_safe_path {
            match RUNTIME_LOG_FD.load(Ordering::Acquire) {
                0.. => {}
                RUNTIME_LOG_UNINITIALIZED | RUNTIME_LOG_INITIALIZING => {
                    runtime_log::note_dropped();
                    return;
                }
                _ => return,
            }
        }
        // Never touch global-dynamic Rust TLS from a signal handler. Signal
        // records use only their stack buffer, atomics, and one O_APPEND
        // writev; nested/concurrent handlers therefore need no shared guard.
        let _thread_guard = if signal_safe_path {
            None
        } else {
            let guard = LogReentryGuard::enter(&EMITTING_HEALING_LOG);
            if guard.is_none() {
                self.healing_log_reentry_drops
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            guard
        };
        // FRANKENLIBC_HEAL_LOG controls only the heap-backed diagnostic
        // ledger/ring. The deployed FRANKENLIBC_LOG sink is independent: when
        // configured, it must receive every repair even if the mirror is off.
        let mirror_active = !signal_safe_path && self.healing_logging_active();
        let runtime_sink_active = if signal_safe_path {
            true
        } else {
            initialize_runtime_log_fd() >= 0
        };
        if !mirror_active && !runtime_sink_active {
            return;
        }

        let decision_id = DecisionId::from_raw(
            self.healing_log_decision_seq
                .fetch_add(1, Ordering::Relaxed)
                + 1,
        );
        let event_seq = next_runtime_log_sequence();
        let runtime_mode = runtime_mode_label();
        let mut line = RuntimeLogBuffer::new();
        if write_healing_log_line(
            &mut line,
            RepairLogRecord {
                event_seq,
                decision_id,
                api_family,
                symbol,
                action,
                context,
                runtime_mode,
                signal_context: signal_context.is_inside(),
                signal_context_known: signal_context.is_known(),
            },
        )
        .is_err()
        {
            runtime_log::note_dropped();
            return;
        }
        if runtime_sink_active {
            append_to_runtime_log(line.as_str());
        }

        // A signal handler may have interrupted either allocator or evidence
        // lock ownership on this thread. The deployed JSONL record above is
        // complete; do not enter the heap-backed diagnostic mirrors here.
        if signal_safe_path {
            return;
        }

        if mirror_active {
            let trace_id = decision_id.scoped_trace_id("membrane::heal");
            crate::evidence_ledger::global_evidence_ledger().record_healing(
                action,
                trace_id,
                decision_id,
                api_family,
                symbol,
            );
            self.push_healing_log_line(line.as_str().to_owned());
        }
    }

    fn push_healing_log_line(&self, line: String) {
        let mut logs = self.healing_logs.lock();
        while logs.len() >= HEALING_LOG_CAPACITY {
            let _ = logs.pop_front();
        }
        logs.push_back(line);
    }
}

impl Default for HealingPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// `FRANKENLIBC_HEAL_LOG`, resolved once and reentrancy-safe: a heal recorded
/// while the variable is being read (the read itself runs fl string ops)
/// sees "off" instead of recursing.
// 0 = unresolved, 1 = resolving, 2 = off, 3 = on.
static HEALING_LOG_STATE: AtomicU8 = AtomicU8::new(0);

fn heal_logging_env_enabled() -> bool {
    match HEALING_LOG_STATE.load(Ordering::Acquire) {
        2 | 1 => false,
        3 => true,
        _ => {
            if HEALING_LOG_STATE
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return HEALING_LOG_STATE.load(Ordering::Acquire) == 3;
            }
            let on = heal_logging_enabled_by_default();
            HEALING_LOG_STATE.store(if on { 3 } else { 2 }, Ordering::Release);
            on
        }
    }
}

fn heal_logging_enabled_by_default() -> bool {
    match std::env::var("FRANKENLIBC_HEAL_LOG") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

const RUNTIME_LOG_UNINITIALIZED: i32 = -3;
const RUNTIME_LOG_INITIALIZING: i32 = -2;
const RUNTIME_LOG_DISABLED: i32 = -1;

/// Owned process-wide `FRANKENLIBC_LOG` descriptor. Non-negative values are
/// live descriptors; negative values are explicit initialization states.
static RUNTIME_LOG_FD: AtomicI32 = AtomicI32::new(RUNTIME_LOG_UNINITIALIZED);

/// Resolve logging controls and open the runtime sink before user code can
/// install a signal handler. Safe to call repeatedly.
pub fn initialize_runtime_log() {
    // Repair rows include runtime_mode; resolve its environment-backed cache
    // here so signal-time formatting is an atomic read only.
    let _ = crate::config::safety_level();
    let _ = heal_logging_env_enabled();
    let _ = initialize_runtime_log_fd();
}

fn initialize_runtime_log_fd() -> i32 {
    let current = RUNTIME_LOG_FD.load(Ordering::Acquire);
    if current != RUNTIME_LOG_UNINITIALIZED {
        return current;
    }
    if RUNTIME_LOG_FD
        .compare_exchange(
            RUNTIME_LOG_UNINITIALIZED,
            RUNTIME_LOG_INITIALIZING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return RUNTIME_LOG_FD.load(Ordering::Acquire);
    }

    let fd = std::env::var_os("FRANKENLIBC_LOG")
        .filter(|path| !path.is_empty())
        .and_then(|path| runtime_log::open_fd(&path))
        .unwrap_or(RUNTIME_LOG_DISABLED);
    RUNTIME_LOG_FD.store(fd, Ordering::Release);
    fd
}

/// Append to a configured regular file. Linux writes borrow the record and
/// newline in one raw writev, rather than allocating another String or calling
/// back into the interposed write/cancellation path. Oversized and failed
/// writes are counted; positive short writes are never retried piecemeal.
fn append_to_runtime_log(line: &str) {
    append_to_runtime_log_with_limit(line, true);
}

fn append_to_runtime_log_with_limit(line: &str, rate_limited: bool) {
    let signal_safe_path = runtime_signal_context().requires_signal_safe_path();
    let fd = if signal_safe_path {
        RUNTIME_LOG_FD.load(Ordering::Acquire)
    } else {
        let Some(_guard) = LogReentryGuard::enter(&WRITING_RUNTIME_LOG) else {
            runtime_log::note_dropped();
            return;
        };
        return append_to_runtime_log_with_fd(initialize_runtime_log_fd(), line, rate_limited);
    };
    append_to_runtime_log_with_fd(fd, line, rate_limited);
}

fn append_to_runtime_log_with_fd(fd: i32, line: &str, rate_limited: bool) {
    match fd {
        0.. if !rate_limited || runtime_log::admit_record() => runtime_log::append_fd(fd, line),
        0.. => {}
        RUNTIME_LOG_DISABLED => runtime_log::note_unavailable(),
        RUNTIME_LOG_UNINITIALIZED | RUNTIME_LOG_INITIALIZING => runtime_log::note_dropped(),
        _ => runtime_log::note_dropped(),
    }
}

/// Append one JSONL record to the `FRANKENLIBC_LOG` file, if one is set:
/// the sink for evidence produced outside the healing policy (membrane
/// denials, the process-exit counter summary).
pub fn append_runtime_log_record(line: &str) {
    append_to_runtime_log(line);
}

/// Append the one process-exit summary without consuming the adverse-event
/// rate budget. This record must remain observable because it reports how many
/// repair/deny rows the limiter suppressed.
pub fn append_runtime_log_summary_record(line: &str) {
    append_to_runtime_log_with_limit(line, false);
}

/// Whether startup opened a live runtime evidence sink.
#[must_use]
pub fn runtime_log_is_configured() -> bool {
    RUNTIME_LOG_FD.load(Ordering::Acquire) >= 0
}

/// Account for a record that could not be formatted or emitted.
pub fn note_runtime_log_drop() {
    runtime_log::note_dropped();
}

/// Reopen an already-initialized runtime evidence sink in a freshly forked
/// child.
///
/// A disabled sink remains disabled. Only an inherited live file is reopened,
/// so the child gets a distinct open file description and observes path
/// rotation independently of the parent.
///
/// # Safety
///
/// This must run only in the freshly forked, single-threaded child after the
/// allocator and membrane fork guards have been released. The surviving
/// thread must not be inside [`append_runtime_log_record`] or
/// [`HealingPolicy::record`]. Callers currently do not mask signals across the
/// clone-to-reopen interval, so a pending handler can still emit one record to
/// the inherited descriptor before this function runs.
#[allow(unsafe_code)]
pub unsafe fn reopen_runtime_log_in_fork_child() {
    let inherited = RUNTIME_LOG_FD.load(Ordering::Acquire);
    if inherited < 0 {
        return;
    }

    let reopened = std::env::var_os("FRANKENLIBC_LOG")
        .filter(|path| !path.is_empty())
        .and_then(|path| runtime_log::open_fd(&path))
        .unwrap_or(RUNTIME_LOG_DISABLED);
    let replaced = RUNTIME_LOG_FD.swap(reopened, Ordering::AcqRel);
    runtime_log::reset_rate_limit_after_fork();
    runtime_log::close_fd(replaced);
}

#[cfg(test)]
fn append_line(file: &std::fs::File, line: &str) {
    runtime_log::append_line(file, line);
}

/// Process id used in stack-formatted deployed records.
#[must_use]
pub fn runtime_log_process_id() -> u32 {
    runtime_log::process_id()
}

fn healing_log_level(action: &HealingAction) -> &'static str {
    if healing_action_escalated(action) {
        "warn"
    } else {
        "info"
    }
}

fn healing_action_escalated(action: &HealingAction) -> bool {
    matches!(
        action,
        HealingAction::ReturnSafeDefault | HealingAction::UpgradeToSafeVariant
    )
}

fn runtime_mode_label() -> &'static str {
    match crate::config::safety_level() {
        crate::config::SafetyLevel::Strict => "strict",
        crate::config::SafetyLevel::Hardened => "hardened",
        crate::config::SafetyLevel::Off => "off",
    }
}

fn healing_action_name(action: &HealingAction) -> &'static str {
    match action {
        HealingAction::ClampSize { .. } => "ClampSize",
        HealingAction::TruncateWithNull { .. } => "TruncateWithNull",
        HealingAction::IgnoreDoubleFree => "IgnoreDoubleFree",
        HealingAction::IgnoreForeignFree => "IgnoreForeignFree",
        HealingAction::ReallocAsMalloc { .. } => "ReallocAsMalloc",
        HealingAction::ReturnSafeDefault => "ReturnSafeDefault",
        HealingAction::UpgradeToSafeVariant => "UpgradeToSafeVariant",
        HealingAction::None => "None",
    }
}

fn write_healing_action_details(
    output: &mut impl fmt::Write,
    action: &HealingAction,
) -> fmt::Result {
    match action {
        HealingAction::ClampSize { requested, clamped } => {
            write!(
                output,
                "{{\"requested\":{requested},\"clamped\":{clamped}}}"
            )
        }
        HealingAction::TruncateWithNull {
            requested,
            truncated,
        } => {
            write!(
                output,
                "{{\"requested\":{requested},\"truncated\":{truncated}}}"
            )
        }
        HealingAction::ReallocAsMalloc { size } => {
            write!(output, "{{\"size\":{size}}}")
        }
        HealingAction::IgnoreDoubleFree
        | HealingAction::IgnoreForeignFree
        | HealingAction::ReturnSafeDefault
        | HealingAction::UpgradeToSafeVariant
        | HealingAction::None => output.write_str("{}"),
    }
}

struct RepairLogRecord<'a> {
    event_seq: u64,
    decision_id: DecisionId,
    api_family: &'static str,
    symbol: &'static str,
    action: &'a HealingAction,
    context: RepairLogContext,
    runtime_mode: &'static str,
    signal_context: bool,
    signal_context_known: bool,
}

fn write_healing_log_line(
    output: &mut RuntimeLogBuffer,
    record: RepairLogRecord<'_>,
) -> fmt::Result {
    let RepairLogRecord {
        event_seq,
        decision_id,
        api_family,
        symbol,
        action,
        context,
        runtime_mode,
        signal_context,
        signal_context_known,
    } = record;
    let level = healing_log_level(action);
    let escalated = healing_action_escalated(action);
    write!(
        output,
        "{{\"event\":\"repair\",\"seq\":{event_seq},\"trace_id\":\"membrane::heal::{:016x}\",\
\"decision_id\":{},\"schema_version\":\"{}\",\"pid\":{},\"bead_id\":\"{HEALING_BEAD_ID}\",\
\"runtime_mode\":\"{}\",\"level\":\"{level}\",\"api_family\":",
        decision_id.as_u64(),
        decision_id.as_u64(),
        MEMBRANE_SCHEMA_VERSION,
        runtime_log_process_id(),
        runtime_mode,
    )?;
    write_runtime_log_json_string(output, api_family)?;
    output.write_str(",\"symbol\":")?;
    write_runtime_log_json_string(output, symbol)?;
    write!(
        output,
        ",\"action\":\"Repair\",\"decision_path\":\"record\",\"outcome\":\"repair\",\
\"healing_action\":\"{}\",\"escalated\":{escalated},\"errno\":{}",
        healing_action_name(action),
        context.errno,
    )?;
    if runtime_mode == "hardened"
        && let Some(address) = context.address
    {
        write!(output, ",\"address\":\"{address:#x}\"")?;
    }
    write!(
        output,
        ",\"signal_context\":{signal_context},\"signal_context_known\":{signal_context_known},\"details\":"
    )?;
    write_healing_action_details(output, action)?;
    output.write_str("}")
}

/// Recommended default healing action for a Gröbner canonical root-cause class.
///
/// This maps the reduced root-cause classification from sparse recovery into
/// a deterministic healing suggestion. The mapping is advisory — callers may
/// override based on mode/context. No unsafe semantic changes are made.
#[must_use]
pub fn recommended_healing_for_canonical_class(class_id: u8) -> HealingAction {
    use crate::grobner;

    match class_id {
        grobner::CANONICAL_CLASS_NONE => HealingAction::None,
        // Temporal/provenance faults: stale data → safe defaults.
        grobner::CANONICAL_CLASS_TEMPORAL => HealingAction::ReturnSafeDefault,
        // Congestion: resource pressure → clamp sizes to relieve load.
        grobner::CANONICAL_CLASS_CONGESTION => HealingAction::ClampSize {
            requested: 0,
            clamped: 0,
        },
        // Topological complexity: complex paths → upgrade to safe variant.
        grobner::CANONICAL_CLASS_TOPOLOGICAL => HealingAction::UpgradeToSafeVariant,
        // Regime shift: transitional state → safe defaults until stable.
        grobner::CANONICAL_CLASS_REGIME => HealingAction::ReturnSafeDefault,
        // Numeric exceptional: floating-point edge cases → clamp values.
        grobner::CANONICAL_CLASS_NUMERIC => HealingAction::ClampSize {
            requested: 0,
            clamped: 0,
        },
        // Resource admissibility: constraints → upgrade to safe variant.
        grobner::CANONICAL_CLASS_ADMISSIBILITY => HealingAction::UpgradeToSafeVariant,
        // Compound (multiple irreducible causes): conservative safe default.
        _ => HealingAction::ReturnSafeDefault,
    }
}

/// Global healing policy instance. Static construction must never enter the
/// allocator; even first-use repairs can safely access these zeroed counters.
static GLOBAL_POLICY: HealingPolicy = HealingPolicy::new();

/// Access the global healing policy.
#[must_use]
pub fn global_healing_policy() -> &'static HealingPolicy {
    &GLOBAL_POLICY
}

/// Inspect the policy without starting or waiting for initialization.
/// It is now const-initialized, so diagnostic readers always see a ready
/// policy, possibly with zero counters and an empty, unallocated ring.
#[must_use]
pub fn initialized_healing_policy() -> Option<&'static HealingPolicy> {
    Some(&GLOBAL_POLICY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn record_test(policy: &HealingPolicy, action: &HealingAction) {
        policy.record(
            "test",
            "healing_policy",
            action,
            RepairLogContext::new(0, None),
        );
    }

    /// The FRANKENLIBC_LOG sink appends whole newline-terminated lines and
    /// keeps what the file already held (bd-rc0923-epic-eeuy4f.16).
    #[test]
    fn runtime_log_appends_whole_lines() {
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-heal-log-{}-{:?}.jsonl",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "{\"existing\":1}\n").unwrap();
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        append_line(&file, "{\"a\":1}");
        append_line(&file, "{\"b\":2}");
        let written = std::fs::read_to_string(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(written, "{\"existing\":1}\n{\"a\":1}\n{\"b\":2}\n");
    }

    #[test]
    fn fixed_runtime_record_escapes_json_without_allocation_backing() {
        let mut line = RuntimeLogBuffer::new();
        write_healing_log_line(
            &mut line,
            RepairLogRecord {
                event_seq: 7,
                decision_id: DecisionId::from_raw(42),
                api_family: "string\nmemory",
                symbol: "str\"len\\probe",
                action: &HealingAction::ReturnSafeDefault,
                context: RepairLogContext::new(0, Some(0xdead_beef)),
                runtime_mode: "hardened",
                signal_context: false,
                signal_context_known: true,
            },
        )
        .unwrap();
        let row: Value = serde_json::from_str(line.as_str()).unwrap();
        assert_eq!(row["trace_id"], "membrane::heal::000000000000002a");
        assert_eq!(row["seq"], 7);
        assert_eq!(row["api_family"], "string\nmemory");
        assert_eq!(row["symbol"], "str\"len\\probe");
        assert_eq!(row["errno"], 0);
        assert_eq!(row["address"], "0xdeadbeef");
        assert_eq!(row["signal_context"], false);
        assert_eq!(row["signal_context_known"], true);
        assert_eq!(row["details"], serde_json::json!({}));
    }

    #[test]
    fn fixed_runtime_record_rejects_overflow() {
        let mut line = RuntimeLogBuffer::new();
        assert!(
            line.write_str(&"x".repeat(RUNTIME_LOG_BUFFER_BYTES))
                .is_err()
        );
        assert!(line.as_str().is_empty());
    }

    #[test]
    fn clamp_size_when_exceeding_bounds() {
        let policy = HealingPolicy::new();
        let action = policy.heal_copy_bounds(1000, Some(500), Some(800));
        assert_eq!(
            action,
            HealingAction::ClampSize {
                requested: 1000,
                clamped: 500
            }
        );
    }

    #[test]
    fn no_heal_when_within_bounds() {
        let policy = HealingPolicy::new();
        let action = policy.heal_copy_bounds(100, Some(500), Some(800));
        assert_eq!(action, HealingAction::None);
    }

    #[test]
    fn no_heal_when_no_bounds_known() {
        let policy = HealingPolicy::new();
        let action = policy.heal_copy_bounds(1000, None, None);
        assert_eq!(action, HealingAction::None);
    }

    #[test]
    fn truncate_string_when_exceeding_dst() {
        let policy = HealingPolicy::new();
        let action = policy.heal_string_bounds(100, Some(50));
        assert_eq!(
            action,
            HealingAction::TruncateWithNull {
                requested: 100,
                truncated: 49
            }
        );
    }

    #[test]
    fn record_increments_counters() {
        let policy = HealingPolicy::new();
        record_test(&policy, &HealingAction::IgnoreDoubleFree);
        record_test(&policy, &HealingAction::IgnoreDoubleFree);
        record_test(
            &policy,
            &HealingAction::ClampSize {
                requested: 10,
                clamped: 5,
            },
        );

        assert_eq!(policy.total_heals.load(Ordering::Relaxed), 3);
        assert_eq!(policy.double_frees.load(Ordering::Relaxed), 2);
        assert_eq!(policy.size_clamps.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn none_is_not_a_heal() {
        assert!(!HealingAction::None.is_heal());
        assert!(HealingAction::IgnoreDoubleFree.is_heal());
        assert!(HealingAction::ReturnSafeDefault.is_heal());
    }

    #[test]
    fn canonical_class_none_yields_no_healing() {
        use crate::grobner::CANONICAL_CLASS_NONE;
        let action = recommended_healing_for_canonical_class(CANONICAL_CLASS_NONE);
        assert_eq!(action, HealingAction::None);
    }

    #[test]
    fn canonical_class_mapping_covers_all_classes() {
        use crate::grobner;
        for class_id in 0..grobner::NUM_CANONICAL_CLASSES as u8 {
            let action = recommended_healing_for_canonical_class(class_id);
            if class_id == grobner::CANONICAL_CLASS_NONE {
                assert!(!action.is_heal());
            } else {
                assert!(
                    action.is_heal(),
                    "Class {} should produce a healing action",
                    class_id
                );
            }
        }
    }

    #[test]
    fn canonical_class_out_of_range_returns_safe_default() {
        let action = recommended_healing_for_canonical_class(255);
        assert_eq!(action, HealingAction::ReturnSafeDefault);
    }

    #[test]
    fn healing_log_export_contains_required_fields() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        policy.record(
            "string_memory",
            "memcpy",
            &HealingAction::ClampSize {
                requested: 32,
                clamped: 8,
            },
            RepairLogContext::new(0, Some(0x1234)),
        );

        let jsonl = policy.export_healing_log_jsonl();
        let row: Value = serde_json::from_str(jsonl.trim()).expect("row must be valid JSON");
        assert_eq!(row["bead_id"], HEALING_BEAD_ID);
        assert_eq!(row["event"], "repair");
        assert_eq!(row["action"], "Repair");
        assert_eq!(row["symbol"], "memcpy");
        assert!(row["pid"].as_u64().is_some_and(|pid| pid > 0));
        assert_eq!(row["api_family"], "string_memory");
        assert_eq!(row["decision_path"], "record");
        assert_eq!(row["outcome"], "repair");
        assert_eq!(row["healing_action"], "ClampSize");
        assert_eq!(row["errno"], 0);
        assert_eq!(row["level"], "info");
        assert_eq!(row["details"]["requested"], 32);
        assert_eq!(row["details"]["clamped"], 8);
        assert!(
            row["trace_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("membrane::heal::"))
        );
        assert!(row["decision_id"].as_u64().is_some_and(|id| id > 0));
        assert_eq!(row["schema_version"].as_str(), Some("1.0"));
    }

    #[test]
    fn escalated_healing_actions_emit_warn_level() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        record_test(&policy, &HealingAction::ReturnSafeDefault);

        let jsonl = policy.export_healing_log_jsonl();
        let row: Value = serde_json::from_str(jsonl.trim()).expect("row must be valid JSON");
        assert_eq!(row["healing_action"], "ReturnSafeDefault");
        assert_eq!(row["level"], "warn");
        assert_eq!(row["escalated"], true);
    }

    #[test]
    fn none_action_does_not_emit_healing_log_row() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        record_test(&policy, &HealingAction::None);

        assert!(
            policy.export_healing_log_jsonl().trim().is_empty(),
            "HealingAction::None should not produce evidence rows"
        );
    }

    #[test]
    fn healing_log_capacity_is_bounded() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        for i in 0..(HEALING_LOG_CAPACITY + 32) {
            record_test(&policy, &HealingAction::ReallocAsMalloc { size: i });
        }

        let row_count = policy
            .export_healing_log_jsonl()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        assert_eq!(row_count, HEALING_LOG_CAPACITY);
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Healing Never Produces UB
    //
    // Theorem: Every healing action's output satisfies the
    // invariant that the effective parameters are SAFE —
    // clamped sizes never exceed bounds, truncated strings have
    // null termination room, and no action can widen a buffer.
    //
    // This is the core hardened-mode safety property: healing
    // prevents UB propagation by construction.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_healing_never_widens_bounds() {
        let policy = HealingPolicy::new();

        // For any requested > available, ClampSize.clamped <= available
        let test_pairs = [
            (100usize, Some(50usize), Some(80usize)), // min(50,80) = 50
            (100, Some(200), Some(30)),               // 30
            (100, Some(50), None),                    // 50
            (100, None, Some(30)),                    // 30
            (usize::MAX, Some(0), Some(0)),           // 0
            (0, Some(100), Some(100)),                // no clamp needed
        ];

        for &(requested, src_rem, dst_rem) in &test_pairs {
            let action = policy.heal_copy_bounds(requested, src_rem, dst_rem);
            match action {
                HealingAction::ClampSize { clamped, .. } => {
                    let available = match (src_rem, dst_rem) {
                        (Some(s), Some(d)) => s.min(d),
                        (Some(s), None) => s,
                        (None, Some(d)) => d,
                        (None, None) => unreachable!(),
                    };
                    assert!(
                        clamped <= available,
                        "Clamp widened: clamped={clamped}, available={available}"
                    );
                }
                HealingAction::None => {
                    // No healing needed means requested <= available
                }
                _ => panic!("Unexpected healing action: {action:?}"),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: String Truncation Preserves Null-Termination Room
    //
    // Theorem: heal_string_bounds() always truncates to at most
    // remaining-1 bytes, leaving room for the null terminator.
    // This prevents buffer overflow in string operations.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_string_truncation_leaves_null_room() {
        let policy = HealingPolicy::new();

        for remaining in 0..=100usize {
            for src_len in [0, 1, remaining, remaining + 1, remaining + 100, usize::MAX] {
                let action = policy.heal_string_bounds(src_len, Some(remaining));
                match action {
                    HealingAction::TruncateWithNull { truncated, .. } => {
                        if remaining > 0 {
                            assert!(
                                truncated < remaining,
                                "Truncated ({truncated}) must be < remaining ({remaining}) \
                                 for null terminator room"
                            );
                        }
                    }
                    HealingAction::ClampSize { clamped, .. } => {
                        assert_eq!(remaining, 0, "ClampSize should only occur for remaining=0");
                        assert_eq!(clamped, 0);
                    }
                    HealingAction::None => {
                        // No healing means src_len < remaining
                        assert!(
                            src_len < remaining,
                            "None healing but src_len={src_len} >= remaining={remaining}"
                        );
                    }
                    _ => panic!("Unexpected action: {action:?}"),
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Healing Action Exhaustiveness
    //
    // Theorem: Every HealingAction variant has a corresponding
    // counter in HealingPolicy, and record() increments exactly
    // the right counter. No action goes untracked.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_healing_counter_exhaustiveness() {
        let actions = [
            HealingAction::ClampSize {
                requested: 10,
                clamped: 5,
            },
            HealingAction::TruncateWithNull {
                requested: 20,
                truncated: 15,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::IgnoreForeignFree,
            HealingAction::ReallocAsMalloc { size: 64 },
            HealingAction::ReturnSafeDefault,
            HealingAction::UpgradeToSafeVariant,
        ];

        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(false); // avoid log noise

        for action in &actions {
            record_test(&policy, action);
        }

        // Each counter should be exactly 1
        assert_eq!(policy.size_clamps.load(Ordering::Relaxed), 1);
        assert_eq!(policy.null_truncations.load(Ordering::Relaxed), 1);
        assert_eq!(policy.double_frees.load(Ordering::Relaxed), 1);
        assert_eq!(policy.foreign_frees.load(Ordering::Relaxed), 1);
        assert_eq!(policy.realloc_as_mallocs.load(Ordering::Relaxed), 1);
        assert_eq!(policy.safe_defaults.load(Ordering::Relaxed), 1);
        assert_eq!(policy.variant_upgrades.load(Ordering::Relaxed), 1);

        // total_heals should be 7 (all actions are heals)
        assert_eq!(policy.total_heals.load(Ordering::Relaxed), 7);

        // HealingAction::None should NOT increment any counter
        let before_total = policy.total_heals.load(Ordering::Relaxed);
        record_test(&policy, &HealingAction::None);
        assert_eq!(
            policy.total_heals.load(Ordering::Relaxed),
            before_total,
            "None should not increment total_heals"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Healing Evidence Monotone Decision IDs
    //
    // Theorem: Each healing evidence row has a strictly increasing
    // decision_id. This ensures deterministic replay: the evidence
    // log can be replayed in order to reconstruct the exact
    // sequence of healing decisions.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_healing_evidence_monotone_decision_ids() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        let actions = [
            HealingAction::ClampSize {
                requested: 10,
                clamped: 5,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::ReturnSafeDefault,
            HealingAction::TruncateWithNull {
                requested: 20,
                truncated: 15,
            },
            HealingAction::ReallocAsMalloc { size: 128 },
        ];

        for action in &actions {
            record_test(&policy, action);
        }

        let jsonl = policy.export_healing_log_jsonl();
        let mut prev_id = 0u64;
        for (i, line) in jsonl.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let row: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Invalid JSON at row {i}: {e}"));
            let decision_id = row["decision_id"]
                .as_u64()
                .unwrap_or_else(|| panic!("Missing decision_id at row {i}"));
            assert!(
                decision_id > prev_id,
                "Decision IDs not monotone: row {i} has id={decision_id}, prev={prev_id}"
            );
            prev_id = decision_id;
        }
        assert_eq!(
            prev_id as usize,
            actions.len(),
            "Should have all decision IDs"
        );
    }

    #[test]
    fn every_healing_action_variant_emits_dispatch_evidence() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        let actions = [
            HealingAction::ClampSize {
                requested: 7,
                clamped: 3,
            },
            HealingAction::TruncateWithNull {
                requested: 16,
                truncated: 15,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::IgnoreForeignFree,
            HealingAction::ReallocAsMalloc { size: 64 },
            HealingAction::ReturnSafeDefault,
            HealingAction::UpgradeToSafeVariant,
        ];

        for action in &actions {
            record_test(&policy, action);
        }

        let rows = policy
            .export_healing_log_jsonl()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("row must be valid JSON"))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), actions.len());
        for row in rows {
            assert_eq!(row["outcome"], "repair");
            assert_eq!(row["api_family"], "test");
            assert!(
                row["healing_action"]
                    .as_str()
                    .is_some_and(|name| !name.is_empty())
            );
            assert!(matches!(row["level"].as_str(), Some("info" | "warn")));
        }
    }

    #[test]
    fn healing_policy_const_initialization_has_no_ring_allocation() {
        static POLICY: HealingPolicy = HealingPolicy::new();
        assert_eq!(POLICY.healing_logs.lock().capacity(), 0);
        assert_eq!(POLICY.total_heals.load(Ordering::Relaxed), 0);
        assert!(std::ptr::eq(
            initialized_healing_policy().unwrap(),
            global_healing_policy()
        ));
    }

    #[test]
    fn nested_heal_counts_without_relocking_the_evidence_ring() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        {
            let _guard = LogReentryGuard::enter(&EMITTING_HEALING_LOG).unwrap();
            let logs = policy.healing_logs.lock();
            record_test(&policy, &HealingAction::IgnoreDoubleFree);
            record_test(&policy, &HealingAction::None);
            assert_eq!(policy.total_heals.load(Ordering::Relaxed), 1);
            assert_eq!(policy.double_frees.load(Ordering::Relaxed), 1);
            assert_eq!(policy.healing_log_reentry_drops.load(Ordering::Relaxed), 1);
            assert_eq!(policy.healing_log_decision_seq.load(Ordering::Relaxed), 0);
            assert!(logs.is_empty());
            assert!(policy.export_healing_log_jsonl().is_empty());
            policy.clear_healing_logs();
        }
        record_test(&policy, &HealingAction::ReturnSafeDefault);
        let rows = policy.export_healing_log_jsonl();
        let row: Value = serde_json::from_str(&rows).unwrap();
        assert_eq!(row["healing_action"], "ReturnSafeDefault");
        assert_eq!(row["decision_id"], 1);
    }

    #[test]
    fn reentry_guard_covers_distinct_policies_on_the_same_thread() {
        let first = HealingPolicy::new();
        let second = HealingPolicy::new();
        first.set_healing_logging_enabled(true);
        second.set_healing_logging_enabled(true);
        let guard = LogReentryGuard::enter(&EMITTING_HEALING_LOG).unwrap();
        record_test(&first, &HealingAction::IgnoreDoubleFree);
        record_test(&second, &HealingAction::IgnoreForeignFree);
        assert!(LogReentryGuard::enter(&EMITTING_HEALING_LOG).is_none());
        assert_eq!(first.healing_log_reentry_drops.load(Ordering::Relaxed), 1);
        assert_eq!(second.healing_log_reentry_drops.load(Ordering::Relaxed), 1);
        drop(guard);
        assert!(LogReentryGuard::enter(&EMITTING_HEALING_LOG).is_some());
    }

    #[test]
    fn log_reentry_guards_restore_flags_after_unwind() {
        for flag in [&EMITTING_HEALING_LOG, &WRITING_RUNTIME_LOG] {
            let result = std::panic::catch_unwind(|| {
                let _guard = LogReentryGuard::enter(flag).unwrap();
                assert!(LogReentryGuard::enter(flag).is_none());
                panic!("injected diagnostic failure");
            });
            assert!(result.is_err());
            assert!(LogReentryGuard::enter(flag).is_some());
        }
    }

    #[test]
    fn healing_log_guard_does_not_suppress_other_threads() {
        let _guard = LogReentryGuard::enter(&EMITTING_HEALING_LOG).unwrap();
        let rows = std::thread::spawn(|| {
            let policy = HealingPolicy::new();
            policy.set_healing_logging_enabled(true);
            record_test(&policy, &HealingAction::IgnoreForeignFree);
            assert_eq!(policy.healing_log_reentry_drops.load(Ordering::Relaxed), 0);
            policy.export_healing_log_jsonl()
        })
        .join()
        .unwrap();
        let row: Value = serde_json::from_str(&rows).unwrap();
        assert_eq!(row["healing_action"], "IgnoreForeignFree");
    }

    #[test]
    fn counter_summary_reports_reentry_and_sink_losses() {
        let policy = HealingPolicy::new();
        let fields = policy.counters_json_fields();
        let value: Value = serde_json::from_str(&format!("{{{fields}}}")).unwrap();
        for field in [
            "healing_log_reentry_drops",
            "runtime_log_written_records",
            "runtime_log_dropped_records",
            "runtime_log_rate_limited_records",
            "runtime_log_admission_clock_failures",
            "runtime_log_short_writes",
            "runtime_log_open_failures",
        ] {
            assert!(value[field].as_u64().is_some(), "missing counter {field}");
        }
    }
}
