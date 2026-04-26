//! Hardware transactional memory helper for hot-path optimistic execution.
//!
//! This module provides:
//! - runtime RTM support detection on x86_64,
//! - adaptive disable/cooldown after repeated aborts,
//! - deterministic test modes for commit/abort/unsupported simulation, and
//! - site-local snapshots for verification.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use frankenlibc_core::syscall as raw_syscall;

const SAMPLE_WINDOW: u64 = 64;
const ABORT_DISABLE_PERCENT: u64 = 30;
const BASE_COOLDOWN_MS: u64 = 1;
const MAX_COOLDOWN_MS: u64 = 1_000;
const MAX_COOLDOWN_EXP: u32 = 10;
const SUMMARY_INTERVAL: u64 = 1_000;
const HTM_SUPPORT_UNKNOWN: u8 = 0;
const HTM_SUPPORT_UNAVAILABLE: u8 = 1;
const HTM_SUPPORT_AVAILABLE: u8 = 2;

#[cfg(target_arch = "x86_64")]
const XBEGIN_STARTED: u32 = u32::MAX;

/// Deterministic test override for HTM execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HtmTestMode {
    /// Use runtime hardware detection.
    Real = 0,
    /// Force the site to bypass HTM and take the software fallback.
    ForceUnsupported = 1,
    /// Force the site to take the optimistic fast path and commit.
    ForceCommit = 2,
    /// Force the site to abort and exercise the fallback path.
    ForceAbort = 3,
}

/// Reason the HTM path was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HtmFallbackReason {
    Unsupported,
    Disabled,
    Abort(u32),
}

/// Snapshot of a site-local HTM controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtmSiteSnapshot {
    pub site: &'static str,
    pub attempts: u64,
    pub commits: u64,
    pub aborts: u64,
    pub fallbacks: u64,
    pub disabled: bool,
    pub cooldown_remaining_ms: u64,
    pub cooldown_exponent: u32,
    pub last_abort_code: u32,
}

static HTM_TEST_MODE: AtomicU8 = AtomicU8::new(HtmTestMode::Real as u8);
static HTM_TEST_ABORT_CODE: AtomicU32 = AtomicU32::new(0xFFFF_FF01);
static HTM_SUPPORT_CACHE: AtomicU8 = AtomicU8::new(HTM_SUPPORT_UNKNOWN);
static HTM_EPOCH_NS: AtomicU64 = AtomicU64::new(0);

/// Swap the deterministic HTM test mode.
#[doc(hidden)]
pub fn htm_swap_test_mode_for_tests(mode: HtmTestMode) -> HtmTestMode {
    decode_test_mode(HTM_TEST_MODE.swap(mode as u8, Ordering::AcqRel))
}

/// Restore the deterministic HTM test mode after a test override.
#[doc(hidden)]
pub fn htm_restore_test_mode_for_tests(previous: HtmTestMode) {
    HTM_TEST_MODE.store(previous as u8, Ordering::Release);
}

/// Swap the synthetic abort code used by [`HtmTestMode::ForceAbort`].
#[doc(hidden)]
pub fn htm_swap_abort_code_for_tests(code: u32) -> u32 {
    HTM_TEST_ABORT_CODE.swap(code, Ordering::AcqRel)
}

fn decode_test_mode(encoded: u8) -> HtmTestMode {
    match encoded {
        1 => HtmTestMode::ForceUnsupported,
        2 => HtmTestMode::ForceCommit,
        3 => HtmTestMode::ForceAbort,
        _ => HtmTestMode::Real,
    }
}

fn current_test_mode() -> HtmTestMode {
    decode_test_mode(HTM_TEST_MODE.load(Ordering::Acquire))
}

#[doc(hidden)]
#[must_use]
pub fn htm_forced_mode_active_for_tests() -> bool {
    !matches!(current_test_mode(), HtmTestMode::Real)
}

fn now_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let now_ns = match unsafe {
        raw_syscall::sys_clock_gettime(libc::CLOCK_MONOTONIC, (&raw mut ts).cast::<u8>())
    } {
        Ok(()) => {
            let sec = u64::try_from(ts.tv_sec).unwrap_or(0);
            let nsec = u64::try_from(ts.tv_nsec).unwrap_or(0).min(999_999_999);
            sec.saturating_mul(1_000_000_000).saturating_add(nsec)
        }
        Err(_) => 0,
    };
    if now_ns == 0 {
        return 0;
    }

    let base = match HTM_EPOCH_NS.compare_exchange(0, now_ns, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => now_ns,
        Err(existing) => existing,
    };
    now_ns.saturating_sub(base) / 1_000_000
}

fn real_htm_supported() -> bool {
    match HTM_SUPPORT_CACHE.load(Ordering::Acquire) {
        HTM_SUPPORT_AVAILABLE => true,
        HTM_SUPPORT_UNAVAILABLE => false,
        _ => {
            #[cfg(target_arch = "x86_64")]
            let supported = std::is_x86_feature_detected!("rtm");
            #[cfg(not(target_arch = "x86_64"))]
            let supported = false;

            HTM_SUPPORT_CACHE.store(
                if supported {
                    HTM_SUPPORT_AVAILABLE
                } else {
                    HTM_SUPPORT_UNAVAILABLE
                },
                Ordering::Release,
            );
            supported
        }
    }
}

/// Per-site HTM controller with adaptive disable and cooldown.
pub struct HtmSite {
    site: &'static str,
    attempts: AtomicU64,
    commits: AtomicU64,
    aborts: AtomicU64,
    fallbacks: AtomicU64,
    window_attempts: AtomicU64,
    window_aborts: AtomicU64,
    disable_until_ms: AtomicU64,
    cooldown_exponent: AtomicU32,
    last_abort_code: AtomicU32,
    last_summary_outcome_count: AtomicU64,
}

impl HtmSite {
    pub const fn new(site: &'static str) -> Self {
        Self {
            site,
            attempts: AtomicU64::new(0),
            commits: AtomicU64::new(0),
            aborts: AtomicU64::new(0),
            fallbacks: AtomicU64::new(0),
            window_attempts: AtomicU64::new(0),
            window_aborts: AtomicU64::new(0),
            disable_until_ms: AtomicU64::new(0),
            cooldown_exponent: AtomicU32::new(0),
            last_abort_code: AtomicU32::new(0),
            last_summary_outcome_count: AtomicU64::new(0),
        }
    }

    pub fn run<R>(&self, f: impl FnOnce() -> R) -> Result<R, HtmFallbackReason> {
        let now = now_ms();
        let mode = current_test_mode();

        if self.disable_until_ms.load(Ordering::Acquire) > now {
            self.record_fallback(HtmFallbackReason::Disabled);
            return Err(HtmFallbackReason::Disabled);
        }

        match mode {
            HtmTestMode::ForceUnsupported => {
                self.record_fallback(HtmFallbackReason::Unsupported);
                Err(HtmFallbackReason::Unsupported)
            }
            HtmTestMode::ForceCommit => {
                let attempt_number = self.record_attempt();
                let out = f();
                self.record_commit(attempt_number);
                Ok(out)
            }
            HtmTestMode::ForceAbort => {
                let attempt_number = self.record_attempt();
                let code = HTM_TEST_ABORT_CODE.load(Ordering::Acquire);
                self.record_abort(attempt_number, code);
                Err(HtmFallbackReason::Abort(code))
            }
            HtmTestMode::Real => {
                if !real_htm_supported() {
                    self.record_fallback(HtmFallbackReason::Unsupported);
                    return Err(HtmFallbackReason::Unsupported);
                }

                #[cfg(target_arch = "x86_64")]
                {
                    let attempt_number = self.record_attempt();
                    // SAFETY: `_xbegin`/`_xend` are only invoked after runtime RTM
                    // detection says the current CPU supports RTM.
                    match unsafe { execute_transaction(f) } {
                        Ok(out) => {
                            self.record_commit(attempt_number);
                            Ok(out)
                        }
                        Err(code) => {
                            self.record_abort(attempt_number, code);
                            Err(HtmFallbackReason::Abort(code))
                        }
                    }
                }
                #[cfg(not(target_arch = "x86_64"))]
                {
                    self.record_fallback(HtmFallbackReason::Unsupported);
                    Err(HtmFallbackReason::Unsupported)
                }
            }
        }
    }

    pub fn snapshot(&self) -> HtmSiteSnapshot {
        let now = now_ms();
        let disable_until = self.disable_until_ms.load(Ordering::Acquire);
        HtmSiteSnapshot {
            site: self.site,
            attempts: self.attempts.load(Ordering::Relaxed),
            commits: self.commits.load(Ordering::Relaxed),
            aborts: self.aborts.load(Ordering::Relaxed),
            fallbacks: self.fallbacks.load(Ordering::Relaxed),
            disabled: disable_until > now,
            cooldown_remaining_ms: disable_until.saturating_sub(now),
            cooldown_exponent: self.cooldown_exponent.load(Ordering::Relaxed),
            last_abort_code: self.last_abort_code.load(Ordering::Relaxed),
        }
    }

    pub fn reset_for_tests(&self) {
        self.attempts.store(0, Ordering::Relaxed);
        self.commits.store(0, Ordering::Relaxed);
        self.aborts.store(0, Ordering::Relaxed);
        self.fallbacks.store(0, Ordering::Relaxed);
        self.window_attempts.store(0, Ordering::Relaxed);
        self.window_aborts.store(0, Ordering::Relaxed);
        self.disable_until_ms.store(0, Ordering::Relaxed);
        self.cooldown_exponent.store(0, Ordering::Relaxed);
        self.last_abort_code.store(0, Ordering::Relaxed);
        self.last_summary_outcome_count.store(0, Ordering::Relaxed);
    }

    fn record_attempt(&self) -> u64 {
        let attempt_number = self.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        self.window_attempts.fetch_add(1, Ordering::Relaxed);
        attempt_number
    }

    fn record_commit(&self, attempt_number: u64) {
        self.commits.fetch_add(1, Ordering::Relaxed);
        if self.window_attempts.load(Ordering::Relaxed) >= SAMPLE_WINDOW {
            self.evaluate_window(false);
        }
        self.cooldown_exponent.store(0, Ordering::Relaxed);
        self.log_outcome("commit", attempt_number, None, None);
        self.maybe_emit_summary();
    }

    fn record_abort(&self, attempt_number: u64, code: u32) {
        self.aborts.fetch_add(1, Ordering::Relaxed);
        self.fallbacks.fetch_add(1, Ordering::Relaxed);
        self.window_aborts.fetch_add(1, Ordering::Relaxed);
        self.last_abort_code.store(code, Ordering::Relaxed);
        if self.window_attempts.load(Ordering::Relaxed) >= SAMPLE_WINDOW {
            self.evaluate_window(true);
        }
        self.log_outcome(
            "abort",
            attempt_number,
            Some(code),
            Some("transaction_abort"),
        );
        self.maybe_emit_summary();
    }

    fn record_fallback(&self, reason: HtmFallbackReason) {
        self.fallbacks.fetch_add(1, Ordering::Relaxed);
        let (abort_code, fallback_reason) = match reason {
            HtmFallbackReason::Unsupported => (None, "unsupported"),
            HtmFallbackReason::Disabled => (None, "disabled"),
            HtmFallbackReason::Abort(code) => (Some(code), "transaction_abort"),
        };
        self.log_outcome(
            "fallback",
            self.attempts.load(Ordering::Relaxed),
            abort_code,
            Some(fallback_reason),
        );
        self.maybe_emit_summary();
    }

    fn log_outcome(
        &self,
        outcome: &'static str,
        attempt_number: u64,
        abort_code: Option<u32>,
        fallback_reason: Option<&'static str>,
    ) {
        tracing::trace!(
            target: "htm",
            call_site_id = self.site,
            attempt_number,
            outcome,
            abort_code = abort_code.unwrap_or(0),
            fallback_reason = fallback_reason.unwrap_or(""),
        );
    }

    fn maybe_emit_summary(&self) {
        let outcomes =
            self.commits.load(Ordering::Relaxed) + self.fallbacks.load(Ordering::Relaxed);
        if outcomes == 0 || !outcomes.is_multiple_of(SUMMARY_INTERVAL) {
            return;
        }

        let previous = self.last_summary_outcome_count.load(Ordering::Relaxed);
        if previous == outcomes
            || self
                .last_summary_outcome_count
                .compare_exchange(previous, outcomes, Ordering::AcqRel, Ordering::Relaxed)
                .is_err()
        {
            return;
        }

        let attempts = self.attempts.load(Ordering::Relaxed);
        let commits = self.commits.load(Ordering::Relaxed);
        let aborts = self.aborts.load(Ordering::Relaxed);
        let snapshot = self.snapshot();
        let commit_rate_pct = if attempts == 0 {
            0.0
        } else {
            (commits as f64 * 100.0) / attempts as f64
        };
        let abort_rate_pct = if attempts == 0 {
            0.0
        } else {
            (aborts as f64 * 100.0) / attempts as f64
        };

        tracing::info!(
            target: "htm",
            call_site_id = self.site,
            attempts,
            commits,
            aborts,
            fallbacks = snapshot.fallbacks,
            disabled = snapshot.disabled,
            cooldown_remaining_ms = snapshot.cooldown_remaining_ms,
            cooldown_exponent = snapshot.cooldown_exponent,
            commit_rate_pct,
            abort_rate_pct,
            "htm_summary"
        );
    }

    fn evaluate_window(&self, aborted: bool) {
        let attempts = self.window_attempts.swap(0, Ordering::Relaxed);
        let aborts = self.window_aborts.swap(0, Ordering::Relaxed);
        if attempts < SAMPLE_WINDOW {
            self.window_attempts.store(attempts, Ordering::Relaxed);
            self.window_aborts.store(aborts, Ordering::Relaxed);
            return;
        }

        if aborts.saturating_mul(100) >= attempts.saturating_mul(ABORT_DISABLE_PERCENT) {
            let next_exp = self
                .cooldown_exponent
                .load(Ordering::Relaxed)
                .saturating_add(1)
                .min(MAX_COOLDOWN_EXP);
            self.cooldown_exponent.store(next_exp, Ordering::Relaxed);
            let cooldown_ms = BASE_COOLDOWN_MS
                .checked_shl(next_exp)
                .unwrap_or(MAX_COOLDOWN_MS)
                .min(MAX_COOLDOWN_MS);
            self.disable_until_ms
                .store(now_ms().saturating_add(cooldown_ms), Ordering::Release);
        } else if !aborted {
            self.cooldown_exponent.store(0, Ordering::Relaxed);
            self.disable_until_ms.store(0, Ordering::Release);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rtm")]
unsafe fn execute_transaction<R>(f: impl FnOnce() -> R) -> Result<R, u32> {
    use core::arch::x86_64::{_xbegin, _xend};

    // SAFETY: caller guarantees RTM support via runtime feature detection.
    let status = unsafe { _xbegin() };
    if status == XBEGIN_STARTED {
        let out = f();
        // SAFETY: the transaction was started by the matching `_xbegin` above.
        unsafe { _xend() };
        Ok(out)
    } else {
        Err(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn forced_commit_records_attempt_and_commit() {
        let _guard = test_lock().lock().expect("test lock poisoned");
        static SITE: HtmSite = HtmSite::new("unit::commit");
        SITE.reset_for_tests();
        let previous = htm_swap_test_mode_for_tests(HtmTestMode::ForceCommit);

        let result = SITE.run(|| 17usize).expect("forced commit should succeed");
        let snapshot = SITE.snapshot();

        htm_restore_test_mode_for_tests(previous);
        assert_eq!(result, 17);
        assert_eq!(snapshot.attempts, 1);
        assert_eq!(snapshot.commits, 1);
        assert_eq!(snapshot.aborts, 0);
        assert_eq!(snapshot.fallbacks, 0);
    }

    #[test]
    fn forced_abort_disables_and_then_recovers() {
        let _guard = test_lock().lock().expect("test lock poisoned");
        static SITE: HtmSite = HtmSite::new("unit::abort");
        SITE.reset_for_tests();
        let previous_mode = htm_swap_test_mode_for_tests(HtmTestMode::ForceAbort);
        let previous_code = htm_swap_abort_code_for_tests(0xAA55);

        for _ in 0..SAMPLE_WINDOW {
            let result = SITE.run(|| 1usize);
            assert_eq!(result, Err(HtmFallbackReason::Abort(0xAA55)));
        }

        let disabled = SITE.snapshot();
        assert!(
            disabled.disabled,
            "site should enter cooldown after abort storm"
        );
        assert_eq!(disabled.last_abort_code, 0xAA55);

        htm_restore_test_mode_for_tests(HtmTestMode::ForceCommit);
        std::thread::sleep(Duration::from_millis(
            disabled.cooldown_remaining_ms.saturating_add(5),
        ));

        let result = SITE
            .run(|| 99usize)
            .expect("site should re-enable after cooldown");
        let recovered = SITE.snapshot();

        htm_restore_test_mode_for_tests(previous_mode);
        let _ = htm_swap_abort_code_for_tests(previous_code);

        assert_eq!(result, 99);
        assert!(recovered.commits >= 1);
        assert!(!recovered.disabled);
    }

    #[test]
    fn unsupported_mode_counts_fallback_without_attempt() {
        let _guard = test_lock().lock().expect("test lock poisoned");
        static SITE: HtmSite = HtmSite::new("unit::unsupported");
        SITE.reset_for_tests();
        let previous = htm_swap_test_mode_for_tests(HtmTestMode::ForceUnsupported);

        let result = SITE.run(|| 5usize);
        let snapshot = SITE.snapshot();

        htm_restore_test_mode_for_tests(previous);

        assert_eq!(result, Err(HtmFallbackReason::Unsupported));
        assert_eq!(snapshot.attempts, 0);
        assert_eq!(snapshot.commits, 0);
        assert_eq!(snapshot.aborts, 0);
        assert_eq!(snapshot.fallbacks, 1);
    }
}
