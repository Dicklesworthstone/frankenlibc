//! Shared startup/bootstrap helpers used by phase-0 CRT plumbing.

use std::ffi::c_int;

/// Maximum number of argv/envp/auxv entries scanned in phase-0 startup.
pub const MAX_STARTUP_SCAN: usize = 4096;

/// ELF auxv terminator key.
pub const AT_NULL: usize = 0;
/// ELF auxv secure-mode key.
pub const AT_SECURE: usize = 23;

/// Deterministic phase-0 startup checkpoints used to model init-order constraints.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupCheckpoint {
    Entry = 0,
    MembraneGate = 1,
    ValidateMainPointer = 2,
    ValidateArgvPointer = 3,
    ScanArgvVector = 4,
    ValidateArgcBound = 5,
    ScanEnvpVector = 6,
    ScanAuxvVector = 7,
    ClassifySecureMode = 8,
    CaptureInvariants = 9,
    CallInitHook = 10,
    CallMain = 11,
    CallFiniHook = 12,
    CallRtldFiniHook = 13,
    Complete = 14,
    Deny = 15,
    FallbackHost = 16,
}

/// Phase-0 dependency DAG over startup checkpoints.
pub const STARTUP_PHASE0_DAG_EDGES: &[(StartupCheckpoint, StartupCheckpoint)] = &[
    (StartupCheckpoint::Entry, StartupCheckpoint::MembraneGate),
    (
        StartupCheckpoint::MembraneGate,
        StartupCheckpoint::ValidateMainPointer,
    ),
    (
        StartupCheckpoint::ValidateMainPointer,
        StartupCheckpoint::ValidateArgvPointer,
    ),
    (
        StartupCheckpoint::ValidateArgvPointer,
        StartupCheckpoint::ScanArgvVector,
    ),
    (
        StartupCheckpoint::ScanArgvVector,
        StartupCheckpoint::ValidateArgcBound,
    ),
    (
        StartupCheckpoint::ValidateArgcBound,
        StartupCheckpoint::ScanEnvpVector,
    ),
    (
        StartupCheckpoint::ScanEnvpVector,
        StartupCheckpoint::ScanAuxvVector,
    ),
    (
        StartupCheckpoint::ScanAuxvVector,
        StartupCheckpoint::ClassifySecureMode,
    ),
    (
        StartupCheckpoint::ClassifySecureMode,
        StartupCheckpoint::CaptureInvariants,
    ),
    (
        StartupCheckpoint::CaptureInvariants,
        StartupCheckpoint::CallInitHook,
    ),
    (
        StartupCheckpoint::CaptureInvariants,
        StartupCheckpoint::CallMain,
    ),
    (StartupCheckpoint::CallInitHook, StartupCheckpoint::CallMain),
    (StartupCheckpoint::CallMain, StartupCheckpoint::CallFiniHook),
    (
        StartupCheckpoint::CallMain,
        StartupCheckpoint::CallRtldFiniHook,
    ),
    (StartupCheckpoint::CallMain, StartupCheckpoint::Complete),
    (
        StartupCheckpoint::CallFiniHook,
        StartupCheckpoint::CallRtldFiniHook,
    ),
    (StartupCheckpoint::CallFiniHook, StartupCheckpoint::Complete),
    (
        StartupCheckpoint::CallRtldFiniHook,
        StartupCheckpoint::Complete,
    ),
    (StartupCheckpoint::MembraneGate, StartupCheckpoint::Deny),
    (
        StartupCheckpoint::ValidateMainPointer,
        StartupCheckpoint::Deny,
    ),
    (
        StartupCheckpoint::ValidateArgvPointer,
        StartupCheckpoint::Deny,
    ),
    (StartupCheckpoint::ScanArgvVector, StartupCheckpoint::Deny),
    (
        StartupCheckpoint::ValidateArgcBound,
        StartupCheckpoint::Deny,
    ),
    (StartupCheckpoint::ScanEnvpVector, StartupCheckpoint::Deny),
    (StartupCheckpoint::ScanAuxvVector, StartupCheckpoint::Deny),
    (StartupCheckpoint::Entry, StartupCheckpoint::FallbackHost),
];

#[must_use]
pub fn startup_path_respects_dag(path: &[StartupCheckpoint]) -> bool {
    if path.len() < 2 {
        return false;
    }

    path.windows(2)
        .all(|pair| STARTUP_PHASE0_DAG_EDGES.contains(&(pair[0], pair[1])))
}

/// Secure-mode automaton states derived from auxv scanning.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecureModeState {
    #[default]
    Unknown = 0,
    NonSecure = 1,
    Secure = 2,
}

impl SecureModeState {
    #[must_use]
    pub const fn is_secure(self) -> bool {
        matches!(self, Self::Secure)
    }
}

/// Evidence emitted by auxv secure-mode classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SecureModeEvidence {
    pub state: SecureModeState,
    pub at_secure_seen: bool,
    pub scanned_pairs: usize,
    pub terminated: bool,
    pub truncated: bool,
}

#[must_use]
pub fn classify_secure_mode(entries: &[(usize, usize)], max_pairs: usize) -> SecureModeEvidence {
    let mut state = SecureModeState::Unknown;
    let mut at_secure_seen = false;
    let mut scanned_pairs = 0usize;
    let mut terminated = false;

    for &(key, value) in entries.iter().take(max_pairs) {
        if key == AT_NULL {
            terminated = true;
            break;
        }

        scanned_pairs += 1;
        if key == AT_SECURE {
            at_secure_seen = true;
            if value != 0 {
                state = SecureModeState::Secure;
            } else if !matches!(state, SecureModeState::Secure) {
                state = SecureModeState::NonSecure;
            }
        }
    }

    if matches!(state, SecureModeState::Unknown) {
        state = SecureModeState::NonSecure;
    }

    let truncated = !terminated && scanned_pairs >= max_pairs;
    SecureModeEvidence {
        state,
        at_secure_seen,
        scanned_pairs,
        terminated,
        truncated,
    }
}

/// Phase-0 startup invariants captured at `__libc_start_main` boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartupInvariants {
    pub argc: usize,
    pub argv_count: usize,
    pub env_count: usize,
    pub auxv_count: usize,
    pub secure_mode: bool,
}

#[must_use]
pub fn normalize_argc(argc: c_int) -> usize {
    if argc < 0 { 0 } else { argc as usize }
}

#[must_use]
pub fn scan_auxv_pairs(entries: &[(usize, usize)], max_pairs: usize) -> (usize, bool) {
    let evidence = classify_secure_mode(entries, max_pairs);
    (evidence.scanned_pairs, evidence.state.is_secure())
}

#[must_use]
pub fn build_invariants(
    argc: c_int,
    argv_count: usize,
    env_count: usize,
    auxv_count: usize,
    secure_mode: bool,
) -> StartupInvariants {
    StartupInvariants {
        argc: normalize_argc(argc),
        argv_count,
        env_count,
        auxv_count,
        secure_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_argc_clamps_negative() {
        assert_eq!(normalize_argc(-7), 0);
        assert_eq!(normalize_argc(0), 0);
        assert_eq!(normalize_argc(3), 3);
    }

    #[test]
    fn scan_auxv_stops_at_null() {
        let entries = [
            (15usize, 0usize),
            (AT_SECURE, 1usize),
            (AT_NULL, 0usize),
            (7usize, 0usize),
        ];
        let (count, secure) = scan_auxv_pairs(&entries, 16);
        assert_eq!(count, 2);
        assert!(secure);
    }

    #[test]
    fn scan_auxv_respects_max_pairs() {
        let entries = [(1usize, 0usize), (AT_SECURE, 1usize), (AT_NULL, 0usize)];
        let (count, secure) = scan_auxv_pairs(&entries, 1);
        assert_eq!(count, 1);
        assert!(!secure);
    }

    #[test]
    fn build_invariants_records_counts() {
        let inv = build_invariants(2, 2, 3, 4, true);
        assert_eq!(inv.argc, 2);
        assert_eq!(inv.argv_count, 2);
        assert_eq!(inv.env_count, 3);
        assert_eq!(inv.auxv_count, 4);
        assert!(inv.secure_mode);
    }

    #[test]
    fn startup_dag_accepts_valid_phase0_route() {
        let path = [
            StartupCheckpoint::Entry,
            StartupCheckpoint::MembraneGate,
            StartupCheckpoint::ValidateMainPointer,
            StartupCheckpoint::ValidateArgvPointer,
            StartupCheckpoint::ScanArgvVector,
            StartupCheckpoint::ValidateArgcBound,
            StartupCheckpoint::ScanEnvpVector,
            StartupCheckpoint::ScanAuxvVector,
            StartupCheckpoint::ClassifySecureMode,
            StartupCheckpoint::CaptureInvariants,
            StartupCheckpoint::CallMain,
            StartupCheckpoint::Complete,
        ];
        assert!(startup_path_respects_dag(&path));
    }

    #[test]
    fn startup_dag_rejects_invalid_route() {
        let path = [
            StartupCheckpoint::Entry,
            StartupCheckpoint::ScanAuxvVector,
            StartupCheckpoint::Complete,
        ];
        assert!(!startup_path_respects_dag(&path));
    }

    #[test]
    fn secure_mode_defaults_to_non_secure_when_absent() {
        let entries = [(1usize, 0usize), (AT_NULL, 0usize)];
        let evidence = classify_secure_mode(&entries, 16);
        assert_eq!(evidence.state, SecureModeState::NonSecure);
        assert!(!evidence.at_secure_seen);
        assert!(evidence.terminated);
        assert!(!evidence.truncated);
    }

    #[test]
    fn secure_mode_becomes_secure_on_nonzero_at_secure() {
        let entries = [(AT_SECURE, 1usize), (AT_NULL, 0usize)];
        let evidence = classify_secure_mode(&entries, 16);
        assert_eq!(evidence.state, SecureModeState::Secure);
        assert!(evidence.at_secure_seen);
    }

    #[test]
    fn secure_mode_stays_secure_after_later_zero_marker() {
        let entries = [(AT_SECURE, 1usize), (AT_SECURE, 0usize), (AT_NULL, 0usize)];
        let evidence = classify_secure_mode(&entries, 16);
        assert_eq!(evidence.state, SecureModeState::Secure);
        assert!(evidence.at_secure_seen);
    }

    #[test]
    fn secure_mode_marks_truncated_scan_without_terminator() {
        let entries = [(1usize, 0usize), (2usize, 0usize)];
        let evidence = classify_secure_mode(&entries, 2);
        assert_eq!(evidence.state, SecureModeState::NonSecure);
        assert!(!evidence.terminated);
        assert!(evidence.truncated);
    }
}
