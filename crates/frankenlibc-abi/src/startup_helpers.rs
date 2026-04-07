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
    ResolveEnvp = 10,
    BindProcessGlobals = 11,
    BootstrapHostSymbols = 12,
    InitHostStdio = 13,
    BootstrapHostLibio = 14,
    PrewarmThreadSymbols = 15,
    PrewarmAllocatorSymbols = 16,
    SignalRuntimeReady = 17,
    CallInitHook = 18,
    CallMain = 19,
    CallFiniHook = 20,
    CallRtldFiniHook = 21,
    Complete = 22,
    Deny = 23,
    FallbackHost = 24,
}

impl StartupCheckpoint {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "Entry",
            Self::MembraneGate => "MembraneGate",
            Self::ValidateMainPointer => "ValidateMainPointer",
            Self::ValidateArgvPointer => "ValidateArgvPointer",
            Self::ScanArgvVector => "ScanArgvVector",
            Self::ValidateArgcBound => "ValidateArgcBound",
            Self::ScanEnvpVector => "ScanEnvpVector",
            Self::ScanAuxvVector => "ScanAuxvVector",
            Self::ClassifySecureMode => "ClassifySecureMode",
            Self::CaptureInvariants => "CaptureInvariants",
            Self::ResolveEnvp => "ResolveEnvp",
            Self::BindProcessGlobals => "BindProcessGlobals",
            Self::BootstrapHostSymbols => "BootstrapHostSymbols",
            Self::InitHostStdio => "InitHostStdio",
            Self::BootstrapHostLibio => "BootstrapHostLibio",
            Self::PrewarmThreadSymbols => "PrewarmThreadSymbols",
            Self::PrewarmAllocatorSymbols => "PrewarmAllocatorSymbols",
            Self::SignalRuntimeReady => "SignalRuntimeReady",
            Self::CallInitHook => "CallInitHook",
            Self::CallMain => "CallMain",
            Self::CallFiniHook => "CallFiniHook",
            Self::CallRtldFiniHook => "CallRtldFiniHook",
            Self::Complete => "Complete",
            Self::Deny => "Deny",
            Self::FallbackHost => "FallbackHost",
        }
    }
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
        StartupCheckpoint::ResolveEnvp,
    ),
    (
        StartupCheckpoint::ResolveEnvp,
        StartupCheckpoint::BindProcessGlobals,
    ),
    (
        StartupCheckpoint::BindProcessGlobals,
        StartupCheckpoint::BootstrapHostSymbols,
    ),
    (
        StartupCheckpoint::BootstrapHostSymbols,
        StartupCheckpoint::InitHostStdio,
    ),
    (
        StartupCheckpoint::InitHostStdio,
        StartupCheckpoint::BootstrapHostLibio,
    ),
    (
        StartupCheckpoint::BootstrapHostLibio,
        StartupCheckpoint::PrewarmThreadSymbols,
    ),
    (
        StartupCheckpoint::PrewarmThreadSymbols,
        StartupCheckpoint::PrewarmAllocatorSymbols,
    ),
    (
        StartupCheckpoint::PrewarmAllocatorSymbols,
        StartupCheckpoint::SignalRuntimeReady,
    ),
    (
        StartupCheckpoint::SignalRuntimeReady,
        StartupCheckpoint::CallInitHook,
    ),
    (
        StartupCheckpoint::SignalRuntimeReady,
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
    (
        StartupCheckpoint::ClassifySecureMode,
        StartupCheckpoint::Deny,
    ),
    (
        StartupCheckpoint::CaptureInvariants,
        StartupCheckpoint::Deny,
    ),
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

/// Build-time certificate emitted by `build.rs` for the phase-0 startup DAG.
pub const STARTUP_INIT_ORDER_CERTIFICATE_JSON: &str = include_str!(concat!(
    env!("OUT_DIR"),
    "/startup_init_order_certificate.json"
));

/// Abstract capabilities that the bootstrap path acquires monotonically.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InitCapability {
    MembraneAdmission = 0,
    MainValidated = 1,
    ArgvValidated = 2,
    ArgvScanned = 3,
    ArgcBounded = 4,
    EnvpScanned = 5,
    AuxvScanned = 6,
    SecureModeKnown = 7,
    InvariantsCaptured = 8,
    EnvpResolved = 9,
    ProcessGlobalsBound = 10,
    HostSymbolsReady = 11,
    HostStdioReady = 12,
    HostLibioReady = 13,
    ThreadSymbolsReady = 14,
    AllocatorSymbolsReady = 15,
    RuntimeReady = 16,
    InitHookObserved = 17,
    MainCompleted = 18,
    FiniObserved = 19,
    RtldFiniObserved = 20,
}

impl InitCapability {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MembraneAdmission => "MembraneAdmission",
            Self::MainValidated => "MainValidated",
            Self::ArgvValidated => "ArgvValidated",
            Self::ArgvScanned => "ArgvScanned",
            Self::ArgcBounded => "ArgcBounded",
            Self::EnvpScanned => "EnvpScanned",
            Self::AuxvScanned => "AuxvScanned",
            Self::SecureModeKnown => "SecureModeKnown",
            Self::InvariantsCaptured => "InvariantsCaptured",
            Self::EnvpResolved => "EnvpResolved",
            Self::ProcessGlobalsBound => "ProcessGlobalsBound",
            Self::HostSymbolsReady => "HostSymbolsReady",
            Self::HostStdioReady => "HostStdioReady",
            Self::HostLibioReady => "HostLibioReady",
            Self::ThreadSymbolsReady => "ThreadSymbolsReady",
            Self::AllocatorSymbolsReady => "AllocatorSymbolsReady",
            Self::RuntimeReady => "RuntimeReady",
            Self::InitHookObserved => "InitHookObserved",
            Self::MainCompleted => "MainCompleted",
            Self::FiniObserved => "FiniObserved",
            Self::RtldFiniObserved => "RtldFiniObserved",
        }
    }

    #[must_use]
    pub const fn bit(self) -> u64 {
        1u64 << (self as u8)
    }
}

const ALL_INIT_CAPABILITIES: &[InitCapability] = &[
    InitCapability::MembraneAdmission,
    InitCapability::MainValidated,
    InitCapability::ArgvValidated,
    InitCapability::ArgvScanned,
    InitCapability::ArgcBounded,
    InitCapability::EnvpScanned,
    InitCapability::AuxvScanned,
    InitCapability::SecureModeKnown,
    InitCapability::InvariantsCaptured,
    InitCapability::EnvpResolved,
    InitCapability::ProcessGlobalsBound,
    InitCapability::HostSymbolsReady,
    InitCapability::HostStdioReady,
    InitCapability::HostLibioReady,
    InitCapability::ThreadSymbolsReady,
    InitCapability::AllocatorSymbolsReady,
    InitCapability::RuntimeReady,
    InitCapability::InitHookObserved,
    InitCapability::MainCompleted,
    InitCapability::FiniObserved,
    InitCapability::RtldFiniObserved,
];

/// Bitset over `InitCapability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InitCapabilitySet(u64);

impl InitCapabilitySet {
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn singleton(capability: InitCapability) -> Self {
        Self(capability.bit())
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    #[must_use]
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    #[must_use]
    pub const fn contains(self, capability: InitCapability) -> bool {
        (self.0 & capability.bit()) != 0
    }

    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        ALL_INIT_CAPABILITIES
            .iter()
            .copied()
            .filter(|capability| self.contains(*capability))
            .map(InitCapability::as_str)
            .collect()
    }
}

const fn capability_set(capabilities: &[InitCapability]) -> InitCapabilitySet {
    let mut bits = 0u64;
    let mut idx = 0usize;
    while idx < capabilities.len() {
        bits |= capabilities[idx].bit();
        idx += 1;
    }
    InitCapabilitySet(bits)
}

/// Abstract contract for a concrete startup checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupCheckpointContract {
    pub checkpoint: StartupCheckpoint,
    pub requires: InitCapabilitySet,
    pub provides: InitCapabilitySet,
}

impl StartupCheckpointContract {
    #[must_use]
    pub const fn new(
        checkpoint: StartupCheckpoint,
        requires: InitCapabilitySet,
        provides: InitCapabilitySet,
    ) -> Self {
        Self {
            checkpoint,
            requires,
            provides,
        }
    }
}

/// Canonical phase-0 Galois witness over the startup DAG.
pub const STARTUP_PHASE0_CHECKPOINT_CONTRACTS: &[StartupCheckpointContract] = &[
    StartupCheckpointContract::new(
        StartupCheckpoint::Entry,
        capability_set(&[]),
        capability_set(&[]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::MembraneGate,
        capability_set(&[]),
        capability_set(&[InitCapability::MembraneAdmission]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ValidateMainPointer,
        capability_set(&[InitCapability::MembraneAdmission]),
        capability_set(&[InitCapability::MainValidated]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ValidateArgvPointer,
        capability_set(&[InitCapability::MainValidated]),
        capability_set(&[InitCapability::ArgvValidated]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ScanArgvVector,
        capability_set(&[InitCapability::ArgvValidated]),
        capability_set(&[InitCapability::ArgvScanned]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ValidateArgcBound,
        capability_set(&[InitCapability::ArgvScanned]),
        capability_set(&[InitCapability::ArgcBounded]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ScanEnvpVector,
        capability_set(&[InitCapability::ArgcBounded]),
        capability_set(&[InitCapability::EnvpScanned]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ScanAuxvVector,
        capability_set(&[InitCapability::EnvpScanned]),
        capability_set(&[InitCapability::AuxvScanned]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ClassifySecureMode,
        capability_set(&[InitCapability::AuxvScanned]),
        capability_set(&[InitCapability::SecureModeKnown]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::CaptureInvariants,
        capability_set(&[InitCapability::SecureModeKnown]),
        capability_set(&[InitCapability::InvariantsCaptured]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::ResolveEnvp,
        capability_set(&[InitCapability::InvariantsCaptured]),
        capability_set(&[InitCapability::EnvpResolved]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::BindProcessGlobals,
        capability_set(&[InitCapability::EnvpResolved]),
        capability_set(&[InitCapability::ProcessGlobalsBound]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::BootstrapHostSymbols,
        capability_set(&[InitCapability::ProcessGlobalsBound]),
        capability_set(&[InitCapability::HostSymbolsReady]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::InitHostStdio,
        capability_set(&[InitCapability::HostSymbolsReady]),
        capability_set(&[InitCapability::HostStdioReady]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::BootstrapHostLibio,
        capability_set(&[InitCapability::HostStdioReady]),
        capability_set(&[InitCapability::HostLibioReady]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::PrewarmThreadSymbols,
        capability_set(&[InitCapability::HostLibioReady]),
        capability_set(&[InitCapability::ThreadSymbolsReady]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::PrewarmAllocatorSymbols,
        capability_set(&[InitCapability::ThreadSymbolsReady]),
        capability_set(&[InitCapability::AllocatorSymbolsReady]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::SignalRuntimeReady,
        capability_set(&[InitCapability::AllocatorSymbolsReady]),
        capability_set(&[InitCapability::RuntimeReady]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::CallInitHook,
        capability_set(&[InitCapability::RuntimeReady]),
        capability_set(&[InitCapability::InitHookObserved]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::CallMain,
        capability_set(&[InitCapability::RuntimeReady]),
        capability_set(&[InitCapability::MainCompleted]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::CallFiniHook,
        capability_set(&[InitCapability::MainCompleted]),
        capability_set(&[InitCapability::FiniObserved]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::CallRtldFiniHook,
        capability_set(&[InitCapability::MainCompleted]),
        capability_set(&[InitCapability::RtldFiniObserved]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::Complete,
        capability_set(&[InitCapability::MainCompleted]),
        capability_set(&[]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::Deny,
        capability_set(&[]),
        capability_set(&[]),
    ),
    StartupCheckpointContract::new(
        StartupCheckpoint::FallbackHost,
        capability_set(&[]),
        capability_set(&[]),
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupCapabilityError {
    InvalidTransition {
        from: StartupCheckpoint,
        to: StartupCheckpoint,
    },
    MissingCapabilities {
        checkpoint: StartupCheckpoint,
        missing: InitCapabilitySet,
        available: InitCapabilitySet,
    },
}

#[must_use]
pub fn startup_checkpoint_contract(checkpoint: StartupCheckpoint) -> StartupCheckpointContract {
    let mut idx = 0usize;
    while idx < STARTUP_PHASE0_CHECKPOINT_CONTRACTS.len() {
        let contract = STARTUP_PHASE0_CHECKPOINT_CONTRACTS[idx];
        if contract.checkpoint == checkpoint {
            return contract;
        }
        idx += 1;
    }
    unreachable!("missing startup checkpoint contract")
}

#[must_use]
pub fn missing_startup_capabilities(
    checkpoint: StartupCheckpoint,
    available: InitCapabilitySet,
) -> InitCapabilitySet {
    let contract = startup_checkpoint_contract(checkpoint);
    contract.requires.difference(available)
}

pub fn verify_startup_path_capabilities(
    path: &[StartupCheckpoint],
) -> Result<InitCapabilitySet, StartupCapabilityError> {
    if path.is_empty() {
        return Ok(InitCapabilitySet::empty());
    }

    for pair in path.windows(2) {
        if !STARTUP_PHASE0_DAG_EDGES.contains(&(pair[0], pair[1])) {
            return Err(StartupCapabilityError::InvalidTransition {
                from: pair[0],
                to: pair[1],
            });
        }
    }

    let mut available = InitCapabilitySet::empty();
    for checkpoint in path {
        let contract = startup_checkpoint_contract(*checkpoint);
        let missing = contract.requires.difference(available);
        if !missing.is_empty() {
            return Err(StartupCapabilityError::MissingCapabilities {
                checkpoint: *checkpoint,
                missing,
                available,
            });
        }
        available = available.union(contract.provides);
    }

    Ok(available)
}

#[must_use]
pub fn allowed_startup_checkpoints(available: InitCapabilitySet) -> Vec<StartupCheckpoint> {
    STARTUP_PHASE0_CHECKPOINT_CONTRACTS
        .iter()
        .filter(|contract| available.contains_all(contract.requires))
        .map(|contract| contract.checkpoint)
        .collect()
}

#[must_use]
pub fn startup_init_order_certificate_json() -> &'static str {
    STARTUP_INIT_ORDER_CERTIFICATE_JSON
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
    use serde_json::Value;

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

    #[test]
    fn startup_capability_flow_accepts_canonical_allow_path() {
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
            StartupCheckpoint::ResolveEnvp,
            StartupCheckpoint::BindProcessGlobals,
            StartupCheckpoint::BootstrapHostSymbols,
            StartupCheckpoint::InitHostStdio,
            StartupCheckpoint::BootstrapHostLibio,
            StartupCheckpoint::PrewarmThreadSymbols,
            StartupCheckpoint::PrewarmAllocatorSymbols,
            StartupCheckpoint::SignalRuntimeReady,
            StartupCheckpoint::CallInitHook,
            StartupCheckpoint::CallMain,
            StartupCheckpoint::CallFiniHook,
            StartupCheckpoint::CallRtldFiniHook,
            StartupCheckpoint::Complete,
        ];
        let available = verify_startup_path_capabilities(&path)
            .expect("canonical phase-0 bootstrap route should satisfy capability order");
        assert!(available.contains(InitCapability::RuntimeReady));
        assert!(available.contains(InitCapability::MainCompleted));
        assert!(available.contains(InitCapability::RtldFiniObserved));
    }

    #[test]
    fn startup_capability_flow_detects_swapped_bind_globals_bug() {
        let prefix = [
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
        ];
        let available = verify_startup_path_capabilities(&prefix)
            .expect("prefix up to invariant capture should be valid");
        let missing =
            missing_startup_capabilities(StartupCheckpoint::BindProcessGlobals, available);
        assert!(missing.contains(InitCapability::EnvpResolved));
        assert_eq!(missing.names(), vec!["EnvpResolved"]);
    }

    #[test]
    fn startup_capability_galois_concretization_exposes_next_step() {
        let prefix = [
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
            StartupCheckpoint::ResolveEnvp,
            StartupCheckpoint::BindProcessGlobals,
        ];
        let available = verify_startup_path_capabilities(&prefix)
            .expect("prefix through process-global binding should be valid");
        let allowed = allowed_startup_checkpoints(available);
        assert!(allowed.contains(&StartupCheckpoint::BootstrapHostSymbols));
        assert!(!allowed.contains(&StartupCheckpoint::CallMain));
    }

    #[test]
    fn embedded_startup_certificate_covers_checkpoint_and_symbol_graphs() {
        let certificate: Value = serde_json::from_str(startup_init_order_certificate_json())
            .expect("startup certificate must be valid JSON");
        let checkpoint_contracts = certificate
            .pointer("/checkpoint_graph/contracts")
            .and_then(Value::as_array)
            .expect("checkpoint contracts should exist");
        let symbol_nodes = certificate
            .pointer("/self_hosting_symbol_graph/nodes")
            .and_then(Value::as_array)
            .expect("self-hosting symbol graph should exist");
        let witness = certificate
            .pointer("/witness_sha256")
            .and_then(Value::as_str)
            .expect("witness hash should exist");

        assert!(checkpoint_contracts.len() >= 15);
        assert!(symbol_nodes.len() >= 15);
        assert_eq!(
            certificate
                .pointer("/checkpoint_graph/acyclic")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            certificate
                .pointer("/self_hosting_symbol_graph/acyclic")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(witness.len(), 64);
    }
}
