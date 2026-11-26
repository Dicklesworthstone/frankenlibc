//! Shared startup/bootstrap helpers used by phase-0 CRT plumbing.

use std::ffi::c_int;

/// Maximum number of argv/envp/auxv entries scanned in phase-0 startup.
pub const MAX_STARTUP_SCAN: usize = 4096;

/// Native ELF64 file-header size, shared by raw startup reads and validation.
pub(crate) const EXECUTABLE_ELF_HEADER_BYTES: usize = 64;

/// Recover the load bias of an executable without the optional PT_PHDR. The file
/// header comes from /proc/self/exe; the program headers and addresses come from
/// the kernel auxv. Matching both views avoids guessing an ELF-header address or
/// assuming that the program-header table immediately follows the ELF header.
pub(crate) fn executable_load_bias_from_header(
    header: &[u8; EXECUTABLE_ELF_HEADER_BYTES],
    phdr_addr: usize,
    phdrs: &[libc::Elf64_Phdr],
    entry: usize,
) -> Result<usize, ()> {
    let native_machine = if cfg!(target_arch = "x86_64") {
        62u16
    } else if cfg!(target_arch = "aarch64") {
        183u16
    } else {
        return Err(());
    };
    let phent = std::mem::size_of::<libc::Elf64_Phdr>();
    let image_type = u16::from_le_bytes(header[16..18].try_into().map_err(|_| ())?);
    if std::mem::size_of::<usize>() != 8
        || &header[..7] != b"\x7fELF\x02\x01\x01"
        || !matches!(image_type, libc::ET_EXEC | libc::ET_DYN)
        || u16::from_le_bytes(header[18..20].try_into().map_err(|_| ())?) != native_machine
        || u32::from_le_bytes(header[20..24].try_into().map_err(|_| ())?) != 1
        || usize::from(u16::from_le_bytes(
            header[52..54].try_into().map_err(|_| ())?,
        )) != EXECUTABLE_ELF_HEADER_BYTES
        || usize::from(u16::from_le_bytes(
            header[54..56].try_into().map_err(|_| ())?,
        )) != phent
        || usize::from(u16::from_le_bytes(
            header[56..58].try_into().map_err(|_| ())?,
        )) != phdrs.len()
        || phdrs.is_empty()
        || phdrs.len() > MAX_STARTUP_SCAN
        || phdr_addr == 0
        || !phdr_addr.is_multiple_of(std::mem::align_of::<libc::Elf64_Phdr>())
    {
        return Err(());
    }
    let file_entry = usize::try_from(u64::from_le_bytes(
        header[24..32].try_into().map_err(|_| ())?,
    ))
    .map_err(|_| ())?;
    let phoff = usize::try_from(u64::from_le_bytes(
        header[32..40].try_into().map_err(|_| ())?,
    ))
    .map_err(|_| ())?;
    // Linux supplies the relocated entry in AT_ENTRY. Accept its displacement
    // only if a readable, file-backed PT_LOAD maps the complete table to the
    // independent AT_PHDR address at exactly the same bias.
    let bias = entry.checked_sub(file_entry).ok_or(())?;
    if (image_type == libc::ET_EXEC && bias != 0) || phoff < EXECUTABLE_ELF_HEADER_BYTES {
        return Err(());
    }
    let table_bytes = phdrs.len().checked_mul(phent).ok_or(())?;
    let table_file_end = phoff.checked_add(table_bytes).ok_or(())?;
    let table_memory_end = phdr_addr.checked_add(table_bytes).ok_or(())?;
    let mut headers_mapped = false;
    let mut entry_mapped = false;
    for segment in phdrs.iter().filter(|p| p.p_type == libc::PT_LOAD) {
        let start = bias
            .checked_add(usize::try_from(segment.p_vaddr).map_err(|_| ())?)
            .ok_or(())?;
        let memory_size = usize::try_from(segment.p_memsz).map_err(|_| ())?;
        let file_start = usize::try_from(segment.p_offset).map_err(|_| ())?;
        let file_size = usize::try_from(segment.p_filesz).map_err(|_| ())?;
        let memory_end = start.checked_add(memory_size).ok_or(())?;
        let file_end = file_start.checked_add(file_size).ok_or(())?;
        if file_size > memory_size
            || (segment.p_align > 1
                && (!segment.p_align.is_power_of_two()
                    || !(bias as u64).is_multiple_of(segment.p_align)
                    || segment.p_vaddr % segment.p_align != segment.p_offset % segment.p_align))
        {
            return Err(());
        }
        if segment.p_flags & libc::PF_R != 0 && phoff >= file_start && table_file_end <= file_end {
            let mapped_table = start.checked_add(phoff - file_start).ok_or(())?;
            headers_mapped |= mapped_table == phdr_addr && table_memory_end <= memory_end;
        }
        entry_mapped |= segment.p_flags & libc::PF_X != 0 && entry >= start && entry < memory_end;
    }
    if headers_mapped && entry_mapped {
        Ok(bias)
    } else {
        Err(())
    }
}

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
            StartupCheckpoint::ResolveEnvp,
            StartupCheckpoint::BindProcessGlobals,
            StartupCheckpoint::BootstrapHostSymbols,
            StartupCheckpoint::InitHostStdio,
            StartupCheckpoint::BootstrapHostLibio,
            StartupCheckpoint::PrewarmThreadSymbols,
            StartupCheckpoint::PrewarmAllocatorSymbols,
            StartupCheckpoint::SignalRuntimeReady,
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

#[cfg(test)]
mod executable_init_tests {
    use super::{EXECUTABLE_ELF_HEADER_BYTES, executable_load_bias_from_header};

    fn fixed_image(
        phoff: u64,
        table_load_offset: u64,
    ) -> (
        [u8; EXECUTABLE_ELF_HEADER_BYTES],
        [libc::Elf64_Phdr; 3],
        usize,
        usize,
    ) {
        let data = libc::Elf64_Phdr {
            p_type: libc::PT_LOAD,
            p_flags: libc::PF_R,
            p_offset: table_load_offset,
            p_vaddr: 0x400000,
            p_paddr: 0x400000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        };
        let code = libc::Elf64_Phdr {
            p_type: libc::PT_LOAD,
            p_flags: libc::PF_R | libc::PF_X,
            p_offset: table_load_offset + 0x1000,
            p_vaddr: 0x401000,
            p_paddr: 0x401000,
            p_filesz: 0x1000,
            p_memsz: 0x1000,
            p_align: 0x1000,
        };
        // A removed optional PT_PHDR entry leaves the table count unchanged.
        let removed = libc::Elf64_Phdr {
            p_type: libc::PT_NULL,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        };
        let entry = 0x401080usize;
        let mut header = [0u8; EXECUTABLE_ELF_HEADER_BYTES];
        header[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        header[16..18].copy_from_slice(&libc::ET_EXEC.to_le_bytes());
        let machine = if cfg!(target_arch = "x86_64") {
            62u16
        } else {
            183u16
        };
        header[18..20].copy_from_slice(&machine.to_le_bytes());
        header[20..24].copy_from_slice(&1u32.to_le_bytes());
        header[24..32].copy_from_slice(&(entry as u64).to_le_bytes());
        header[32..40].copy_from_slice(&phoff.to_le_bytes());
        header[52..54].copy_from_slice(&(EXECUTABLE_ELF_HEADER_BYTES as u16).to_le_bytes());
        header[54..56]
            .copy_from_slice(&(std::mem::size_of::<libc::Elf64_Phdr>() as u16).to_le_bytes());
        header[56..58].copy_from_slice(&3u16.to_le_bytes());
        let phdr_addr = 0x400000 + (phoff - table_load_offset) as usize;
        (header, [data, code, removed], phdr_addr, entry)
    }

    #[test]
    fn fixed_executable_without_phdr_accepts_nonstandard_table_offset() {
        for phoff in [64, 0x180, 0x800] {
            let (header, phdrs, address, entry) = fixed_image(phoff, 0);
            assert_eq!(
                executable_load_bias_from_header(&header, address, &phdrs, entry),
                Ok(0)
            );
        }
    }

    #[test]
    fn fixed_executable_without_phdr_translates_nonzero_segment_file_offset() {
        let (header, phdrs, address, entry) = fixed_image(0x2180, 0x2000);
        assert_eq!(address, 0x400180);
        assert_eq!(
            executable_load_bias_from_header(&header, address, &phdrs, entry),
            Ok(0)
        );
    }

    #[test]
    fn static_pie_without_phdr_matches_entry_and_table_at_one_bias() {
        let (mut header, phdrs, table, entry) = fixed_image(0x2180, 0x2000);
        header[16..18].copy_from_slice(&libc::ET_DYN.to_le_bytes());
        for bias in [0x2000, 0x7fab_1200_0000] {
            assert_eq!(
                executable_load_bias_from_header(&header, table + bias, &phdrs, entry + bias),
                Ok(bias)
            );
            assert_eq!(
                executable_load_bias_from_header(&header, table + bias, &phdrs, entry + bias + 8),
                Err(())
            );
        }
        assert_eq!(
            executable_load_bias_from_header(&header, table, &phdrs, entry - 1),
            Err(())
        );
        assert_eq!(
            executable_load_bias_from_header(&header, table + 8, &phdrs, entry + 8),
            Err(())
        );
        header[16..18].copy_from_slice(&libc::ET_EXEC.to_le_bytes());
        assert_eq!(
            executable_load_bias_from_header(&header, table + 0x2000, &phdrs, entry + 0x2000),
            Err(())
        );
    }

    #[test]
    fn executable_without_phdr_rejects_malformed_headers() {
        let (header, phdrs, address, entry) = fixed_image(0x180, 0);
        for (offset, replacement) in [
            (0, b'?'), // Magic.
            (4, 1),    // ELF32.
            (5, 2),    // Big-endian metadata.
            (6, 0),    // Identification version.
            (16, 4),   // ET_CORE is not an executable image.
            (18, 0),   // Wrong machine.
            (20, 0),   // ELF version.
            (52, 63),  // Truncated ELF header layout.
            (54, 55),  // Wrong program-header entry size.
            (56, 2),   // File/auxv program-header counts disagree.
        ] {
            let mut malformed = header;
            malformed[offset] = replacement;
            assert_eq!(
                executable_load_bias_from_header(&malformed, address, &phdrs, entry),
                Err(()),
                "accepted malformed ELF header field at {offset}"
            );
        }
        let mut overlapping = header;
        overlapping[32..40].copy_from_slice(&32u64.to_le_bytes());
        assert_eq!(
            executable_load_bias_from_header(&overlapping, 0x400020, &phdrs, entry),
            Err(())
        );
    }

    #[test]
    fn fixed_executable_without_phdr_checks_auxv_addresses() {
        let (header, phdrs, address, entry) = fixed_image(0x180, 0);
        for wrong_address in [0, address + 1, address + 8, address + 0x100000] {
            assert_eq!(
                executable_load_bias_from_header(&header, wrong_address, &phdrs, entry),
                Err(())
            );
        }
        assert_eq!(
            executable_load_bias_from_header(&header, address, &phdrs, entry + 1),
            Err(())
        );
        assert_eq!(
            executable_load_bias_from_header(&header, address, &[], entry),
            Err(())
        );
    }

    #[test]
    fn fixed_executable_without_phdr_requires_complete_readable_file_backing() {
        for case in 0..4 {
            let (header, mut phdrs, address, entry) = fixed_image(0x180, 0);
            match case {
                0 => phdrs[0].p_flags = libc::PF_X,
                1 => {
                    // All but the last table byte is file-backed; memory alone
                    // is insufficient even though the PT_LOAD remains readable.
                    phdrs[0].p_filesz = 0x180 + std::mem::size_of_val(&phdrs) as u64 - 1;
                }
                2 => phdrs[0].p_memsz = phdrs[0].p_filesz - 1,
                3 => {
                    phdrs[0].p_offset = 0x188;
                    phdrs[0].p_align = 1;
                }
                _ => unreachable!(),
            }
            assert_eq!(
                executable_load_bias_from_header(&header, address, &phdrs, entry),
                Err(()),
                "accepted invalid table mapping case {case}"
            );
        }
    }

    #[test]
    fn fixed_executable_without_phdr_requires_executable_entry_mapping() {
        let (header, mut phdrs, address, entry) = fixed_image(0x180, 0);
        phdrs[1].p_flags = libc::PF_R;
        assert_eq!(
            executable_load_bias_from_header(&header, address, &phdrs, entry),
            Err(())
        );
        for invalid_entry in [0x400100u64, 0x402000] {
            let (mut header, phdrs, address, _) = fixed_image(0x180, 0);
            header[24..32].copy_from_slice(&invalid_entry.to_le_bytes());
            assert_eq!(
                executable_load_bias_from_header(&header, address, &phdrs, invalid_entry as usize),
                Err(())
            );
        }
    }

    #[test]
    fn fixed_executable_without_phdr_rejects_overflow_and_invalid_alignment() {
        let (mut header, phdrs, address, entry) = fixed_image(0x180, 0);
        header[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            executable_load_bias_from_header(&header, address, &phdrs, entry),
            Err(())
        );
        let (header, phdrs, _, entry) = fixed_image(0x180, 0);
        assert_eq!(
            executable_load_bias_from_header(&header, usize::MAX - 7, &phdrs, entry),
            Err(())
        );
        for case in 0..4 {
            let (header, mut phdrs, address, entry) = fixed_image(0x180, 0);
            match case {
                0 => phdrs[0].p_vaddr = u64::MAX - 0x7ff,
                1 => phdrs[0].p_offset = u64::MAX - 0x7ff,
                2 => phdrs[0].p_align = 3,
                3 => phdrs[0].p_vaddr += 1,
                _ => unreachable!(),
            }
            assert_eq!(
                executable_load_bias_from_header(&header, address, &phdrs, entry),
                Err(()),
                "accepted overflow/alignment case {case}"
            );
        }
    }
}
