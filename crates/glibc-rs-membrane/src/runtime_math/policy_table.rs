//! Proof-carrying policy table loader/verifier (PCPT / `.pcpt` artifacts).
//!
//! Bead: `bd-20s`
//!
//! This module implements deterministic parsing and init-time verification of
//! a compact offline-synthesized policy table artifact described in:
//! `runtime_math/proof_carrying_policy_tables.md`.
//!
//! Runtime constraints:
//! - no file I/O on hot paths (artifact is embedded or loaded once at init)
//! - verification is bounded and deterministic
//! - failures are conservative: caller must fall back to built-in policy

use core::fmt;

use crate::config::SafetyLevel;
use crate::heal::HealingAction;

use super::{ApiFamily, ValidationProfile};

const MAGIC: &[u8; 8] = b"PCPTv001";

// Header is fixed-size, little-endian, and intentionally packed (no padding).
//
// Layout (bytes):
// - magic[8]
// - schema_version: u16
// - hash_alg: u8
// - key_spec_id: u16
// - cell_spec_id: u16
// - table_len: u32
// - table_bytes: u32
// - table_hash[32]
// - meta_hash[32]
// - reserved[32]
const HEADER_LEN: usize = 8 + 2 + 1 + 2 + 2 + 4 + 4 + 32 + 32 + 32; // 119

const SCHEMA_VERSION_V1: u16 = 1;
const KEY_SPEC_ID_V1: u16 = 1;
const CELL_SPEC_ID_V1: u16 = 1;

const RISK_BUCKETS: usize = 16;
const BUDGET_BUCKETS: usize = 8;
const CONSISTENCY_BUCKETS: usize = 4;

const CELL_BYTES_V1: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HashAlg {
    Blake3_256 = 1,
    Sha256 = 2,
}

impl HashAlg {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Blake3_256),
            2 => Some(Self::Sha256),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    schema_version: u16,
    hash_alg: HashAlg,
    key_spec_id: u16,
    cell_spec_id: u16,
    table_len: u32,
    table_bytes: u32,
    table_hash: [u8; 32],
    meta_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum PcptAction {
    Allow = 0,
    FullValidate = 1,
    Repair = 2,
    Deny = 3,
}

impl PcptAction {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Allow),
            1 => Some(Self::FullValidate),
            2 => Some(Self::Repair),
            3 => Some(Self::Deny),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum RepairKind {
    None = 0,
    ClampSize = 1,
    TruncateWithNull = 2,
    IgnoreDoubleFree = 3,
    IgnoreForeignFree = 4,
    ReallocAsMalloc = 5,
    ReturnSafeDefault = 6,
    UpgradeToSafeVariant = 7,
}

impl RepairKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::ClampSize),
            2 => Some(Self::TruncateWithNull),
            3 => Some(Self::IgnoreDoubleFree),
            4 => Some(Self::IgnoreForeignFree),
            5 => Some(Self::ReallocAsMalloc),
            6 => Some(Self::ReturnSafeDefault),
            7 => Some(Self::UpgradeToSafeVariant),
            _ => None,
        }
    }

    #[must_use]
    fn as_healing_action(self) -> HealingAction {
        match self {
            Self::None => HealingAction::None,
            Self::ClampSize => HealingAction::ClampSize {
                requested: 0,
                clamped: 0,
            },
            Self::TruncateWithNull => HealingAction::TruncateWithNull {
                requested: 0,
                truncated: 0,
            },
            Self::IgnoreDoubleFree => HealingAction::IgnoreDoubleFree,
            Self::IgnoreForeignFree => HealingAction::IgnoreForeignFree,
            Self::ReallocAsMalloc => HealingAction::ReallocAsMalloc { size: 0 },
            Self::ReturnSafeDefault => HealingAction::ReturnSafeDefault,
            Self::UpgradeToSafeVariant => HealingAction::UpgradeToSafeVariant,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CellV1 {
    profile: ValidationProfile,
    action: PcptAction,
    repair: RepairKind,
    flags: u8,
}

#[derive(Debug, Clone)]
pub struct PolicyTableSummary {
    pub schema_version: u16,
    pub hash_alg: HashAlg,
    pub key_spec_id: u16,
    pub cell_spec_id: u16,
    pub table_len: u32,
    pub table_hash_hex: String,
    pub meta_hash_hex: String,
    pub generator_build_info: Option<String>,
    pub offline_proof_digest_hex: Option<String>,
    pub invariant_manifest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifiedPolicyTable<'a> {
    header: Header,
    table_bytes: &'a [u8],
    meta_bytes: &'a [u8],
    summary: PolicyTableSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyTableError {
    TooShort,
    BadMagic,
    UnsupportedSchema { schema_version: u16 },
    UnsupportedHashAlg { hash_alg: u8 },
    UnsupportedKeySpec { key_spec_id: u16 },
    UnsupportedCellSpec { cell_spec_id: u16 },
    ReservedNonZero,
    LengthMismatch,
    HashMismatch { which: &'static str },
    MissingRequiredTlv { tlv_type: u16 },
    MalformedTlv,
    BadCellEncoding { idx: usize },
    StrictRepairNotAllowed { idx: usize },
    DenyMustNotRepair { idx: usize },
    RiskMonotonicityViolation { mode: SafetyLevel, family: ApiFamily, idx: usize },
    ModeRefinementViolation { family: ApiFamily, idx: usize },
}

impl fmt::Display for PolicyTableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "pcpt: too short"),
            Self::BadMagic => write!(f, "pcpt: bad magic"),
            Self::UnsupportedSchema { schema_version } => {
                write!(f, "pcpt: unsupported schema_version={schema_version}")
            }
            Self::UnsupportedHashAlg { hash_alg } => write!(f, "pcpt: unsupported hash_alg={hash_alg}"),
            Self::UnsupportedKeySpec { key_spec_id } => {
                write!(f, "pcpt: unsupported key_spec_id={key_spec_id}")
            }
            Self::UnsupportedCellSpec { cell_spec_id } => {
                write!(f, "pcpt: unsupported cell_spec_id={cell_spec_id}")
            }
            Self::ReservedNonZero => write!(f, "pcpt: reserved bytes must be zero"),
            Self::LengthMismatch => write!(f, "pcpt: length mismatch"),
            Self::HashMismatch { which } => write!(f, "pcpt: hash mismatch ({which})"),
            Self::MissingRequiredTlv { tlv_type } => write!(f, "pcpt: missing required TLV type=0x{tlv_type:04X}"),
            Self::MalformedTlv => write!(f, "pcpt: malformed TLV stream"),
            Self::BadCellEncoding { idx } => write!(f, "pcpt: bad cell encoding idx={idx}"),
            Self::StrictRepairNotAllowed { idx } => write!(f, "pcpt: strict row has Repair action idx={idx}"),
            Self::DenyMustNotRepair { idx } => write!(f, "pcpt: Deny row must have repair=None idx={idx}"),
            Self::RiskMonotonicityViolation { mode, family, idx } => {
                write!(f, "pcpt: risk monotonicity violation mode={mode:?} family={family:?} idx={idx}")
            }
            Self::ModeRefinementViolation { family, idx } => {
                write!(f, "pcpt: strict vs hardened refinement violation family={family:?} idx={idx}")
            }
        }
    }
}

impl std::error::Error for PolicyTableError {}

impl<'a> VerifiedPolicyTable<'a> {
    #[must_use]
    pub fn summary(&self) -> &PolicyTableSummary {
        &self.summary
    }

    #[must_use]
    pub fn cell_v1(&self, idx: usize) -> Option<CellV1> {
        if idx >= self.header.table_len as usize {
            return None;
        }
        let off = idx.checked_mul(CELL_BYTES_V1)?;
        let b = self.table_bytes.get(off..off + CELL_BYTES_V1)?;

        let profile = match b[0] {
            0 => ValidationProfile::Fast,
            1 => ValidationProfile::Full,
            _ => return None,
        };
        let action = PcptAction::from_u8(b[1])?;
        let repair = RepairKind::from_u8(b[2])?;
        Some(CellV1 {
            profile,
            action,
            repair,
            flags: b[3],
        })
    }
}

/// Verify a `.pcpt` artifact from in-memory bytes.
///
/// This function does not perform file I/O; callers are expected to embed the
/// artifact (e.g. `include_bytes!`) or load it once during init.
pub fn verify_pcpt(bytes: &[u8]) -> Result<VerifiedPolicyTable<'_>, PolicyTableError> {
    if bytes.len() < HEADER_LEN {
        return Err(PolicyTableError::TooShort);
    }

    if &bytes[0..8] != MAGIC {
        return Err(PolicyTableError::BadMagic);
    }

    let schema_version = read_u16_le(bytes, 8)?;
    if schema_version != SCHEMA_VERSION_V1 {
        return Err(PolicyTableError::UnsupportedSchema { schema_version });
    }

    let hash_alg_raw = bytes[10];
    let hash_alg = HashAlg::from_u8(hash_alg_raw)
        .ok_or(PolicyTableError::UnsupportedHashAlg { hash_alg: hash_alg_raw })?;

    let key_spec_id = read_u16_le(bytes, 11)?;
    if key_spec_id != KEY_SPEC_ID_V1 {
        return Err(PolicyTableError::UnsupportedKeySpec { key_spec_id });
    }

    let cell_spec_id = read_u16_le(bytes, 13)?;
    if cell_spec_id != CELL_SPEC_ID_V1 {
        return Err(PolicyTableError::UnsupportedCellSpec { cell_spec_id });
    }

    let table_len = read_u32_le(bytes, 15)?;
    let table_bytes = read_u32_le(bytes, 19)?;

    let expected_len =
        2u64 * ApiFamily::COUNT as u64 * RISK_BUCKETS as u64 * BUDGET_BUCKETS as u64 * CONSISTENCY_BUCKETS as u64;
    if u64::from(table_len) != expected_len {
        return Err(PolicyTableError::LengthMismatch);
    }
    if table_bytes as usize != (table_len as usize).saturating_mul(CELL_BYTES_V1) {
        return Err(PolicyTableError::LengthMismatch);
    }

    let mut table_hash = [0u8; 32];
    table_hash.copy_from_slice(bytes.get(23..55).ok_or(PolicyTableError::TooShort)?);
    let mut meta_hash = [0u8; 32];
    meta_hash.copy_from_slice(bytes.get(55..87).ok_or(PolicyTableError::TooShort)?);

    let reserved = bytes.get(87..HEADER_LEN).ok_or(PolicyTableError::TooShort)?;
    if reserved.iter().any(|&b| b != 0) {
        return Err(PolicyTableError::ReservedNonZero);
    }

    let table_off = HEADER_LEN;
    let table_end = table_off
        .checked_add(table_bytes as usize)
        .ok_or(PolicyTableError::LengthMismatch)?;
    if bytes.len() < table_end {
        return Err(PolicyTableError::TooShort);
    }
    let table_slice = &bytes[table_off..table_end];
    let meta_slice = &bytes[table_end..];

    // Hash checks.
    let computed_table_hash = hash_256(hash_alg, table_slice);
    if computed_table_hash != table_hash {
        return Err(PolicyTableError::HashMismatch { which: "table_hash" });
    }
    let computed_meta_hash = hash_256(hash_alg, meta_slice);
    if computed_meta_hash != meta_hash {
        return Err(PolicyTableError::HashMismatch { which: "meta_hash" });
    }

    let header = Header {
        schema_version,
        hash_alg,
        key_spec_id,
        cell_spec_id,
        table_len,
        table_bytes,
        table_hash,
        meta_hash,
    };

    // Parse metadata TLVs (for summary + minimal required presence).
    let tlvs = parse_tlvs(meta_slice)?;
    let (build_info, proof_digest, invariants) = extract_required_tlvs(&tlvs)?;

    // Cell sanity and invariants.
    verify_cells_and_invariants(&header, table_slice)?;

    let summary = PolicyTableSummary {
        schema_version,
        hash_alg,
        key_spec_id,
        cell_spec_id,
        table_len,
        table_hash_hex: to_hex(&table_hash),
        meta_hash_hex: to_hex(&meta_hash),
        generator_build_info: build_info,
        offline_proof_digest_hex: proof_digest.map(|d| to_hex(&d)),
        invariant_manifest: invariants,
    };

    Ok(VerifiedPolicyTable {
        header,
        table_bytes: table_slice,
        meta_bytes: meta_slice,
        summary,
    })
}

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    t: u16,
    v: &'a [u8],
}

fn parse_tlvs(meta: &[u8]) -> Result<Vec<Tlv<'_>>, PolicyTableError> {
    let mut tlvs = Vec::new();
    let mut off = 0usize;
    while off < meta.len() {
        if meta.len() - off < 4 {
            return Err(PolicyTableError::MalformedTlv);
        }
        let t = read_u16_le(meta, off)?;
        let len = read_u16_le(meta, off + 2)? as usize;
        off = off.checked_add(4).ok_or(PolicyTableError::MalformedTlv)?;
        let end = off.checked_add(len).ok_or(PolicyTableError::MalformedTlv)?;
        let v = meta.get(off..end).ok_or(PolicyTableError::MalformedTlv)?;
        tlvs.push(Tlv { t, v });
        off = end;
    }
    Ok(tlvs)
}

fn extract_required_tlvs(tlvs: &[Tlv<'_>]) -> Result<(Option<String>, Option<[u8; 32]>, Option<String>), PolicyTableError>
{
    let mut build_info = None;
    let mut proof_digest = None;
    let mut invariants = None;

    for tlv in tlvs {
        match tlv.t {
            0x0001 => {
                if build_info.is_none() {
                    build_info = Some(ascii_lossy_trim(tlv.v));
                }
            }
            0x0002 => {
                if proof_digest.is_none() {
                    if tlv.v.len() != 32 {
                        return Err(PolicyTableError::MalformedTlv);
                    }
                    let mut d = [0u8; 32];
                    d.copy_from_slice(tlv.v);
                    proof_digest = Some(d);
                }
            }
            0x0003 => {
                if invariants.is_none() {
                    invariants = Some(ascii_lossy_trim(tlv.v));
                }
            }
            _ => {}
        }
    }

    if build_info.is_none() {
        return Err(PolicyTableError::MissingRequiredTlv { tlv_type: 0x0001 });
    }
    if proof_digest.is_none() {
        return Err(PolicyTableError::MissingRequiredTlv { tlv_type: 0x0002 });
    }
    if invariants.is_none() {
        return Err(PolicyTableError::MissingRequiredTlv { tlv_type: 0x0003 });
    }

    Ok((build_info, proof_digest, invariants))
}

fn verify_cells_and_invariants(header: &Header, table: &[u8]) -> Result<(), PolicyTableError> {
    if table.len() != header.table_bytes as usize {
        return Err(PolicyTableError::LengthMismatch);
    }

    let table_len = header.table_len as usize;
    for idx in 0..table_len {
        let cell = decode_cell_v1(table, idx).ok_or(PolicyTableError::BadCellEncoding { idx })?;

        let is_strict_row = idx_is_strict_row(idx);
        if is_strict_row {
            // flags bit0 must be set for strict rows.
            if (cell.flags & 0x01) == 0 {
                return Err(PolicyTableError::BadCellEncoding { idx });
            }
            if matches!(cell.action, PcptAction::Repair) {
                return Err(PolicyTableError::StrictRepairNotAllowed { idx });
            }
        }

        if matches!(cell.action, PcptAction::Deny) && !matches!(cell.repair, RepairKind::None) {
            return Err(PolicyTableError::DenyMustNotRepair { idx });
        }
    }

    // Risk monotonicity (per mode,family,budget,consistency).
    for mode in [SafetyLevel::Strict, SafetyLevel::Hardened] {
        for family_idx in 0..ApiFamily::COUNT {
            let family = family_from_index(family_idx);
            for budget in 0..BUDGET_BUCKETS {
                for consistency in 0..CONSISTENCY_BUCKETS {
                    let mut prev_profile_rank = 0u8;
                    let mut prev_action_rank = 0u8;
                    for risk_bucket in 0..RISK_BUCKETS {
                        let idx = key_v1_index(mode, family, risk_bucket as u8, budget as u8, consistency as u8);
                        let cell =
                            decode_cell_v1(table, idx).ok_or(PolicyTableError::BadCellEncoding { idx })?;

                        let profile_rank = match cell.profile {
                            ValidationProfile::Fast => 0,
                            ValidationProfile::Full => 1,
                        };
                        let action_rank = action_rank(mode, cell.action).ok_or(PolicyTableError::BadCellEncoding { idx })?;

                        if risk_bucket > 0
                            && (profile_rank < prev_profile_rank || action_rank < prev_action_rank)
                        {
                            return Err(PolicyTableError::RiskMonotonicityViolation {
                                mode,
                                family,
                                idx,
                            });
                        }
                        prev_profile_rank = profile_rank;
                        prev_action_rank = action_rank;
                    }
                }
            }
        }
    }

    // Mode refinement (cheap, conservative):
    // If hardened allows something, strict must not be more restrictive.
    for family_idx in 0..ApiFamily::COUNT {
        let family = family_from_index(family_idx);
        for risk_bucket in 0..RISK_BUCKETS {
            for budget in 0..BUDGET_BUCKETS {
                for consistency in 0..CONSISTENCY_BUCKETS {
                    let s_idx = key_v1_index(
                        SafetyLevel::Strict,
                        family,
                        risk_bucket as u8,
                        budget as u8,
                        consistency as u8,
                    );
                    let h_idx = key_v1_index(
                        SafetyLevel::Hardened,
                        family,
                        risk_bucket as u8,
                        budget as u8,
                        consistency as u8,
                    );
                    let s = decode_cell_v1(table, s_idx)
                        .ok_or(PolicyTableError::BadCellEncoding { idx: s_idx })?;
                    let h = decode_cell_v1(table, h_idx)
                        .ok_or(PolicyTableError::BadCellEncoding { idx: h_idx })?;

                    if matches!(h.action, PcptAction::Allow) && !matches!(s.action, PcptAction::Allow) {
                        return Err(PolicyTableError::ModeRefinementViolation { family, idx: s_idx });
                    }
                    if matches!(h.action, PcptAction::FullValidate)
                        && matches!(s.action, PcptAction::Deny)
                    {
                        return Err(PolicyTableError::ModeRefinementViolation { family, idx: s_idx });
                    }

                    // Profile refinement: strict should not be more restrictive than hardened.
                    if matches!(h.profile, ValidationProfile::Fast) && matches!(s.profile, ValidationProfile::Full) {
                        return Err(PolicyTableError::ModeRefinementViolation { family, idx: s_idx });
                    }
                }
            }
        }
    }

    Ok(())
}

fn decode_cell_v1(table: &[u8], idx: usize) -> Option<CellV1> {
    let off = idx.checked_mul(CELL_BYTES_V1)?;
    let b = table.get(off..off + CELL_BYTES_V1)?;

    let profile = match b[0] {
        0 => ValidationProfile::Fast,
        1 => ValidationProfile::Full,
        _ => return None,
    };
    let action = PcptAction::from_u8(b[1])?;
    let repair = RepairKind::from_u8(b[2])?;
    Some(CellV1 {
        profile,
        action,
        repair,
        flags: b[3],
    })
}

fn idx_is_strict_row(idx: usize) -> bool {
    let per_mode = ApiFamily::COUNT * RISK_BUCKETS * BUDGET_BUCKETS * CONSISTENCY_BUCKETS;
    idx < per_mode
}

fn family_from_index(idx: usize) -> ApiFamily {
    // ApiFamily is a dense repr(u8) enum, 0..COUNT.
    match idx as u8 {
        0 => ApiFamily::PointerValidation,
        1 => ApiFamily::Allocator,
        2 => ApiFamily::StringMemory,
        3 => ApiFamily::Stdio,
        4 => ApiFamily::Threading,
        5 => ApiFamily::Resolver,
        6 => ApiFamily::MathFenv,
        7 => ApiFamily::Loader,
        8 => ApiFamily::Stdlib,
        9 => ApiFamily::Ctype,
        10 => ApiFamily::Time,
        11 => ApiFamily::Signal,
        12 => ApiFamily::IoFd,
        13 => ApiFamily::Socket,
        14 => ApiFamily::Locale,
        15 => ApiFamily::Termios,
        16 => ApiFamily::Inet,
        17 => ApiFamily::Process,
        18 => ApiFamily::VirtualMemory,
        _ => ApiFamily::Poll,
    }
}

fn action_rank(mode: SafetyLevel, action: PcptAction) -> Option<u8> {
    match mode {
        SafetyLevel::Strict | SafetyLevel::Off => match action {
            PcptAction::Allow => Some(0),
            PcptAction::FullValidate => Some(1),
            PcptAction::Deny => Some(2),
            PcptAction::Repair => None,
        },
        SafetyLevel::Hardened => match action {
            PcptAction::Allow => Some(0),
            PcptAction::FullValidate => Some(1),
            PcptAction::Repair => Some(2),
            PcptAction::Deny => Some(3),
        },
    }
}

/// Compute the v1 table index for the discretized key dimensions.
#[must_use]
pub fn key_v1_index(
    mode: SafetyLevel,
    family: ApiFamily,
    risk_bucket: u8,
    budget_bucket: u8,
    consistency_bucket: u8,
) -> usize {
    let mode_idx = match mode {
        SafetyLevel::Strict | SafetyLevel::Off => 0usize,
        SafetyLevel::Hardened => 1usize,
    };
    let f = ApiFamily::COUNT;
    let r = RISK_BUCKETS;
    let b = BUDGET_BUCKETS;
    let c = CONSISTENCY_BUCKETS;

    let family_idx = usize::from(family as u8);
    let rb = usize::from(risk_bucket.min((RISK_BUCKETS - 1) as u8));
    let bb = usize::from(budget_bucket.min((BUDGET_BUCKETS - 1) as u8));
    let cb = usize::from(consistency_bucket.min((CONSISTENCY_BUCKETS - 1) as u8));

    ((((mode_idx * f + family_idx) * r + rb) * b + bb) * c + cb)
}

#[must_use]
pub fn risk_bucket_v1(risk_ppm: u32) -> u8 {
    // 16 equal-width bins across 0..=1_000_000.
    let bucket = (risk_ppm / 62_500).min(15);
    bucket as u8
}

#[must_use]
pub fn budget_bucket_v1(fast_over_budget: bool, full_over_budget: bool, pareto_exhausted: bool) -> u8 {
    (u8::from(fast_over_budget)) | (u8::from(full_over_budget) << 1) | (u8::from(pareto_exhausted) << 2)
}

#[must_use]
pub fn consistency_bucket_v1(consistency_faults: u64) -> u8 {
    match consistency_faults {
        0 => 0,
        1 => 1,
        2 | 3 => 2,
        _ => 3,
    }
}

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16, PolicyTableError> {
    let b = buf.get(off..off + 2).ok_or(PolicyTableError::TooShort)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32, PolicyTableError> {
    let b = buf.get(off..off + 4).ok_or(PolicyTableError::TooShort)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn hash_256(alg: HashAlg, bytes: &[u8]) -> [u8; 32] {
    match alg {
        HashAlg::Blake3_256 => *blake3::hash(bytes).as_bytes(),
        HashAlg::Sha256 => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            hasher.update(bytes);
            let out = hasher.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&out);
            arr
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn ascii_lossy_trim(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_pcpt(hash_alg: HashAlg) -> Vec<u8> {
        let table_len =
            2u32 * ApiFamily::COUNT as u32 * RISK_BUCKETS as u32 * BUDGET_BUCKETS as u32 * CONSISTENCY_BUCKETS as u32;
        let table_bytes = (table_len as usize) * CELL_BYTES_V1;
        let mut table = vec![0u8; table_bytes];

        // Fill: strict rows have strict_allowed=1; hardened rows flags=0.
        for idx in 0..table_len as usize {
            let off = idx * CELL_BYTES_V1;
            let is_strict = idx_is_strict_row(idx);
            table[off] = 0; // profile Fast
            table[off + 1] = 0; // action Allow
            table[off + 2] = 0; // repair None
            table[off + 3] = if is_strict { 0x01 } else { 0x00 };
        }

        let meta = {
            let mut m = Vec::new();
            // build info
            push_tlv(&mut m, 0x0001, b"gen:unit-test");
            // proof digest (32 bytes)
            push_tlv(&mut m, 0x0002, &[0xAB; 32]);
            // invariant manifest
            push_tlv(&mut m, 0x0003, b"invariants:v1");
            m
        };

        let table_hash = hash_256(hash_alg, &table);
        let meta_hash = hash_256(hash_alg, &meta);

        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&SCHEMA_VERSION_V1.to_le_bytes());
        out.push(hash_alg as u8);
        out.extend_from_slice(&KEY_SPEC_ID_V1.to_le_bytes());
        out.extend_from_slice(&CELL_SPEC_ID_V1.to_le_bytes());
        out.extend_from_slice(&table_len.to_le_bytes());
        out.extend_from_slice(&(table_bytes as u32).to_le_bytes());
        out.extend_from_slice(&table_hash);
        out.extend_from_slice(&meta_hash);
        out.extend_from_slice(&[0u8; 32]); // reserved
        debug_assert_eq!(out.len(), HEADER_LEN);
        out.extend_from_slice(&table);
        out.extend_from_slice(&meta);
        out
    }

    fn push_tlv(out: &mut Vec<u8>, t: u16, v: &[u8]) {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&(v.len() as u16).to_le_bytes());
        out.extend_from_slice(v);
    }

    #[test]
    fn verifies_minimal_blake3_artifact() {
        let bytes = build_minimal_pcpt(HashAlg::Blake3_256);
        let verified = verify_pcpt(&bytes).expect("verify");
        assert_eq!(verified.summary.schema_version, SCHEMA_VERSION_V1);
        assert_eq!(verified.summary.key_spec_id, KEY_SPEC_ID_V1);
        assert_eq!(verified.summary.cell_spec_id, CELL_SPEC_ID_V1);
        assert!(verified.summary.generator_build_info.is_some());
        assert!(verified.summary.offline_proof_digest_hex.is_some());
        assert!(verified.summary.invariant_manifest.is_some());
    }

    #[test]
    fn bad_magic_fails() {
        let mut bytes = build_minimal_pcpt(HashAlg::Blake3_256);
        bytes[0] = b'X';
        assert_eq!(verify_pcpt(&bytes).unwrap_err(), PolicyTableError::BadMagic);
    }

    #[test]
    fn reserved_non_zero_fails() {
        let mut bytes = build_minimal_pcpt(HashAlg::Blake3_256);
        bytes[87] = 1;
        assert_eq!(verify_pcpt(&bytes).unwrap_err(), PolicyTableError::ReservedNonZero);
    }

    #[test]
    fn hash_mismatch_fails() {
        let mut bytes = build_minimal_pcpt(HashAlg::Blake3_256);
        // Flip one byte in table region.
        bytes[HEADER_LEN + 10] ^= 0xFF;
        assert!(matches!(
            verify_pcpt(&bytes).unwrap_err(),
            PolicyTableError::HashMismatch { .. }
        ));
    }

    #[test]
    fn strict_repair_is_rejected() {
        let mut bytes = build_minimal_pcpt(HashAlg::Blake3_256);
        // Set the first strict cell to Repair with a valid repair kind.
        let off = HEADER_LEN;
        bytes[off + 1] = PcptAction::Repair as u8;
        bytes[off + 2] = RepairKind::ReturnSafeDefault as u8;

        // Recompute hashes to make it a logical (not hash) failure.
        let table_end = HEADER_LEN + (2 * ApiFamily::COUNT * RISK_BUCKETS * BUDGET_BUCKETS * CONSISTENCY_BUCKETS * CELL_BYTES_V1);
        let table = bytes[HEADER_LEN..table_end].to_vec();
        let meta = bytes[table_end..].to_vec();
        let table_hash = hash_256(HashAlg::Blake3_256, &table);
        let meta_hash = hash_256(HashAlg::Blake3_256, &meta);
        bytes[23..55].copy_from_slice(&table_hash);
        bytes[55..87].copy_from_slice(&meta_hash);

        assert!(matches!(
            verify_pcpt(&bytes).unwrap_err(),
            PolicyTableError::StrictRepairNotAllowed { .. }
        ));
    }

    #[test]
    fn risk_monotonicity_violation_is_rejected() {
        let mut bytes = build_minimal_pcpt(HashAlg::Blake3_256);

        // Make one hardened row decrease action rank at higher risk bucket.
        // For (mode=hardened,family=PointerValidation,budget=0,consistency=0):
        // risk_bucket 0 -> Deny, risk_bucket 1 -> Allow (decreasing).
        let idx0 = key_v1_index(SafetyLevel::Hardened, ApiFamily::PointerValidation, 0, 0, 0);
        let idx1 = key_v1_index(SafetyLevel::Hardened, ApiFamily::PointerValidation, 1, 0, 0);
        let off0 = HEADER_LEN + idx0 * CELL_BYTES_V1;
        let off1 = HEADER_LEN + idx1 * CELL_BYTES_V1;
        bytes[off0 + 1] = PcptAction::Deny as u8;
        bytes[off1 + 1] = PcptAction::Allow as u8;

        // Recompute hashes.
        let table_end = HEADER_LEN + (2 * ApiFamily::COUNT * RISK_BUCKETS * BUDGET_BUCKETS * CONSISTENCY_BUCKETS * CELL_BYTES_V1);
        let table = bytes[HEADER_LEN..table_end].to_vec();
        let meta = bytes[table_end..].to_vec();
        let table_hash = hash_256(HashAlg::Blake3_256, &table);
        let meta_hash = hash_256(HashAlg::Blake3_256, &meta);
        bytes[23..55].copy_from_slice(&table_hash);
        bytes[55..87].copy_from_slice(&meta_hash);

        assert!(matches!(
            verify_pcpt(&bytes).unwrap_err(),
            PolicyTableError::RiskMonotonicityViolation { .. }
        ));
    }
}

