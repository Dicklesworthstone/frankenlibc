//! Runtime evidence symbol record format and systematic ring buffer.
//!
//! This module implements the `bd-kom` v1 contract:
//! - Fixed-size evidence symbols (systematic source symbols) suitable for offline decoding.
//! - Self-describing envelope fields: epoch/seed, ESI, K_source, T, integrity hashes.
//! - A bounded overwrite-on-full ring buffer with lock-free publication.
//!
//! Design reference: `runtime_math/raptorq_runtime_architecture.md`.
//!
//! ## No-unsafe policy
//! `frankenlibc-membrane` is `#![deny(unsafe_code)]`. All encoding/decoding is done via
//! explicit little-endian byte writes into a `[u8; N]` backing array.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, ValidationProfile,
};

/// v1 symbol payload size (`T`).
pub const EVIDENCE_SYMBOL_SIZE_T: usize = 128;
/// v1 auth tag size (reserved; optional, usually all zeros).
///
/// Rationale: 32 bytes matches a BLAKE3 output and is a convenient future MAC size.
pub const EVIDENCE_AUTH_TAG_SIZE: usize = 32;
/// Fixed-size record header.
pub const EVIDENCE_HEADER_SIZE: usize = 64;
/// Fixed-size record total size.
pub const EVIDENCE_RECORD_SIZE: usize = 256;

const MAGIC: [u8; 4] = *b"EVR1";
const VERSION_V1: u16 = 1;

/// Record is a systematic source symbol (as opposed to a repair symbol).
pub const FLAG_SYSTEMATIC: u16 = 1 << 0;
/// Record is a repair symbol (cadence-only; not generated in strict mode).
pub const FLAG_REPAIR: u16 = 1 << 1;
/// Auth tag bytes are meaningful (non-zero) and should be verified by tooling.
pub const FLAG_AUTH_TAG_PRESENT: u16 = 1 << 2;

const OFF_MAGIC: usize = 0; // [u8;4]
const OFF_VERSION: usize = 4; // u16
const OFF_FLAGS: usize = 6; // u16
const OFF_EPOCH_ID: usize = 8; // u64
const OFF_SEQNO: usize = 16; // u64
const OFF_SEED: usize = 24; // u64
const OFF_FAMILY: usize = 32; // u8
const OFF_MODE: usize = 33; // u8
const OFF_ACTION: usize = 34; // u8
const OFF_PROFILE: usize = 35; // u8
const OFF_ESI: usize = 36; // u16
const OFF_K_SOURCE: usize = 38; // u16
const OFF_R_REPAIR: usize = 40; // u16
const OFF_SYMBOL_SIZE_T: usize = 42; // u16
const OFF_PAYLOAD_HASH: usize = 44; // u64
const OFF_CHAIN_HASH: usize = 52; // u64
const OFF_RESERVED: usize = 60; // u32

pub const PAYLOAD_OFFSET: usize = EVIDENCE_HEADER_SIZE;
pub const AUTH_TAG_OFFSET: usize = PAYLOAD_OFFSET + EVIDENCE_SYMBOL_SIZE_T;
pub const RESERVED_OFFSET: usize = AUTH_TAG_OFFSET + EVIDENCE_AUTH_TAG_SIZE;

/// Basic parse/validation errors for an evidence record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceRecordError {
    BadMagic,
    UnsupportedVersion(u16),
    BadSymbolSize(u16),
}

/// Fixed-size evidence symbol record (envelope + payload + optional auth tag + reserved).
///
/// The backing byte layout is stable for v1 and intentionally explicit to avoid
/// padding/packing pitfalls.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EvidenceSymbolRecord {
    bytes: [u8; EVIDENCE_RECORD_SIZE],
}

impl fmt::Debug for EvidenceSymbolRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EvidenceSymbolRecord")
            .field("version", &self.version())
            .field("flags", &self.flags())
            .field("epoch_id", &self.epoch_id())
            .field("seqno", &self.seqno())
            .field("family", &self.family())
            .field("mode", &self.mode())
            .field("action", &self.action())
            .field("profile", &self.profile())
            .field("esi", &self.esi())
            .field("k_source", &self.k_source())
            .field("r_repair", &self.r_repair())
            .field("symbol_size_t", &self.symbol_size_t())
            .field(
                "payload_hash",
                &format_args!("{:#016x}", self.payload_hash()),
            )
            .field("chain_hash", &format_args!("{:#016x}", self.chain_hash()))
            .finish_non_exhaustive()
    }
}

impl EvidenceSymbolRecord {
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            bytes: [0u8; EVIDENCE_RECORD_SIZE],
        }
    }

    /// Construct a record from raw bytes (e.g. tooling ingest).
    ///
    /// This does not validate the record; callers should use `validate_basic()`
    /// and optional integrity checks as appropriate.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; EVIDENCE_RECORD_SIZE]) -> Self {
        Self { bytes }
    }

    /// Construct and immediately run basic structural validation.
    pub fn try_from_bytes(bytes: [u8; EVIDENCE_RECORD_SIZE]) -> Result<Self, EvidenceRecordError> {
        let rec = Self::from_bytes(bytes);
        rec.validate_basic()?;
        Ok(rec)
    }

    /// Compute the v1 seeded payload hash for a payload.
    #[must_use]
    pub fn compute_payload_hash_v1(payload: &[u8; EVIDENCE_SYMBOL_SIZE_T], seed: u64) -> u64 {
        evidence_hash64(payload, seed ^ 0xA0B1_C2D3_E4F5_0617)
    }

    /// Verify `payload_hash == H(payload; seed)` for v1.
    #[must_use]
    pub fn verify_payload_hash_v1(&self) -> bool {
        self.payload_hash() == Self::compute_payload_hash_v1(self.payload(), self.seed())
    }

    /// Compute the v1 chain hash given the prior chain hash.
    #[must_use]
    pub fn compute_chain_hash_v1(&self, prev_chain_hash: u64) -> u64 {
        let auth_present = (self.flags() & FLAG_AUTH_TAG_PRESENT) != 0;
        chain_hash64(prev_chain_hash, &self.bytes, auth_present)
    }

    /// Verify `chain_hash == H(prev_chain_hash || header_prefix || auth_tag)` for v1.
    #[must_use]
    pub fn verify_chain_hash_v1(&self, prev_chain_hash: u64) -> bool {
        self.chain_hash() == self.compute_chain_hash_v1(prev_chain_hash)
    }

    /// Build a v1 record from raw envelope parameters + payload bytes.
    ///
    /// This computes:
    /// - `payload_hash = H(payload; seed)`
    /// - `chain_hash = H(prev_chain_hash || header_prefix || auth_tag)`
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn build_v1(
        epoch_id: u64,
        seqno: u64,
        seed: u64,
        family: ApiFamily,
        mode: SafetyLevel,
        action: MembraneAction,
        profile: ValidationProfile,
        flags: u16,
        esi: u16,
        k_source: u16,
        r_repair: u16,
        prev_chain_hash: u64,
        payload: &[u8; EVIDENCE_SYMBOL_SIZE_T],
        auth_tag: Option<&[u8; EVIDENCE_AUTH_TAG_SIZE]>,
    ) -> Self {
        let mut r = Self::zeroed();

        r.bytes[OFF_MAGIC..OFF_MAGIC + 4].copy_from_slice(&MAGIC);
        write_u16(&mut r.bytes, OFF_VERSION, VERSION_V1);
        write_u16(&mut r.bytes, OFF_FLAGS, flags);
        write_u64(&mut r.bytes, OFF_EPOCH_ID, epoch_id);
        write_u64(&mut r.bytes, OFF_SEQNO, seqno);
        write_u64(&mut r.bytes, OFF_SEED, seed);
        r.bytes[OFF_FAMILY] = family as u8;
        r.bytes[OFF_MODE] = mode_code(mode);
        r.bytes[OFF_ACTION] = action_code(action);
        r.bytes[OFF_PROFILE] = profile_code(profile);
        write_u16(&mut r.bytes, OFF_ESI, esi);
        write_u16(&mut r.bytes, OFF_K_SOURCE, k_source);
        write_u16(&mut r.bytes, OFF_R_REPAIR, r_repair);
        write_u16(
            &mut r.bytes,
            OFF_SYMBOL_SIZE_T,
            u16::try_from(EVIDENCE_SYMBOL_SIZE_T).unwrap_or(u16::MAX),
        );
        write_u32(&mut r.bytes, OFF_RESERVED, 0);

        // Payload (exactly T bytes).
        r.bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + EVIDENCE_SYMBOL_SIZE_T].copy_from_slice(payload);

        // Auth tag (optional but fixed-size storage).
        if let Some(tag) = auth_tag {
            r.bytes[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + EVIDENCE_AUTH_TAG_SIZE].copy_from_slice(tag);
        }

        // Integrity: payload hash (seeded).
        let payload_hash = evidence_hash64(payload, seed ^ 0xA0B1_C2D3_E4F5_0617);
        write_u64(&mut r.bytes, OFF_PAYLOAD_HASH, payload_hash);

        // Integrity: chain hash (includes payload_hash via header prefix).
        let chain_hash = chain_hash64(prev_chain_hash, &r.bytes, auth_tag.is_some());
        write_u64(&mut r.bytes, OFF_CHAIN_HASH, chain_hash);

        r
    }

    /// Basic structural validation (magic/version/T).
    pub fn validate_basic(&self) -> Result<(), EvidenceRecordError> {
        if self.bytes[OFF_MAGIC..OFF_MAGIC + 4] != MAGIC {
            return Err(EvidenceRecordError::BadMagic);
        }
        let version = self.version();
        if version != VERSION_V1 {
            return Err(EvidenceRecordError::UnsupportedVersion(version));
        }
        let t = self.symbol_size_t();
        if t as usize != EVIDENCE_SYMBOL_SIZE_T {
            return Err(EvidenceRecordError::BadSymbolSize(t));
        }
        Ok(())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; EVIDENCE_RECORD_SIZE] {
        &self.bytes
    }

    #[must_use]
    pub fn version(&self) -> u16 {
        read_u16(&self.bytes, OFF_VERSION)
    }

    #[must_use]
    pub fn flags(&self) -> u16 {
        read_u16(&self.bytes, OFF_FLAGS)
    }

    #[must_use]
    pub fn epoch_id(&self) -> u64 {
        read_u64(&self.bytes, OFF_EPOCH_ID)
    }

    #[must_use]
    pub fn seqno(&self) -> u64 {
        read_u64(&self.bytes, OFF_SEQNO)
    }

    #[must_use]
    pub fn seed(&self) -> u64 {
        read_u64(&self.bytes, OFF_SEED)
    }

    #[must_use]
    pub fn family(&self) -> u8 {
        self.bytes[OFF_FAMILY]
    }

    #[must_use]
    pub fn mode(&self) -> u8 {
        self.bytes[OFF_MODE]
    }

    #[must_use]
    pub fn action(&self) -> u8 {
        self.bytes[OFF_ACTION]
    }

    #[must_use]
    pub fn profile(&self) -> u8 {
        self.bytes[OFF_PROFILE]
    }

    #[must_use]
    pub fn esi(&self) -> u16 {
        read_u16(&self.bytes, OFF_ESI)
    }

    #[must_use]
    pub fn k_source(&self) -> u16 {
        read_u16(&self.bytes, OFF_K_SOURCE)
    }

    #[must_use]
    pub fn r_repair(&self) -> u16 {
        read_u16(&self.bytes, OFF_R_REPAIR)
    }

    #[must_use]
    pub fn symbol_size_t(&self) -> u16 {
        read_u16(&self.bytes, OFF_SYMBOL_SIZE_T)
    }

    #[must_use]
    pub fn payload_hash(&self) -> u64 {
        read_u64(&self.bytes, OFF_PAYLOAD_HASH)
    }

    /// Hash-chain head after incorporating this record.
    #[must_use]
    pub fn chain_hash(&self) -> u64 {
        read_u64(&self.bytes, OFF_CHAIN_HASH)
    }

    #[must_use]
    pub fn payload(&self) -> &[u8; EVIDENCE_SYMBOL_SIZE_T] {
        self.bytes[PAYLOAD_OFFSET..PAYLOAD_OFFSET + EVIDENCE_SYMBOL_SIZE_T]
            .try_into()
            .expect("payload slice has fixed length")
    }

    #[must_use]
    pub fn auth_tag(&self) -> &[u8; EVIDENCE_AUTH_TAG_SIZE] {
        self.bytes[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + EVIDENCE_AUTH_TAG_SIZE]
            .try_into()
            .expect("auth tag slice has fixed length")
    }
}

/// v1 payload magic for decision events.
const PAYLOAD_MAGIC_DECISION_V1: [u8; 4] = *b"EVP1";
const PAYLOAD_VERSION_V1: u8 = 1;
const EVENT_KIND_DECISION: u8 = 1;
const LOSS_BLOCK_VERSION_V1: u8 = 1;
const LOSS_BLOCK_OFFSET: usize = 60;

/// Optional decision-theory evidence payload embedded in the decision symbol.
///
/// This captures the expected-loss attribution required for repair/deny audits:
/// posterior severity estimate plus selected vs competing action costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LossEvidenceV1 {
    /// Posterior `P(C=Adverse | evidence)` in ppm (0..1_000_000).
    pub posterior_adverse_ppm: u32,
    /// Selected action id (0=allow, 1=full-validate, 2=repair, 3=deny).
    pub selected_action: u8,
    /// Closest competing action id.
    pub competing_action: u8,
    /// Expected-loss cost for selected action in milli-units.
    pub selected_expected_loss_milli: u32,
    /// Expected-loss cost for competing action in milli-units.
    pub competing_expected_loss_milli: u32,
}

/// Encode a v1 "decision" evidence payload.
///
/// This mapping is designed to be:
/// - deterministic
/// - byte-stable (explicit little-endian writes)
/// - small enough to evolve via reserved space
#[must_use]
pub fn encode_decision_payload_v1(
    mode: SafetyLevel,
    ctx: RuntimeContext,
    decision: RuntimeDecision,
    estimated_cost_ns: u64,
    adverse: bool,
    loss_evidence: Option<LossEvidenceV1>,
) -> [u8; EVIDENCE_SYMBOL_SIZE_T] {
    let mut p = [0u8; EVIDENCE_SYMBOL_SIZE_T];
    p[0..4].copy_from_slice(&PAYLOAD_MAGIC_DECISION_V1);
    p[4] = PAYLOAD_VERSION_V1;
    p[5] = EVENT_KIND_DECISION;
    p[6] = 0;
    p[7] = 0;

    write_u64(&mut p, 8, ctx.addr_hint as u64);
    write_u64(&mut p, 16, ctx.requested_bytes as u64);

    let mut ctx_flags: u8 = 0;
    if ctx.is_write {
        ctx_flags |= 1 << 0;
    }
    if ctx.bloom_negative {
        ctx_flags |= 1 << 1;
    }
    p[24] = ctx_flags;
    p[25] = mode_code(mode);
    write_u16(&mut p, 26, ctx.contention_hint);

    write_u32(&mut p, 28, decision.policy_id);
    write_u32(&mut p, 32, decision.risk_upper_bound_ppm);
    write_u32(
        &mut p,
        36,
        u32::try_from(estimated_cost_ns).unwrap_or(u32::MAX),
    );

    p[40] = if adverse { 1 } else { 0 };

    let (heal_code, heal_arg0, heal_arg1) = healing_code_and_args(decision.action);
    p[41] = heal_code;
    p[42] = 0;
    p[43] = 0;
    write_u64(&mut p, 44, heal_arg0);
    write_u64(&mut p, 52, heal_arg1);

    if let Some(loss) = loss_evidence {
        // Flag presence of the expected-loss block.
        p[42] = 1;
        p[43] = LOSS_BLOCK_VERSION_V1;
        write_u32(
            &mut p,
            LOSS_BLOCK_OFFSET,
            loss.posterior_adverse_ppm.min(1_000_000),
        );
        p[LOSS_BLOCK_OFFSET + 4] = loss.selected_action;
        p[LOSS_BLOCK_OFFSET + 5] = loss.competing_action;
        write_u32(
            &mut p,
            LOSS_BLOCK_OFFSET + 8,
            loss.selected_expected_loss_milli,
        );
        write_u32(
            &mut p,
            LOSS_BLOCK_OFFSET + 12,
            loss.competing_expected_loss_milli,
        );
    }

    // Remaining bytes reserved for forward-compatible v1 growth.
    p
}

fn healing_code_and_args(action: MembraneAction) -> (u8, u64, u64) {
    const NONE: u8 = 0;
    const CLAMP_SIZE: u8 = 1;
    const TRUNCATE_WITH_NULL: u8 = 2;
    const IGNORE_DOUBLE_FREE: u8 = 3;
    const IGNORE_FOREIGN_FREE: u8 = 4;
    const REALLOC_AS_MALLOC: u8 = 5;
    const RETURN_SAFE_DEFAULT: u8 = 6;
    const UPGRADE_TO_SAFE_VARIANT: u8 = 7;

    match action {
        MembraneAction::Repair(h) => match h {
            HealingAction::ClampSize { requested, clamped } => {
                (CLAMP_SIZE, requested as u64, clamped as u64)
            }
            HealingAction::TruncateWithNull {
                requested,
                truncated,
            } => (TRUNCATE_WITH_NULL, requested as u64, truncated as u64),
            HealingAction::IgnoreDoubleFree => (IGNORE_DOUBLE_FREE, 0, 0),
            HealingAction::IgnoreForeignFree => (IGNORE_FOREIGN_FREE, 0, 0),
            HealingAction::ReallocAsMalloc { size } => (REALLOC_AS_MALLOC, size as u64, 0),
            HealingAction::ReturnSafeDefault => (RETURN_SAFE_DEFAULT, 0, 0),
            HealingAction::UpgradeToSafeVariant => (UPGRADE_TO_SAFE_VARIANT, 0, 0),
            HealingAction::None => (NONE, 0, 0),
        },
        _ => (NONE, 0, 0),
    }
}

#[inline]
const fn mode_code(mode: SafetyLevel) -> u8 {
    match mode {
        SafetyLevel::Strict => 0,
        SafetyLevel::Hardened => 1,
        SafetyLevel::Off => 2,
    }
}

#[inline]
const fn profile_code(profile: ValidationProfile) -> u8 {
    match profile {
        ValidationProfile::Fast => 0,
        ValidationProfile::Full => 1,
    }
}

#[inline]
fn action_code(action: MembraneAction) -> u8 {
    match action {
        MembraneAction::Allow => 0,
        MembraneAction::FullValidate => 1,
        MembraneAction::Repair(_) => 2,
        MembraneAction::Deny => 3,
    }
}

#[inline]
fn derive_epoch_id(
    boot_nonce: u64,
    mode: SafetyLevel,
    family: ApiFamily,
    epoch_counter: u64,
) -> u64 {
    // Deterministic mixing; avoids syscalls/time. The seed is carried in-record for tooling.
    let base = boot_nonce ^ (epoch_counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    base ^ ((mode_code(mode) as u64) << 56) ^ ((family as u64) << 48)
}

#[inline]
fn derive_epoch_seed(epoch_id: u64) -> u64 {
    splitmix64(epoch_id ^ 0xD6E8_FEB8_6659_FD93)
}

// ── Repair Symbol Generation (v1) ──────────────────────────────
//
// This is the `bd-1es` deterministic XOR-only encoder used to produce cadence
// repair symbols for offline decoding.
//
// Key constraints:
// - Deterministic: schedule depends only on (epoch_seed, k_source, repair_esi).
// - XOR-only: no GF(256) arithmetic, no Gaussian elimination in libc runtime.
// - Small-degree bias: peeling-friendly (degree ~ geometric, capped).
//
// IMPORTANT: Generation is cadence-only (never on strict fast path). Integration
// into runtime logging is handled by `bd-3ku`.

/// v1 target decode slack (`K + slack_decode`).
pub const SLACK_DECODE_V1: u16 = 2;

/// v1 maximum repair-symbol degree (subset size).
pub const REPAIR_MAX_DEGREE_V1: usize = 16;

/// Deterministic repair schedule for a single repair symbol (v1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairScheduleV1 {
    degree: u16,
    len: u8,
    indices: [u16; REPAIR_MAX_DEGREE_V1],
}

impl RepairScheduleV1 {
    #[must_use]
    pub const fn degree(&self) -> u16 {
        self.degree
    }

    #[must_use]
    pub fn indices(&self) -> &[u16] {
        &self.indices[..self.len as usize]
    }
}

/// Derive the number of repair symbols `R` to generate for an epoch.
///
/// Spec (bd-1es / bd-3a9):
/// - `R = max(slack_decode, ceil(K_source * overhead_percent / 100))`
///
/// If `k_source == 0`, returns 0 (no epoch).
#[must_use]
pub fn derive_repair_symbol_count_v1(k_source: u16, overhead_percent: u16) -> u16 {
    if k_source == 0 {
        return 0;
    }
    let k = k_source as u32;
    let overhead = overhead_percent as u32;
    let r_overhead = ceil_div_u32(k.saturating_mul(overhead), 100);
    let r = r_overhead.max(SLACK_DECODE_V1 as u32);
    u16::try_from(r).unwrap_or(u16::MAX)
}

/// Approximate maximum loss fraction tolerated beyond decode slack.
///
/// Spec (bd-1es):
/// - `loss_fraction_max ≈ (R - slack_decode) / (K_source + R)`
///
/// Returned as ppm in `[0, 1_000_000]` for fixed-point stability.
#[must_use]
pub fn loss_fraction_max_ppm_v1(k_source: u16, r_repair: u16) -> u32 {
    if k_source == 0 {
        return 0;
    }
    let numer = (r_repair.saturating_sub(SLACK_DECODE_V1) as u64).saturating_mul(1_000_000);
    let denom = (k_source as u64).saturating_add(r_repair as u64).max(1);
    u32::try_from((numer / denom).min(1_000_000)).unwrap_or(1_000_000)
}

/// Derive a deterministic repair schedule (subset of `0..k_source`) for `repair_esi`.
///
/// Degree distribution (v1):
/// - `degree = 1 + min(trailing_zeros(u), REPAIR_MAX_DEGREE_V1-1)` where `u` is PRNG output.
/// - clamp to `k_source` (so indices are always distinct / valid)
///
/// Index selection:
/// - propose index = `next_u64 % k_source`
/// - resolve duplicates via deterministic linear probing (wrap-around)
#[must_use]
pub fn derive_repair_schedule_v1(
    epoch_seed: u64,
    k_source: u16,
    repair_esi: u16,
) -> RepairScheduleV1 {
    if k_source == 0 {
        return RepairScheduleV1 {
            degree: 0,
            len: 0,
            indices: [0u16; REPAIR_MAX_DEGREE_V1],
        };
    }

    let mut state =
        epoch_seed ^ 0x52D2_EE1D_4B33_9D5Bu64 ^ ((repair_esi as u64) << 32) ^ (k_source as u64);

    let u = splitmix64_next(&mut state);
    let mut degree = 1u16 + (u.trailing_zeros() as u16).min((REPAIR_MAX_DEGREE_V1 - 1) as u16);
    degree = degree.min(k_source);

    let mut out = [0u16; REPAIR_MAX_DEGREE_V1];
    let mut len: usize = 0;

    while len < degree as usize {
        let r = splitmix64_next(&mut state);
        let mut idx = (r % (k_source as u64)) as u16;

        // Resolve duplicates deterministically via linear probing.
        let mut probes: u16 = 0;
        while contains_u16(&out[..len], idx) && probes < k_source {
            idx = idx.wrapping_add(1);
            if idx >= k_source {
                idx = 0;
            }
            probes = probes.wrapping_add(1);
        }

        // Fallback (should not trigger for degree<=k_source): pick first unused.
        if probes >= k_source {
            for cand in 0..k_source {
                if !contains_u16(&out[..len], cand) {
                    idx = cand;
                    break;
                }
            }
        }

        out[len] = idx;
        len += 1;
    }

    RepairScheduleV1 {
        degree,
        len: u8::try_from(len).unwrap_or(u8::MAX),
        indices: out,
    }
}

/// XOR-encode a single repair payload symbol for the given `repair_esi`.
///
/// The repair payload is the XOR of `degree` systematic payloads at indices given by
/// `derive_repair_schedule_v1(epoch_seed, k_source, repair_esi)`.
#[must_use]
pub fn encode_xor_repair_payload_v1(
    epoch_seed: u64,
    source_payloads: &[[u8; EVIDENCE_SYMBOL_SIZE_T]],
    repair_esi: u16,
) -> [u8; EVIDENCE_SYMBOL_SIZE_T] {
    let k_source = u16::try_from(source_payloads.len()).unwrap_or(u16::MAX);
    if k_source == 0 {
        return [0u8; EVIDENCE_SYMBOL_SIZE_T];
    }
    debug_assert!(
        repair_esi >= k_source,
        "repair_esi should start at k_source (systematic are 0..k_source-1)"
    );

    let sched = derive_repair_schedule_v1(epoch_seed, k_source, repair_esi);
    let mut out = [0u8; EVIDENCE_SYMBOL_SIZE_T];
    for &idx in sched.indices() {
        let src = &source_payloads[idx as usize];
        for i in 0..EVIDENCE_SYMBOL_SIZE_T {
            out[i] ^= src[i];
        }
    }
    out
}

/// Generate all repair payload symbols for an epoch (v1).
///
/// Returns `(esi, payload)` pairs where repair ESIs are `k_source..k_source+R-1`.
#[must_use]
pub fn generate_repair_payloads_v1(
    epoch_seed: u64,
    source_payloads: &[[u8; EVIDENCE_SYMBOL_SIZE_T]],
    overhead_percent: u16,
) -> Vec<(u16, [u8; EVIDENCE_SYMBOL_SIZE_T])> {
    let k_source = u16::try_from(source_payloads.len()).unwrap_or(u16::MAX);
    let r = derive_repair_symbol_count_v1(k_source, overhead_percent);
    let mut out = Vec::with_capacity(r as usize);
    for i in 0..r {
        let esi = k_source.wrapping_add(i);
        let payload = encode_xor_repair_payload_v1(epoch_seed, source_payloads, esi);
        out.push((esi, payload));
    }
    out
}

#[inline]
fn ceil_div_u32(numer: u32, denom: u32) -> u32 {
    if denom == 0 {
        return u32::MAX;
    }
    numer.saturating_add(denom.saturating_sub(1)) / denom
}

#[inline]
fn contains_u16(hay: &[u16], needle: u16) -> bool {
    hay.contains(&needle)
}

/// A systematic evidence log with per-(mode,family) epoch state and a bounded ring buffer.
///
/// Recording is cheap (no allocation). Epoch state uses small per-stream mutexes to keep
/// ESI assignment and chain hashing sequential per stream.
pub struct SystematicEvidenceLog<const CAP: usize> {
    ring: EvidenceRingBuffer<CAP>,
    boot_nonce: u64,
    streams: [Mutex<EpochStreamState>; ApiFamily::COUNT * 2],
}

#[derive(Debug, Clone, Copy)]
struct EpochStreamState {
    epoch_counter: u64,
    next_esi: u16,
    chain_hash: u64,
}

impl EpochStreamState {
    const fn new() -> Self {
        Self {
            epoch_counter: 0,
            next_esi: 0,
            chain_hash: 0,
        }
    }
}

impl<const CAP: usize> SystematicEvidenceLog<CAP> {
    /// v1 maximum systematic symbols per epoch (`K_max`).
    pub const K_MAX: u16 = 256;

    #[must_use]
    pub fn new(boot_nonce: u64) -> Self {
        Self {
            ring: EvidenceRingBuffer::new(),
            boot_nonce,
            streams: core::array::from_fn(|_| Mutex::new(EpochStreamState::new())),
        }
    }

    /// Record a runtime decision as a systematic evidence symbol.
    ///
    /// Returns the global `seqno` assigned to the record (monotonic, overwrite-on-full).
    #[allow(clippy::too_many_arguments)]
    pub fn record_decision(
        &self,
        mode: SafetyLevel,
        ctx: RuntimeContext,
        decision: RuntimeDecision,
        estimated_cost_ns: u64,
        adverse: bool,
        loss_evidence: Option<LossEvidenceV1>,
        flags: u16,
        auth_tag: Option<&[u8; EVIDENCE_AUTH_TAG_SIZE]>,
    ) -> u64 {
        let stream_idx = stream_index(mode, ctx.family);
        let mut st = self.streams[stream_idx].lock();

        if st.next_esi >= Self::K_MAX {
            st.epoch_counter = st.epoch_counter.wrapping_add(1);
            st.next_esi = 0;
            st.chain_hash = 0;
        }

        let esi = st.next_esi;
        st.next_esi = st.next_esi.wrapping_add(1);

        let epoch_id = derive_epoch_id(self.boot_nonce, mode, ctx.family, st.epoch_counter);
        let seed = derive_epoch_seed(epoch_id);

        let seqno = self.ring.allocate_seqno();
        let payload = encode_decision_payload_v1(
            mode,
            ctx,
            decision,
            estimated_cost_ns,
            adverse,
            loss_evidence,
        );

        let mut record_flags = flags | FLAG_SYSTEMATIC;
        if auth_tag.is_some() {
            record_flags |= FLAG_AUTH_TAG_PRESENT;
        }

        let rec = EvidenceSymbolRecord::build_v1(
            epoch_id,
            seqno,
            seed,
            ctx.family,
            mode,
            decision.action,
            decision.profile,
            record_flags,
            esi,
            Self::K_MAX,
            0,
            st.chain_hash,
            &payload,
            auth_tag,
        );

        st.chain_hash = rec.chain_hash();
        drop(st);

        self.ring.publish(seqno, rec);
        seqno
    }

    /// Snapshot a best-effort consistent view of the ring buffer for tooling/harness.
    #[must_use]
    pub fn snapshot_sorted(&self) -> Vec<EvidenceSymbolRecord> {
        self.ring.snapshot_sorted()
    }
}

fn stream_index(mode: SafetyLevel, family: ApiFamily) -> usize {
    let mode_bit = if matches!(mode, SafetyLevel::Hardened) {
        1
    } else {
        0
    };
    (family as usize) * 2 + mode_bit
}

/// Overwrite-on-full evidence ring buffer.
///
/// Writer protocol (single record):
/// 1. allocate global `seqno`
/// 2. write record bytes into slot
/// 3. publish `seqno` with `Release`
///
/// Reader protocol (snapshot):
/// 1. read published `seqno` with `Acquire`
/// 2. copy record
/// 3. re-read published `seqno` with `Acquire` and accept iff unchanged
pub struct EvidenceRingBuffer<const CAP: usize> {
    next_seqno: AtomicU64,
    slots: [EvidenceSlot; CAP],
}

struct EvidenceSlot {
    published_seqno: AtomicU64,
    record: Mutex<EvidenceSymbolRecord>,
}

impl EvidenceSlot {
    fn new() -> Self {
        Self {
            published_seqno: AtomicU64::new(0),
            record: Mutex::new(EvidenceSymbolRecord::zeroed()),
        }
    }
}

impl<const CAP: usize> Default for EvidenceRingBuffer<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> EvidenceRingBuffer<CAP> {
    #[must_use]
    pub fn new() -> Self {
        // CAP is expected to be a smallish power of two, but we don't require it.
        Self {
            next_seqno: AtomicU64::new(0),
            slots: core::array::from_fn(|_| EvidenceSlot::new()),
        }
    }

    /// Allocate a new global sequence number (monotonic).
    pub fn allocate_seqno(&self) -> u64 {
        self.next_seqno
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    /// Publish a record for a previously allocated seqno.
    pub fn publish(&self, seqno: u64, record: EvidenceSymbolRecord) {
        let idx = (seqno as usize) % CAP;
        let slot = &self.slots[idx];
        debug_assert_eq!(record.seqno(), seqno);
        // Write record under the slot mutex, then publish the seqno.
        // Readers will Acquire-load seqno and then lock/copy record.
        *slot.record.lock() = record;
        slot.published_seqno.store(seqno, Ordering::Release);
    }

    /// Snapshot all stable records and return them sorted by `seqno`.
    #[must_use]
    pub fn snapshot_sorted(&self) -> Vec<EvidenceSymbolRecord> {
        let mut out = Vec::new();
        for slot in &self.slots {
            let s1 = slot.published_seqno.load(Ordering::Acquire);
            if s1 == 0 {
                continue;
            }
            let rec = *slot.record.lock();
            let s2 = slot.published_seqno.load(Ordering::Acquire);
            if s1 == s2 && rec.seqno() == s1 {
                out.push(rec);
            }
        }
        out.sort_by_key(EvidenceSymbolRecord::seqno);
        out
    }
}

// ── Byte helpers ───────────────────────────────────────────────

#[inline]
fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

// ── Hashing ────────────────────────────────────────────────────

/// Fast non-cryptographic 64-bit hash for integrity (corruption/torn-write detection).
///
/// This is intentionally small and deterministic. It is not meant to resist an
/// adversary; tooling can layer stronger MACs using the reserved auth tag bytes.
fn evidence_hash64(bytes: &[u8], seed: u64) -> u64 {
    // MurmurHash3-inspired 64-bit mix (x64 body) with explicit LE chunking.
    const C1: u64 = 0x87C3_7B91_1142_53D5;
    const C2: u64 = 0x4CF5_AD43_2745_937F;

    let mut h = seed ^ (bytes.len() as u64);
    let mut i = 0usize;
    while i + 8 <= bytes.len() {
        let mut k = u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ]);
        k = k.wrapping_mul(C1);
        k = k.rotate_left(31);
        k = k.wrapping_mul(C2);
        h ^= k;
        h = h.rotate_left(27);
        h = h.wrapping_mul(5).wrapping_add(0x52DC_E729);
        i += 8;
    }

    // Tail (<=7 bytes), little-endian folded into k.
    let mut k1 = 0u64;
    let tail = &bytes[i..];
    for (j, b) in tail.iter().enumerate() {
        k1 |= (*b as u64) << (8 * j);
    }
    if !tail.is_empty() {
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h ^= k1;
    }

    fmix64(h)
}

#[inline]
fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
    k ^= k >> 33;
    k = k.wrapping_mul(0xC4CE_B9FE_1A85_EC53);
    k ^= k >> 33;
    k
}

#[inline]
fn splitmix64(mut x: u64) -> u64 {
    splitmix64_next(&mut x)
}

#[inline]
fn splitmix64_next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn chain_hash64(
    prev_chain_hash: u64,
    record_bytes: &[u8; EVIDENCE_RECORD_SIZE],
    auth_tag_present: bool,
) -> u64 {
    // Material = prev || header_prefix(with payload_hash) || auth_tag_bytes.
    let mut tmp = [0u8; 8 + OFF_CHAIN_HASH + EVIDENCE_AUTH_TAG_SIZE];
    tmp[0..8].copy_from_slice(&prev_chain_hash.to_le_bytes());
    tmp[8..8 + OFF_CHAIN_HASH].copy_from_slice(&record_bytes[0..OFF_CHAIN_HASH]);
    tmp[8 + OFF_CHAIN_HASH..]
        .copy_from_slice(&record_bytes[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + EVIDENCE_AUTH_TAG_SIZE]);

    // If auth tag is not present, it's still hashed (as zeros). The flag is
    // already part of header_prefix via `flags`, but we also domain-separate
    // the chain seed to keep "tagged" and "untagged" streams disjoint.
    let domain = 0xBADC_0FFE_E0D0_0001u64 ^ (auth_tag_present as u64);
    evidence_hash64(&tmp, domain)
}

// ── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn record_layout_is_stable_v1() {
        assert_eq!(EVIDENCE_HEADER_SIZE, 64);
        assert_eq!(EVIDENCE_SYMBOL_SIZE_T, 128);
        assert_eq!(EVIDENCE_AUTH_TAG_SIZE, 32);
        assert_eq!(EVIDENCE_RECORD_SIZE, 256);
        assert_eq!(PAYLOAD_OFFSET, 64);
        assert_eq!(AUTH_TAG_OFFSET, 192);
        assert_eq!(RESERVED_OFFSET, 224);
        assert_eq!(RESERVED_OFFSET + 32, EVIDENCE_RECORD_SIZE);
        assert_eq!(size_of::<EvidenceSymbolRecord>(), EVIDENCE_RECORD_SIZE);
    }

    #[test]
    fn record_build_and_basic_parse_roundtrip() {
        let epoch_id = 0x1122_3344_5566_7788;
        let seed = 0x0102_0304_0506_0708;
        let seqno = 42;
        let payload = [7u8; EVIDENCE_SYMBOL_SIZE_T];
        let auth = [9u8; EVIDENCE_AUTH_TAG_SIZE];
        let rec = EvidenceSymbolRecord::build_v1(
            epoch_id,
            seqno,
            seed,
            ApiFamily::Allocator,
            SafetyLevel::Hardened,
            MembraneAction::Repair(HealingAction::IgnoreDoubleFree),
            ValidationProfile::Full,
            FLAG_SYSTEMATIC | FLAG_AUTH_TAG_PRESENT,
            3,
            256,
            0,
            0,
            &payload,
            Some(&auth),
        );

        rec.validate_basic().unwrap();
        assert_eq!(rec.epoch_id(), epoch_id);
        assert_eq!(rec.seqno(), seqno);
        assert_eq!(rec.seed(), seed);
        assert_eq!(rec.family(), ApiFamily::Allocator as u8);
        assert_eq!(rec.mode(), 1);
        assert_eq!(rec.action(), 2);
        assert_eq!(rec.profile(), 1);
        assert_eq!(rec.esi(), 3);
        assert_eq!(rec.k_source(), 256);
        assert_eq!(rec.r_repair(), 0);
        assert_eq!(rec.symbol_size_t() as usize, EVIDENCE_SYMBOL_SIZE_T);
        assert_eq!(rec.payload(), &payload);
        assert_eq!(rec.auth_tag(), &auth);
        assert_ne!(rec.payload_hash(), 0);
        assert_ne!(rec.chain_hash(), 0);
    }

    #[test]
    fn encode_decision_payload_has_expected_header_bytes() {
        let ctx = RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0xABCD,
            requested_bytes: 123,
            is_write: true,
            contention_hint: 9,
            bloom_negative: false,
        };
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 7,
            risk_upper_bound_ppm: 99,
            evidence_seqno: 0,
        };
        let p = encode_decision_payload_v1(SafetyLevel::Strict, ctx, decision, 17, false, None);
        assert_eq!(&p[0..4], b"EVP1");
        assert_eq!(p[4], 1);
        assert_eq!(p[5], 1);
        assert_eq!(read_u64(&p, 8), 0xABCD);
        assert_eq!(read_u64(&p, 16), 123);
        assert_eq!(p[24] & 1, 1); // is_write
        assert_eq!(p[25], 0); // strict mode
        assert_eq!(read_u16(&p, 26), 9);
        assert_eq!(u32::from_le_bytes([p[28], p[29], p[30], p[31]]), 7);
        assert_eq!(u32::from_le_bytes([p[32], p[33], p[34], p[35]]), 99);
    }

    #[test]
    fn encode_decision_payload_embeds_loss_evidence_block() {
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x1234,
            requested_bytes: 256,
            is_write: false,
            contention_hint: 3,
            bloom_negative: true,
        };
        let decision = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::UpgradeToSafeVariant),
            policy_id: 11,
            risk_upper_bound_ppm: 250_000,
            evidence_seqno: 0,
        };
        let loss = LossEvidenceV1 {
            posterior_adverse_ppm: 720_000,
            selected_action: 2,
            competing_action: 1,
            selected_expected_loss_milli: 640,
            competing_expected_loss_milli: 910,
        };
        let p =
            encode_decision_payload_v1(SafetyLevel::Hardened, ctx, decision, 64, true, Some(loss));
        assert_eq!(p[42], 1);
        assert_eq!(p[43], LOSS_BLOCK_VERSION_V1);
        assert_eq!(
            u32::from_le_bytes([
                p[LOSS_BLOCK_OFFSET],
                p[LOSS_BLOCK_OFFSET + 1],
                p[LOSS_BLOCK_OFFSET + 2],
                p[LOSS_BLOCK_OFFSET + 3],
            ]),
            loss.posterior_adverse_ppm
        );
        assert_eq!(p[LOSS_BLOCK_OFFSET + 4], loss.selected_action);
        assert_eq!(p[LOSS_BLOCK_OFFSET + 5], loss.competing_action);
        assert_eq!(
            u32::from_le_bytes([
                p[LOSS_BLOCK_OFFSET + 8],
                p[LOSS_BLOCK_OFFSET + 9],
                p[LOSS_BLOCK_OFFSET + 10],
                p[LOSS_BLOCK_OFFSET + 11],
            ]),
            loss.selected_expected_loss_milli
        );
        assert_eq!(
            u32::from_le_bytes([
                p[LOSS_BLOCK_OFFSET + 12],
                p[LOSS_BLOCK_OFFSET + 13],
                p[LOSS_BLOCK_OFFSET + 14],
                p[LOSS_BLOCK_OFFSET + 15],
            ]),
            loss.competing_expected_loss_milli
        );
    }

    #[test]
    fn ring_buffer_overwrites_on_full() {
        const CAP: usize = 4;
        let ring: EvidenceRingBuffer<CAP> = EvidenceRingBuffer::new();

        for i in 0..10u64 {
            let seq = ring.allocate_seqno();
            let payload = [i as u8; EVIDENCE_SYMBOL_SIZE_T];
            let rec = EvidenceSymbolRecord::build_v1(
                1,
                seq,
                2,
                ApiFamily::Allocator,
                SafetyLevel::Strict,
                MembraneAction::Allow,
                ValidationProfile::Fast,
                FLAG_SYSTEMATIC,
                0,
                256,
                0,
                0,
                &payload,
                None,
            );
            ring.publish(seq, rec);
        }

        let snap = ring.snapshot_sorted();
        // Capacity bounds the number of stable records visible.
        assert!(snap.len() <= CAP);
        // The latest seqno should be 10 (since we wrote 10 records).
        assert_eq!(snap.last().unwrap().seqno(), 10);
    }

    #[test]
    fn derive_repair_symbol_count_matches_spec_examples() {
        assert_eq!(derive_repair_symbol_count_v1(0, 10), 0);
        assert_eq!(derive_repair_symbol_count_v1(1, 0), SLACK_DECODE_V1);
        assert_eq!(derive_repair_symbol_count_v1(8, 10), SLACK_DECODE_V1);
        assert_eq!(derive_repair_symbol_count_v1(20, 10), SLACK_DECODE_V1);
        assert_eq!(derive_repair_symbol_count_v1(21, 10), 3);
        assert_eq!(derive_repair_symbol_count_v1(256, 10), 26);
    }

    #[test]
    fn loss_fraction_ppm_is_zero_when_r_equals_slack() {
        let k = 256;
        let r = SLACK_DECODE_V1;
        assert_eq!(loss_fraction_max_ppm_v1(k, r), 0);
    }

    #[test]
    fn repair_schedule_indices_are_in_range_and_unique() {
        let epoch_seed = 0x0123_4567_89AB_CDEF;
        let k_source = 32;
        let repair_esi = k_source;
        let sched = derive_repair_schedule_v1(epoch_seed, k_source, repair_esi);
        assert!(sched.degree() >= 1);
        assert!(sched.degree() as usize <= REPAIR_MAX_DEGREE_V1);
        assert_eq!(sched.indices().len(), sched.degree() as usize);
        for &idx in sched.indices() {
            assert!(idx < k_source);
        }
        for (i, &a) in sched.indices().iter().enumerate() {
            for &b in &sched.indices()[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn xor_repair_payload_is_deterministic_and_matches_xor_of_selected_sources() {
        let epoch_seed = 0x0F1E_2D3C_4B5A_6978;
        const K: usize = 8;
        let mut src = [[0u8; EVIDENCE_SYMBOL_SIZE_T]; K];
        for (i, s) in src.iter_mut().enumerate() {
            *s = [i as u8; EVIDENCE_SYMBOL_SIZE_T];
        }

        let k_source = u16::try_from(src.len()).unwrap();
        let repair_esi = k_source;

        let sched = derive_repair_schedule_v1(epoch_seed, k_source, repair_esi);
        let expected_byte = sched
            .indices()
            .iter()
            .fold(0u8, |acc, &idx| acc ^ (idx as u8));

        let p1 = encode_xor_repair_payload_v1(epoch_seed, &src, repair_esi);
        let p2 = encode_xor_repair_payload_v1(epoch_seed, &src, repair_esi);
        assert_eq!(p1, p2);
        assert!(p1.iter().all(|&b| b == expected_byte));
    }

    #[test]
    fn repair_schedule_v1_test_vector_seed_0x0123_k8_esi8() {
        let epoch_seed = 0x0123_4567_89AB_CDEF;
        let k_source = 8;
        let repair_esi = 8;
        let sched = derive_repair_schedule_v1(epoch_seed, k_source, repair_esi);
        assert_eq!(sched.degree(), 2);
        assert_eq!(sched.indices(), &[4, 5]);

        let mut src = [[0u8; EVIDENCE_SYMBOL_SIZE_T]; 8];
        for (i, s) in src.iter_mut().enumerate() {
            *s = [i as u8; EVIDENCE_SYMBOL_SIZE_T];
        }
        let payload = encode_xor_repair_payload_v1(epoch_seed, &src, repair_esi);
        assert!(payload.iter().all(|&b| b == (4u8 ^ 5u8)));
    }
}
