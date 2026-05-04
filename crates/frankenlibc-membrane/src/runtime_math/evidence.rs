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
use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::time::Instant;

use parking_lot::Mutex;
use serde_json::Value;

use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION, PolicyId};
use crate::runtime_math::{
    ApiFamily, MembraneAction, RuntimeContext, RuntimeDecision, ValidationProfile,
};
use crate::util::now_utc_iso_like;

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

/// Basic parse errors for v1 decision payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionPayloadError {
    BadMagic,
    UnsupportedVersion(u8),
    UnsupportedEventKind(u8),
    UnsupportedLossBlockVersion(u8),
}

/// Decoded v1 decision payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedDecisionPayloadV1 {
    pub mode: u8,
    pub addr_hint: usize,
    pub requested_bytes: usize,
    pub is_write: bool,
    pub bloom_negative: bool,
    pub contention_hint: u16,
    pub policy_id: u32,
    pub risk_upper_bound_ppm: u32,
    pub estimated_cost_ns: u64,
    pub adverse: bool,
    pub healing_action: HealingAction,
    pub loss_evidence: Option<LossEvidenceV1>,
}

/// Decode a v1 decision payload emitted inside an `EvidenceSymbolRecord`.
pub fn decode_decision_payload_v1(
    payload: &[u8; EVIDENCE_SYMBOL_SIZE_T],
) -> Result<DecodedDecisionPayloadV1, DecisionPayloadError> {
    if payload[0..4] != PAYLOAD_MAGIC_DECISION_V1 {
        return Err(DecisionPayloadError::BadMagic);
    }
    if payload[4] != PAYLOAD_VERSION_V1 {
        return Err(DecisionPayloadError::UnsupportedVersion(payload[4]));
    }
    if payload[5] != EVENT_KIND_DECISION {
        return Err(DecisionPayloadError::UnsupportedEventKind(payload[5]));
    }
    if payload[42] != 0 && payload[43] != LOSS_BLOCK_VERSION_V1 {
        return Err(DecisionPayloadError::UnsupportedLossBlockVersion(
            payload[43],
        ));
    }

    let loss_evidence = if payload[42] == 0 {
        None
    } else {
        Some(LossEvidenceV1 {
            posterior_adverse_ppm: read_u32(payload, LOSS_BLOCK_OFFSET).min(1_000_000),
            selected_action: payload[LOSS_BLOCK_OFFSET + 4],
            competing_action: payload[LOSS_BLOCK_OFFSET + 5],
            selected_expected_loss_milli: read_u32(payload, LOSS_BLOCK_OFFSET + 8),
            competing_expected_loss_milli: read_u32(payload, LOSS_BLOCK_OFFSET + 12),
        })
    };

    Ok(DecodedDecisionPayloadV1 {
        mode: payload[25],
        addr_hint: usize::try_from(read_u64(payload, 8)).unwrap_or(usize::MAX),
        requested_bytes: usize::try_from(read_u64(payload, 16)).unwrap_or(usize::MAX),
        is_write: (payload[24] & (1 << 0)) != 0,
        bloom_negative: (payload[24] & (1 << 1)) != 0,
        contention_hint: read_u16(payload, 26),
        policy_id: read_u32(payload, 28),
        risk_upper_bound_ppm: read_u32(payload, 32),
        estimated_cost_ns: u64::from(read_u32(payload, 36)),
        adverse: payload[40] != 0,
        healing_action: decode_healing_action(
            payload[41],
            read_u64(payload, 44),
            read_u64(payload, 52),
        ),
        loss_evidence,
    })
}

/// Coarse decision-class taxonomy used by the galaxy-brain card ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DecisionType {
    ModeTransition = 0,
    Quarantine = 1,
    Repair = 2,
    Escalation = 3,
    CertificateEvaluation = 4,
    PolicyOverride = 5,
}

/// Compact runtime decision card (galaxy-brain card v1).
///
/// This is intentionally copyable and allocation-free so the hot recording path can
/// publish cards to a bounded ring with deterministic overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionCardV1 {
    pub decision_id: u64,
    pub decision_type: DecisionType,
    pub thread_id: u64,
    pub symbol_id: u32,
    pub timestamp_mono_ns: u64,
    pub epoch_id: u64,
    pub evidence_seqno: u64,
    pub context: RuntimeContext,
    pub decision: RuntimeDecision,
    pub adverse: bool,
    pub estimated_cost_ns: u64,
    pub reasoning_flags: u32,
    pub counterfactual_action: MembraneAction,
    pub loss_evidence: Option<LossEvidenceV1>,
}

impl DecisionCardV1 {
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            decision_id: 0,
            decision_type: DecisionType::CertificateEvaluation,
            thread_id: 0,
            symbol_id: 0,
            timestamp_mono_ns: 0,
            epoch_id: 0,
            evidence_seqno: 0,
            context: RuntimeContext {
                family: ApiFamily::PointerValidation,
                addr_hint: 0,
                requested_bytes: 0,
                is_write: false,
                contention_hint: 0,
                bloom_negative: false,
            },
            decision: RuntimeDecision {
                profile: ValidationProfile::Fast,
                action: MembraneAction::Allow,
                policy_id: 0,
                risk_upper_bound_ppm: 0,
                evidence_seqno: 0,
            },
            adverse: false,
            estimated_cost_ns: 0,
            reasoning_flags: 0,
            counterfactual_action: MembraneAction::Allow,
            loss_evidence: None,
        }
    }
}

/// Stable JSONL schema name for runtime membrane-decision evidence rows.
pub const RUNTIME_EVIDENCE_JSONL_SCHEMA_V1: &str = "runtime_evidence.decision.v1";

/// Required top-level fields for [`RUNTIME_EVIDENCE_JSONL_SCHEMA_V1`].
pub const RUNTIME_EVIDENCE_REQUIRED_FIELDS_V1: &[&str] = &[
    "schema",
    "schema_version",
    "timestamp",
    "trace_id",
    "bead_id",
    "event",
    "mode",
    "runtime_mode",
    "validation_profile",
    "decision_path",
    "healing_action",
    "denied",
    "latency_ns",
    "api_family",
    "symbol",
    "context",
    "source_commit",
    "artifact_refs",
];

pub const RUNTIME_EVIDENCE_DEFAULT_ARTIFACT_REFS: &[&str] =
    &["crates/frankenlibc-membrane/src/runtime_math/evidence.rs"];

/// Runtime evidence logging policy exposed for gates and replay tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeEvidenceLogPolicy {
    pub hot_path_io_enabled_by_default: bool,
    pub journal_enabled_by_default: bool,
    pub bounded_ring_capacity: usize,
    pub overflow_policy: &'static str,
}

impl RuntimeEvidenceLogPolicy {
    #[must_use]
    pub const fn bounded_ring(capacity: usize) -> Self {
        Self {
            hot_path_io_enabled_by_default: false,
            journal_enabled_by_default: false,
            bounded_ring_capacity: capacity,
            overflow_policy: "overwrite_oldest_ring_slot",
        }
    }
}

/// Fail-closed validation errors for runtime evidence JSONL rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEvidenceRowValidationError {
    NotObject,
    MissingRequiredField(&'static str),
    WrongType(&'static str),
    EmptyString(&'static str),
    EmptyArtifactRefs,
    UnexpectedValue(&'static str),
}

/// Validate one parsed runtime-evidence JSONL row against the v1 required-field contract.
pub fn validate_runtime_evidence_row_v1(
    row: &Value,
) -> Result<(), RuntimeEvidenceRowValidationError> {
    let obj = row
        .as_object()
        .ok_or(RuntimeEvidenceRowValidationError::NotObject)?;
    for field in RUNTIME_EVIDENCE_REQUIRED_FIELDS_V1 {
        if !obj.contains_key(*field) {
            return Err(RuntimeEvidenceRowValidationError::MissingRequiredField(
                field,
            ));
        }
    }

    expect_exact_string(row, "schema", RUNTIME_EVIDENCE_JSONL_SCHEMA_V1)?;
    expect_exact_string(row, "event", "runtime_evidence")?;
    expect_one_of(row, "mode", &["strict", "hardened"])?;
    expect_one_of(row, "runtime_mode", &["strict", "hardened"])?;
    expect_one_of(row, "validation_profile", &["Fast", "Full"])?;
    expect_non_empty_string(row, "timestamp")?;
    expect_non_empty_string(row, "trace_id")?;
    expect_non_empty_string(row, "bead_id")?;
    expect_non_empty_string(row, "decision_path")?;
    expect_non_empty_string(row, "api_family")?;
    expect_non_empty_string(row, "symbol")?;
    expect_non_empty_string(row, "source_commit")?;
    expect_bool(row, "denied")?;
    expect_u64(row, "latency_ns")?;
    expect_context(row)?;
    expect_healing_action(row)?;
    expect_artifact_refs(row)?;
    Ok(())
}

/// Query filter for decision cards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DecisionCardFilter {
    pub decision_type: Option<DecisionType>,
    pub min_timestamp_mono_ns: Option<u64>,
    pub max_timestamp_mono_ns: Option<u64>,
    pub thread_id: Option<u64>,
    pub symbol_id: Option<u32>,
}

impl DecisionCardFilter {
    #[must_use]
    pub const fn any() -> Self {
        Self {
            decision_type: None,
            min_timestamp_mono_ns: None,
            max_timestamp_mono_ns: None,
            thread_id: None,
            symbol_id: None,
        }
    }

    #[must_use]
    pub fn matches(&self, card: &DecisionCardV1) -> bool {
        if let Some(t) = self.decision_type
            && card.decision_type != t
        {
            return false;
        }
        if let Some(min_ts) = self.min_timestamp_mono_ns
            && card.timestamp_mono_ns < min_ts
        {
            return false;
        }
        if let Some(max_ts) = self.max_timestamp_mono_ns
            && card.timestamp_mono_ns > max_ts
        {
            return false;
        }
        if let Some(thread_id) = self.thread_id
            && card.thread_id != thread_id
        {
            return false;
        }
        if let Some(symbol_id) = self.symbol_id
            && card.symbol_id != symbol_id
        {
            return false;
        }
        true
    }
}

/// Expected replay outcome for a sampled runtime decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceReplayExpectation {
    pub replay_id: String,
    pub evidence_seqno: u64,
    pub expected_decision: MembraneAction,
    pub expected_profile: Option<ValidationProfile>,
    pub expected_policy_id: Option<u32>,
    pub expected_runtime_mode: Option<SafetyLevel>,
    pub replacement_level: String,
    pub artifact_refs: Vec<String>,
}

/// Runtime replay outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeEvidenceReplayStatus {
    Passed,
    MissingDecisionCard,
    MissingEvidenceRecord,
    InvalidEvidenceRecord,
    InvalidDecisionPayload,
    DecisionMismatch,
    MetadataMismatch,
}

/// Per-expectation replay row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceReplayRow {
    pub trace_id: String,
    pub replay_id: String,
    pub evidence_seqno: u64,
    pub api_family: String,
    pub symbol: String,
    pub runtime_mode: String,
    pub replacement_level: String,
    pub decision_path: String,
    pub healing_action: String,
    pub expected_decision: String,
    pub actual_decision: Option<String>,
    pub expected_profile: Option<String>,
    pub actual_profile: Option<String>,
    pub expected_policy_id: Option<u32>,
    pub actual_policy_id: Option<u32>,
    pub evidence_snapshot: Option<RuntimeEvidenceSnapshot>,
    pub status: RuntimeEvidenceReplayStatus,
    pub failure_signature: Option<String>,
    pub artifact_refs: Vec<String>,
}

/// Redacted ring-buffer snapshot attached to replay output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceSnapshot {
    pub epoch_id: u64,
    pub seqno: u64,
    pub decision_id: u64,
    pub payload_hash: u64,
    pub chain_hash: u64,
    pub addr_hint_redacted: bool,
    pub requested_bytes: usize,
    pub risk_upper_bound_ppm: u32,
    pub estimated_cost_ns: u64,
}

/// Replay report for deterministic runtime-evidence gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeEvidenceReplayReport {
    pub bead_id: String,
    pub rows: Vec<RuntimeEvidenceReplayRow>,
    pub cards_out_of_order: bool,
    pub records_out_of_order: bool,
}

impl RuntimeEvidenceReplayReport {
    #[must_use]
    pub fn passed(&self) -> bool {
        !self.cards_out_of_order
            && !self.records_out_of_order
            && self
                .rows
                .iter()
                .all(|row| row.status == RuntimeEvidenceReplayStatus::Passed)
    }

    #[must_use]
    pub fn to_json(&self) -> String {
        let mut out = String::new();
        let passed = self.passed();
        let failure_count = self
            .rows
            .iter()
            .filter(|row| row.status != RuntimeEvidenceReplayStatus::Passed)
            .count()
            + usize::from(self.cards_out_of_order)
            + usize::from(self.records_out_of_order);
        let _ = write!(
            &mut out,
            "{{\"schema\":\"runtime_evidence_replay.v1\",\"bead_id\":\"{}\",\"passed\":{},\"count\":{},\"failure_count\":{},\"cards_out_of_order\":{},\"records_out_of_order\":{},\"rows\":[",
            json_escape(&self.bead_id),
            passed,
            self.rows.len(),
            failure_count,
            self.cards_out_of_order,
            self.records_out_of_order
        );

        for (idx, row) in self.rows.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            let _ = write!(
                &mut out,
                "{{\"trace_id\":\"{}\",\"bead_id\":\"{}\",\"replay_id\":\"{}\",\"evidence_seqno\":{},\"api_family\":\"{}\",\"symbol\":\"{}\",\"runtime_mode\":\"{}\",\"replacement_level\":\"{}\",\"decision_path\":\"{}\",\"healing_action\":\"{}\",\"expected_decision\":\"{}\",\"actual_decision\":{},\"expected_profile\":{},\"actual_profile\":{},\"expected_policy_id\":{},\"actual_policy_id\":{},",
                json_escape(&row.trace_id),
                json_escape(&self.bead_id),
                json_escape(&row.replay_id),
                row.evidence_seqno,
                json_escape(&row.api_family),
                json_escape(&row.symbol),
                json_escape(&row.runtime_mode),
                json_escape(&row.replacement_level),
                json_escape(&row.decision_path),
                json_escape(&row.healing_action),
                json_escape(&row.expected_decision),
                json_string_or_null(row.actual_decision.as_deref()),
                json_string_or_null(row.expected_profile.as_deref()),
                json_string_or_null(row.actual_profile.as_deref()),
                json_u32_or_null(row.expected_policy_id),
                json_u32_or_null(row.actual_policy_id)
            );
            match &row.evidence_snapshot {
                Some(snapshot) => {
                    let _ = write!(
                        &mut out,
                        "\"evidence_snapshot\":{{\"epoch_id\":{},\"seqno\":{},\"decision_id\":{},\"payload_hash\":{},\"chain_hash\":{},\"addr_hint_redacted\":{},\"requested_bytes\":{},\"risk_upper_bound_ppm\":{},\"estimated_cost_ns\":{}}},",
                        snapshot.epoch_id,
                        snapshot.seqno,
                        snapshot.decision_id,
                        snapshot.payload_hash,
                        snapshot.chain_hash,
                        snapshot.addr_hint_redacted,
                        snapshot.requested_bytes,
                        snapshot.risk_upper_bound_ppm,
                        snapshot.estimated_cost_ns
                    );
                }
                None => out.push_str("\"evidence_snapshot\":null,"),
            }
            let _ = write!(
                &mut out,
                "\"status\":\"{}\",\"failure_signature\":{},\"artifact_refs\":[",
                replay_status_name(row.status),
                json_string_or_null(row.failure_signature.as_deref())
            );
            for (ref_idx, artifact) in row.artifact_refs.iter().enumerate() {
                if ref_idx > 0 {
                    out.push(',');
                }
                let _ = write!(&mut out, "\"{}\"", json_escape(artifact));
            }
            out.push_str("]}");
        }
        out.push_str("]}");
        out
    }
}

const DECISION_CARD_JOURNAL_MAGIC: [u8; 4] = *b"DCR1";
const DECISION_CARD_JOURNAL_VERSION_V1: u16 = 1;
const DECISION_CARD_JOURNAL_RECORD_SIZE: usize = 176;

const DCR_OFF_MAGIC: usize = 0;
const DCR_OFF_VERSION: usize = 4;
const DCR_OFF_DECISION_ID: usize = 8;
const DCR_OFF_DECISION_TYPE: usize = 16;
const DCR_OFF_THREAD_ID: usize = 20;
const DCR_OFF_SYMBOL_ID: usize = 28;
const DCR_OFF_TIMESTAMP_NS: usize = 32;
const DCR_OFF_EPOCH_ID: usize = 40;
const DCR_OFF_EVIDENCE_SEQNO: usize = 48;
const DCR_OFF_CTX_FAMILY: usize = 56;
const DCR_OFF_CTX_IS_WRITE: usize = 57;
const DCR_OFF_CTX_BLOOM_NEGATIVE: usize = 58;
const DCR_OFF_CTX_CONTENTION_HINT: usize = 60;
const DCR_OFF_DECISION_PROFILE: usize = 62;
const DCR_OFF_DECISION_ACTION: usize = 63;
const DCR_OFF_DECISION_HEAL_CODE: usize = 64;
const DCR_OFF_COUNTERFACTUAL_ACTION: usize = 65;
const DCR_OFF_COUNTERFACTUAL_HEAL_CODE: usize = 66;
const DCR_OFF_LOSS_PRESENT: usize = 67;
const DCR_OFF_REASONING_FLAGS: usize = 68;
const DCR_OFF_POLICY_ID: usize = 72;
const DCR_OFF_RISK_UPPER_BOUND_PPM: usize = 76;
const DCR_OFF_DECISION_EVIDENCE_SEQNO: usize = 80;
const DCR_OFF_ESTIMATED_COST_NS: usize = 88;
const DCR_OFF_CTX_ADDR_HINT: usize = 96;
const DCR_OFF_CTX_REQUESTED_BYTES: usize = 104;
const DCR_OFF_DECISION_HEAL_ARG0: usize = 112;
const DCR_OFF_DECISION_HEAL_ARG1: usize = 120;
const DCR_OFF_COUNTERFACTUAL_HEAL_ARG0: usize = 128;
const DCR_OFF_COUNTERFACTUAL_HEAL_ARG1: usize = 136;
const DCR_OFF_LOSS_POSTERIOR_PPM: usize = 144;
const DCR_OFF_LOSS_SELECTED_ACTION: usize = 148;
const DCR_OFF_LOSS_COMPETING_ACTION: usize = 149;
const DCR_OFF_LOSS_SELECTED_EXPECTED_MILLI: usize = 152;
const DCR_OFF_LOSS_COMPETING_EXPECTED_MILLI: usize = 156;
const DCR_OFF_ADVERSE: usize = 160;

struct DecisionCardJournal {
    file: File,
    flush_every: u64,
    pending_since_flush: u64,
    appended_total: u64,
    flush_total: u64,
}

impl DecisionCardJournal {
    fn open(path: &Path, flush_every: u64) -> io::Result<(Self, Vec<DecisionCardV1>)> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        file.seek(SeekFrom::Start(0))?;
        let replay_cards = replay_decision_cards_from_file(&mut file)?;
        file.seek(SeekFrom::End(0))?;
        Ok((
            Self {
                file,
                flush_every: flush_every.max(1),
                pending_since_flush: 0,
                appended_total: 0,
                flush_total: 0,
            },
            replay_cards,
        ))
    }

    fn append(&mut self, card: DecisionCardV1) -> io::Result<()> {
        let record = encode_decision_card_journal_record(card);
        self.file.write_all(&record)?;
        self.pending_since_flush = self.pending_since_flush.saturating_add(1);
        self.appended_total = self.appended_total.saturating_add(1);
        if self.pending_since_flush >= self.flush_every {
            self.file.sync_data()?;
            self.pending_since_flush = 0;
            self.flush_total = self.flush_total.saturating_add(1);
        }
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.pending_since_flush > 0 {
            self.file.sync_data()?;
            self.pending_since_flush = 0;
            self.flush_total = self.flush_total.saturating_add(1);
        }
        Ok(())
    }

    fn stats(&self) -> (u64, u64) {
        (self.appended_total, self.flush_total)
    }
}

fn replay_decision_cards_from_file(file: &mut File) -> io::Result<Vec<DecisionCardV1>> {
    let mut cards = Vec::new();
    let mut buf = [0u8; DECISION_CARD_JOURNAL_RECORD_SIZE];
    loop {
        match file.read_exact(&mut buf) {
            Ok(()) => {
                if let Some(card) = decode_decision_card_journal_record(&buf) {
                    cards.push(card);
                }
            }
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err),
        }
    }
    Ok(cards)
}

fn encode_decision_card_journal_record(
    card: DecisionCardV1,
) -> [u8; DECISION_CARD_JOURNAL_RECORD_SIZE] {
    let mut out = [0u8; DECISION_CARD_JOURNAL_RECORD_SIZE];
    out[DCR_OFF_MAGIC..DCR_OFF_MAGIC + 4].copy_from_slice(&DECISION_CARD_JOURNAL_MAGIC);
    write_u16(&mut out, DCR_OFF_VERSION, DECISION_CARD_JOURNAL_VERSION_V1);
    write_u64(&mut out, DCR_OFF_DECISION_ID, card.decision_id);
    out[DCR_OFF_DECISION_TYPE] = card.decision_type as u8;
    write_u64(&mut out, DCR_OFF_THREAD_ID, card.thread_id);
    write_u32(&mut out, DCR_OFF_SYMBOL_ID, card.symbol_id);
    write_u64(&mut out, DCR_OFF_TIMESTAMP_NS, card.timestamp_mono_ns);
    write_u64(&mut out, DCR_OFF_EPOCH_ID, card.epoch_id);
    write_u64(&mut out, DCR_OFF_EVIDENCE_SEQNO, card.evidence_seqno);
    out[DCR_OFF_CTX_FAMILY] = card.context.family as u8;
    out[DCR_OFF_CTX_IS_WRITE] = if card.context.is_write { 1 } else { 0 };
    out[DCR_OFF_CTX_BLOOM_NEGATIVE] = if card.context.bloom_negative { 1 } else { 0 };
    write_u16(
        &mut out,
        DCR_OFF_CTX_CONTENTION_HINT,
        card.context.contention_hint,
    );
    out[DCR_OFF_DECISION_PROFILE] = profile_code(card.decision.profile);
    out[DCR_OFF_DECISION_ACTION] = action_code(card.decision.action);
    out[DCR_OFF_COUNTERFACTUAL_ACTION] = action_code(card.counterfactual_action);
    write_u32(&mut out, DCR_OFF_REASONING_FLAGS, card.reasoning_flags);
    write_u32(&mut out, DCR_OFF_POLICY_ID, card.decision.policy_id);
    write_u32(
        &mut out,
        DCR_OFF_RISK_UPPER_BOUND_PPM,
        card.decision.risk_upper_bound_ppm,
    );
    write_u64(
        &mut out,
        DCR_OFF_DECISION_EVIDENCE_SEQNO,
        card.decision.evidence_seqno,
    );
    write_u64(&mut out, DCR_OFF_ESTIMATED_COST_NS, card.estimated_cost_ns);
    write_u64(
        &mut out,
        DCR_OFF_CTX_ADDR_HINT,
        u64::try_from(card.context.addr_hint).unwrap_or(u64::MAX),
    );
    write_u64(
        &mut out,
        DCR_OFF_CTX_REQUESTED_BYTES,
        u64::try_from(card.context.requested_bytes).unwrap_or(u64::MAX),
    );
    out[DCR_OFF_ADVERSE] = if card.adverse { 1 } else { 0 };

    let (decision_heal_code, decision_heal_arg0, decision_heal_arg1) =
        healing_code_and_args(card.decision.action);
    out[DCR_OFF_DECISION_HEAL_CODE] = decision_heal_code;
    write_u64(&mut out, DCR_OFF_DECISION_HEAL_ARG0, decision_heal_arg0);
    write_u64(&mut out, DCR_OFF_DECISION_HEAL_ARG1, decision_heal_arg1);

    let (counterfactual_heal_code, counterfactual_heal_arg0, counterfactual_heal_arg1) =
        healing_code_and_args(card.counterfactual_action);
    out[DCR_OFF_COUNTERFACTUAL_HEAL_CODE] = counterfactual_heal_code;
    write_u64(
        &mut out,
        DCR_OFF_COUNTERFACTUAL_HEAL_ARG0,
        counterfactual_heal_arg0,
    );
    write_u64(
        &mut out,
        DCR_OFF_COUNTERFACTUAL_HEAL_ARG1,
        counterfactual_heal_arg1,
    );

    if let Some(loss) = card.loss_evidence {
        out[DCR_OFF_LOSS_PRESENT] = 1;
        write_u32(
            &mut out,
            DCR_OFF_LOSS_POSTERIOR_PPM,
            loss.posterior_adverse_ppm.min(1_000_000),
        );
        out[DCR_OFF_LOSS_SELECTED_ACTION] = loss.selected_action;
        out[DCR_OFF_LOSS_COMPETING_ACTION] = loss.competing_action;
        write_u32(
            &mut out,
            DCR_OFF_LOSS_SELECTED_EXPECTED_MILLI,
            loss.selected_expected_loss_milli,
        );
        write_u32(
            &mut out,
            DCR_OFF_LOSS_COMPETING_EXPECTED_MILLI,
            loss.competing_expected_loss_milli,
        );
    }

    out
}

fn decode_decision_card_journal_record(
    bytes: &[u8; DECISION_CARD_JOURNAL_RECORD_SIZE],
) -> Option<DecisionCardV1> {
    if bytes[DCR_OFF_MAGIC..DCR_OFF_MAGIC + 4] != DECISION_CARD_JOURNAL_MAGIC {
        return None;
    }
    let version = read_u16(bytes, DCR_OFF_VERSION);
    if version != DECISION_CARD_JOURNAL_VERSION_V1 {
        return None;
    }

    let decision_type = decision_type_from_code(bytes[DCR_OFF_DECISION_TYPE])?;
    let context_family = api_family_from_code(bytes[DCR_OFF_CTX_FAMILY])?;
    let profile = validation_profile_from_code(bytes[DCR_OFF_DECISION_PROFILE]);

    let decision_action = decode_membrane_action(
        bytes[DCR_OFF_DECISION_ACTION],
        bytes[DCR_OFF_DECISION_HEAL_CODE],
        read_u64(bytes, DCR_OFF_DECISION_HEAL_ARG0),
        read_u64(bytes, DCR_OFF_DECISION_HEAL_ARG1),
    );
    let counterfactual_action = decode_membrane_action(
        bytes[DCR_OFF_COUNTERFACTUAL_ACTION],
        bytes[DCR_OFF_COUNTERFACTUAL_HEAL_CODE],
        read_u64(bytes, DCR_OFF_COUNTERFACTUAL_HEAL_ARG0),
        read_u64(bytes, DCR_OFF_COUNTERFACTUAL_HEAL_ARG1),
    );

    let loss_evidence = if bytes[DCR_OFF_LOSS_PRESENT] == 0 {
        None
    } else {
        Some(LossEvidenceV1 {
            posterior_adverse_ppm: read_u32(bytes, DCR_OFF_LOSS_POSTERIOR_PPM).min(1_000_000),
            selected_action: bytes[DCR_OFF_LOSS_SELECTED_ACTION],
            competing_action: bytes[DCR_OFF_LOSS_COMPETING_ACTION],
            selected_expected_loss_milli: read_u32(bytes, DCR_OFF_LOSS_SELECTED_EXPECTED_MILLI),
            competing_expected_loss_milli: read_u32(bytes, DCR_OFF_LOSS_COMPETING_EXPECTED_MILLI),
        })
    };

    Some(DecisionCardV1 {
        decision_id: read_u64(bytes, DCR_OFF_DECISION_ID),
        decision_type,
        thread_id: read_u64(bytes, DCR_OFF_THREAD_ID),
        symbol_id: read_u32(bytes, DCR_OFF_SYMBOL_ID),
        timestamp_mono_ns: read_u64(bytes, DCR_OFF_TIMESTAMP_NS),
        epoch_id: read_u64(bytes, DCR_OFF_EPOCH_ID),
        evidence_seqno: read_u64(bytes, DCR_OFF_EVIDENCE_SEQNO),
        context: RuntimeContext {
            family: context_family,
            addr_hint: usize::try_from(read_u64(bytes, DCR_OFF_CTX_ADDR_HINT))
                .unwrap_or(usize::MAX),
            requested_bytes: usize::try_from(read_u64(bytes, DCR_OFF_CTX_REQUESTED_BYTES))
                .unwrap_or(usize::MAX),
            is_write: bytes[DCR_OFF_CTX_IS_WRITE] != 0,
            contention_hint: read_u16(bytes, DCR_OFF_CTX_CONTENTION_HINT),
            bloom_negative: bytes[DCR_OFF_CTX_BLOOM_NEGATIVE] != 0,
        },
        decision: RuntimeDecision {
            profile,
            action: decision_action,
            policy_id: read_u32(bytes, DCR_OFF_POLICY_ID),
            risk_upper_bound_ppm: read_u32(bytes, DCR_OFF_RISK_UPPER_BOUND_PPM),
            evidence_seqno: read_u64(bytes, DCR_OFF_DECISION_EVIDENCE_SEQNO),
        },
        adverse: bytes[DCR_OFF_ADVERSE] != 0,
        estimated_cost_ns: read_u64(bytes, DCR_OFF_ESTIMATED_COST_NS),
        reasoning_flags: read_u32(bytes, DCR_OFF_REASONING_FLAGS),
        counterfactual_action,
        loss_evidence,
    })
}

fn decision_type_from_code(code: u8) -> Option<DecisionType> {
    match code {
        0 => Some(DecisionType::ModeTransition),
        1 => Some(DecisionType::Quarantine),
        2 => Some(DecisionType::Repair),
        3 => Some(DecisionType::Escalation),
        4 => Some(DecisionType::CertificateEvaluation),
        5 => Some(DecisionType::PolicyOverride),
        _ => None,
    }
}

fn api_family_from_code(code: u8) -> Option<ApiFamily> {
    match code {
        0 => Some(ApiFamily::PointerValidation),
        1 => Some(ApiFamily::Allocator),
        2 => Some(ApiFamily::StringMemory),
        3 => Some(ApiFamily::Stdio),
        4 => Some(ApiFamily::Threading),
        5 => Some(ApiFamily::Resolver),
        6 => Some(ApiFamily::MathFenv),
        7 => Some(ApiFamily::Loader),
        8 => Some(ApiFamily::Stdlib),
        9 => Some(ApiFamily::Ctype),
        10 => Some(ApiFamily::Time),
        11 => Some(ApiFamily::Signal),
        12 => Some(ApiFamily::IoFd),
        13 => Some(ApiFamily::Socket),
        14 => Some(ApiFamily::Locale),
        15 => Some(ApiFamily::Termios),
        16 => Some(ApiFamily::Inet),
        17 => Some(ApiFamily::Process),
        18 => Some(ApiFamily::VirtualMemory),
        19 => Some(ApiFamily::Poll),
        _ => None,
    }
}

const fn validation_profile_from_code(code: u8) -> ValidationProfile {
    if code == 1 {
        ValidationProfile::Full
    } else {
        ValidationProfile::Fast
    }
}

fn decode_healing_action(code: u8, arg0: u64, arg1: u64) -> HealingAction {
    match code {
        1 => HealingAction::ClampSize {
            requested: usize::try_from(arg0).unwrap_or(usize::MAX),
            clamped: usize::try_from(arg1).unwrap_or(usize::MAX),
        },
        2 => HealingAction::TruncateWithNull {
            requested: usize::try_from(arg0).unwrap_or(usize::MAX),
            truncated: usize::try_from(arg1).unwrap_or(usize::MAX),
        },
        3 => HealingAction::IgnoreDoubleFree,
        4 => HealingAction::IgnoreForeignFree,
        5 => HealingAction::ReallocAsMalloc {
            size: usize::try_from(arg0).unwrap_or(usize::MAX),
        },
        6 => HealingAction::ReturnSafeDefault,
        7 => HealingAction::UpgradeToSafeVariant,
        _ => HealingAction::None,
    }
}

fn decode_membrane_action(action_code: u8, heal_code: u8, arg0: u64, arg1: u64) -> MembraneAction {
    match action_code {
        0 => MembraneAction::Allow,
        1 => MembraneAction::FullValidate,
        2 => MembraneAction::Repair(decode_healing_action(heal_code, arg0, arg1)),
        3 => MembraneAction::Deny,
        _ => MembraneAction::Allow,
    }
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
    decision_cards: DecisionCardRingBuffer<CAP>,
    decision_card_journal_enabled: AtomicBool,
    decision_card_journal_errors: AtomicU64,
    decision_card_journal: Mutex<Option<DecisionCardJournal>>,
    monotonic_start: Instant,
    last_timestamp_ns: AtomicU64,
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
            decision_cards: DecisionCardRingBuffer::new(),
            decision_card_journal_enabled: AtomicBool::new(false),
            decision_card_journal_errors: AtomicU64::new(0),
            decision_card_journal: Mutex::new(None),
            monotonic_start: Instant::now(),
            last_timestamp_ns: AtomicU64::new(0),
            boot_nonce,
            streams: core::array::from_fn(|_| Mutex::new(EpochStreamState::new())),
        }
    }

    /// Enable crash-safe append/replay for decision cards.
    ///
    /// Returns the number of replayed cards loaded from the existing journal.
    pub fn enable_decision_card_journal<P: AsRef<Path>>(
        &self,
        path: P,
        flush_every: u64,
    ) -> io::Result<usize> {
        if self.decision_card_journal_enabled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                ErrorKind::AlreadyExists,
                "decision-card journal already enabled",
            ));
        }

        let (journal, replay_cards) = DecisionCardJournal::open(path.as_ref(), flush_every)?;
        let mut max_decision_id = 0u64;
        let mut max_timestamp = 0u64;
        for card in replay_cards.iter().copied() {
            max_decision_id = max_decision_id.max(card.decision_id);
            max_timestamp = max_timestamp.max(card.timestamp_mono_ns);
            self.decision_cards.publish(card.decision_id, card);
        }

        if max_decision_id > 0 {
            self.decision_cards
                .set_next_decision_id_floor(max_decision_id);
        }
        if max_timestamp > 0 {
            self.last_timestamp_ns
                .fetch_max(max_timestamp, Ordering::Relaxed);
        }

        *self.decision_card_journal.lock() = Some(journal);
        self.decision_card_journal_enabled
            .store(true, Ordering::Release);
        Ok(replay_cards.len())
    }

    #[doc(hidden)]
    pub fn flush_decision_card_journal_for_tests(&self) -> io::Result<()> {
        let mut guard = self.decision_card_journal.lock();
        if let Some(journal) = guard.as_mut() {
            journal.flush()?;
        }
        Ok(())
    }

    #[doc(hidden)]
    #[must_use]
    pub fn decision_card_journal_error_count_for_tests(&self) -> u64 {
        self.decision_card_journal_errors.load(Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[must_use]
    pub fn decision_card_journal_stats_for_tests(&self) -> Option<(u64, u64)> {
        let guard = self.decision_card_journal.lock();
        guard.as_ref().map(DecisionCardJournal::stats)
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

        let mut decision_with_seq = decision;
        decision_with_seq.evidence_seqno = seqno;
        let decision_id = self.decision_cards.allocate_decision_id();
        let card = DecisionCardV1 {
            decision_id,
            decision_type: classify_decision_type(mode, ctx, decision),
            thread_id: current_thread_id_u64(),
            symbol_id: decision.policy_id,
            timestamp_mono_ns: next_strict_timestamp_ns(
                self.monotonic_start,
                &self.last_timestamp_ns,
            ),
            epoch_id,
            evidence_seqno: seqno,
            context: ctx,
            decision: decision_with_seq,
            adverse,
            estimated_cost_ns,
            reasoning_flags: decision_reasoning_flags(mode, ctx, decision, adverse, loss_evidence),
            counterfactual_action: derive_counterfactual_action(mode, decision.action),
            loss_evidence,
        };
        self.decision_cards.publish(decision_id, card);
        if self.decision_card_journal_enabled.load(Ordering::Relaxed) {
            let mut guard = self.decision_card_journal.lock();
            if let Some(journal) = guard.as_mut()
                && journal.append(card).is_err()
            {
                self.decision_card_journal_errors
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        seqno
    }

    /// Snapshot a best-effort consistent view of the ring buffer for tooling/harness.
    #[must_use]
    pub fn snapshot_sorted(&self) -> Vec<EvidenceSymbolRecord> {
        self.ring.snapshot_sorted()
    }

    /// Snapshot decision cards sorted by `decision_id`.
    #[must_use]
    pub fn decision_cards_snapshot_sorted(&self) -> Vec<DecisionCardV1> {
        self.decision_cards.snapshot_sorted()
    }

    /// Query decision cards by type/time/thread/symbol predicates.
    #[must_use]
    pub fn query_decision_cards(&self, filter: DecisionCardFilter) -> Vec<DecisionCardV1> {
        self.decision_cards
            .snapshot_sorted()
            .into_iter()
            .filter(|card| filter.matches(card))
            .collect()
    }

    /// Export decision cards as deterministic JSON for harness/CI ingestion.
    #[must_use]
    pub fn export_decision_cards_json(&self) -> String {
        let cards = self.decision_cards.snapshot_sorted();
        let mut out = String::with_capacity(cards.len().saturating_mul(256).saturating_add(128));
        out.push_str("{\"schema\":\"decision_cards.v1\",\"count\":");
        let _ = write!(&mut out, "{}", cards.len());
        let _ = write!(
            &mut out,
            ",\"schema_version\":\"{}\",\"cards\":[",
            MEMBRANE_SCHEMA_VERSION
        );

        for (idx, card) in cards.iter().enumerate() {
            if idx > 0 {
                out.push(',');
            }
            let decision_id = DecisionId::from_raw(card.decision_id);
            let policy_id = PolicyId::from_raw(card.decision.policy_id);
            let trace_id = decision_id.scoped_trace_id("runtime_math::decision_card");
            let api_family = runtime_family_name(card.context.family);
            let symbol = runtime_decision_symbol(card.context.family);
            let decision_path = runtime_decision_path(card.decision.action);
            let _ = write!(
                &mut out,
                "{{\"trace_id\":\"{}\",\"decision_id\":{},\"decision_type\":{},\"thread_id\":{},\"symbol_id\":{},\"timestamp_mono_ns\":{},\"epoch_id\":{},\"evidence_seqno\":{},\"family\":{},\"mode\":{},\"api_family\":\"{}\",\"symbol\":\"{}\",\"decision_path\":\"{}\",\"profile\":{},\"action\":{},\"counterfactual_action\":{},\"policy_id\":{},\"risk_upper_bound_ppm\":{},\"adverse\":{},\"estimated_cost_ns\":{},\"reasoning_flags\":{},\"artifact_refs\":[\"crates/frankenlibc-membrane/src/runtime_math/evidence.rs\"],\"context\":{{\"addr_hint\":{},\"requested_bytes\":{},\"is_write\":{},\"contention_hint\":{},\"bloom_negative\":{}}}",
                trace_id.as_str(),
                decision_id.as_u64(),
                card.decision_type as u8,
                card.thread_id,
                card.symbol_id,
                card.timestamp_mono_ns,
                card.epoch_id,
                card.evidence_seqno,
                card.context.family as u8,
                decision_mode_code(card.reasoning_flags),
                api_family,
                symbol,
                decision_path,
                profile_code(card.decision.profile),
                action_code(card.decision.action),
                action_code(card.counterfactual_action),
                policy_id.as_u32(),
                card.decision.risk_upper_bound_ppm,
                card.adverse,
                card.estimated_cost_ns,
                card.reasoning_flags,
                card.context.addr_hint,
                card.context.requested_bytes,
                card.context.is_write,
                card.context.contention_hint,
                card.context.bloom_negative
            );
            match card.loss_evidence {
                Some(loss) => {
                    let _ = write!(
                        &mut out,
                        ",\"loss_evidence\":{{\"posterior_adverse_ppm\":{},\"selected_action\":{},\"competing_action\":{},\"selected_expected_loss_milli\":{},\"competing_expected_loss_milli\":{}}}}}",
                        loss.posterior_adverse_ppm,
                        loss.selected_action,
                        loss.competing_action,
                        loss.selected_expected_loss_milli,
                        loss.competing_expected_loss_milli
                    );
                }
                None => out.push_str(",\"loss_evidence\":null}"),
            }
        }

        out.push_str("]}");
        out
    }

    /// Bounded logging policy for runtime evidence exports.
    ///
    /// Decision cards are always kept in the fixed-size in-memory ring; crash-safe
    /// journaling is opt-in via `enable_decision_card_journal()`, so hot-path file
    /// I/O stays disabled by default.
    #[must_use]
    pub const fn runtime_evidence_logging_policy(&self) -> RuntimeEvidenceLogPolicy {
        RuntimeEvidenceLogPolicy::bounded_ring(CAP)
    }

    /// Export decision cards as v1 runtime evidence JSONL rows.
    ///
    /// This is a snapshot/export operation over the bounded ring, not a new
    /// unbounded hot-path sink. If callers pass no artifact refs, the exporter
    /// emits the evidence module path so every row remains traceable.
    #[must_use]
    pub fn export_runtime_evidence_jsonl(
        &self,
        bead_id: &str,
        scenario_id: &str,
        source_commit: &str,
        artifact_refs: &[&str],
    ) -> String {
        let cards = self.decision_cards.snapshot_sorted();
        let refs = if artifact_refs.is_empty() {
            RUNTIME_EVIDENCE_DEFAULT_ARTIFACT_REFS
        } else {
            artifact_refs
        };
        let policy = self.runtime_evidence_logging_policy();
        let timestamp = now_utc_iso_like();
        let mut out = String::with_capacity(cards.len().saturating_mul(640).saturating_add(128));

        for card in cards {
            let decision_id = DecisionId::from_raw(card.decision_id);
            let policy_id = PolicyId::from_raw(card.decision.policy_id);
            let trace_id = decision_id.scoped_trace_id("runtime_math::runtime_evidence");
            let runtime_mode = card_runtime_mode_name(&card);
            let validation_profile = profile_name(card.decision.profile);
            let decision_path = runtime_decision_path(card.decision.action);
            let action = action_name(card.decision.action);
            let healing_action = healing_action_json_for_decision(card.decision.action);
            let denied = matches!(card.decision.action, MembraneAction::Deny);
            let level = runtime_evidence_level(card.decision.action);
            let api_family = runtime_family_name(card.context.family);
            let symbol = runtime_decision_symbol(card.context.family);

            let _ = write!(
                &mut out,
                "{{\"schema\":\"{}\",\"schema_version\":\"{}\",\"timestamp\":\"{}\",\"trace_id\":\"{}\",\"bead_id\":\"{}\",\"scenario_id\":\"{}\",\"level\":\"{}\",\"event\":\"runtime_evidence\",\"controller_id\":\"runtime_math_kernel.v1\",\"decision_id\":{},\"policy_id\":{},\"evidence_seqno\":{},\"mode\":\"{}\",\"runtime_mode\":\"{}\",\"validation_profile\":\"{}\",\"decision_path\":\"{}\",\"decision_action\":\"{}\",\"healing_action\":{},\"denied\":{},\"latency_ns\":{},\"api_family\":\"{}\",\"symbol\":\"{}\",\"source_commit\":\"{}\",\"bounded_policy\":{{\"hot_path_io_enabled_by_default\":{},\"journal_enabled_by_default\":{},\"ring_capacity\":{},\"overflow_policy\":\"{}\"}},\"context\":{{\"addr_hint_redacted\":true,\"requested_bytes\":{},\"is_write\":{},\"contention_hint\":{},\"bloom_negative\":{}}},\"artifact_refs\":[",
                RUNTIME_EVIDENCE_JSONL_SCHEMA_V1,
                MEMBRANE_SCHEMA_VERSION,
                json_escape(&timestamp),
                trace_id.as_str(),
                json_escape(bead_id),
                json_escape(scenario_id),
                level,
                decision_id.as_u64(),
                policy_id.as_u32(),
                card.decision.evidence_seqno,
                runtime_mode,
                runtime_mode,
                validation_profile,
                decision_path,
                action,
                healing_action,
                denied,
                card.estimated_cost_ns,
                api_family,
                symbol,
                json_escape(source_commit),
                policy.hot_path_io_enabled_by_default,
                policy.journal_enabled_by_default,
                policy.bounded_ring_capacity,
                policy.overflow_policy,
                card.context.requested_bytes,
                card.context.is_write,
                card.context.contention_hint,
                card.context.bloom_negative,
            );
            for (idx, artifact) in refs.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let _ = write!(&mut out, "\"{}\"", json_escape(artifact));
            }
            out.push_str("]}\n");
        }

        out
    }

    /// Replay current ring/card snapshots against expected decisions.
    #[must_use]
    pub fn replay_runtime_evidence_v1(
        &self,
        bead_id: &str,
        expectations: &[RuntimeEvidenceReplayExpectation],
    ) -> RuntimeEvidenceReplayReport {
        let cards = self.decision_cards_snapshot_sorted();
        let records = self.snapshot_sorted();
        replay_runtime_evidence_v1(bead_id, &cards, &records, expectations)
    }
}

/// Replay decision cards and evidence records against expected decisions.
#[must_use]
pub fn replay_runtime_evidence_v1(
    bead_id: &str,
    cards: &[DecisionCardV1],
    records: &[EvidenceSymbolRecord],
    expectations: &[RuntimeEvidenceReplayExpectation],
) -> RuntimeEvidenceReplayReport {
    let cards_out_of_order = cards
        .windows(2)
        .any(|w| w[1].decision_id < w[0].decision_id);
    let records_out_of_order = records.windows(2).any(|w| w[1].seqno() < w[0].seqno());
    let rows = expectations
        .iter()
        .map(|expected| replay_one_expectation(expected, cards, records))
        .collect();
    RuntimeEvidenceReplayReport {
        bead_id: bead_id.to_string(),
        rows,
        cards_out_of_order,
        records_out_of_order,
    }
}

fn replay_one_expectation(
    expected: &RuntimeEvidenceReplayExpectation,
    cards: &[DecisionCardV1],
    records: &[EvidenceSymbolRecord],
) -> RuntimeEvidenceReplayRow {
    let card = cards
        .iter()
        .find(|card| card.evidence_seqno == expected.evidence_seqno);
    let record = records
        .iter()
        .find(|record| record.seqno() == expected.evidence_seqno);

    let trace_id = card.map_or_else(
        || {
            format!(
                "runtime_evidence_replay::missing::{}",
                expected.evidence_seqno
            )
        },
        |card| {
            DecisionId::from_raw(card.decision_id)
                .scoped_trace_id("runtime_math::decision_card")
                .as_str()
                .to_string()
        },
    );
    let fallback_family = card.map(|card| card.context.family);
    let mut api_family = fallback_family
        .map_or("unknown", runtime_family_name)
        .to_string();
    let mut symbol = fallback_family
        .map_or("runtime_math::unknown", runtime_decision_symbol)
        .to_string();
    let mut runtime_mode = expected
        .expected_runtime_mode
        .map_or("unknown", runtime_mode_name)
        .to_string();
    let mut decision_path = "missing".to_string();
    let mut healing_action = "None".to_string();
    let mut actual_decision = card.map(|card| action_name(card.decision.action).to_string());
    let mut actual_profile = card.map(|card| profile_name(card.decision.profile).to_string());
    let mut actual_policy_id = card.map(|card| card.decision.policy_id);
    let mut evidence_snapshot = None;

    let Some(card) = card else {
        return RuntimeEvidenceReplayRow {
            trace_id,
            replay_id: expected.replay_id.clone(),
            evidence_seqno: expected.evidence_seqno,
            api_family,
            symbol,
            runtime_mode,
            replacement_level: expected.replacement_level.clone(),
            decision_path,
            healing_action,
            expected_decision: action_name(expected.expected_decision).to_string(),
            actual_decision,
            expected_profile: expected
                .expected_profile
                .map(profile_name)
                .map(str::to_string),
            actual_profile,
            expected_policy_id: expected.expected_policy_id,
            actual_policy_id,
            evidence_snapshot,
            status: RuntimeEvidenceReplayStatus::MissingDecisionCard,
            failure_signature: Some(format!(
                "missing_decision_card:evidence_seqno={}",
                expected.evidence_seqno
            )),
            artifact_refs: expected.artifact_refs.clone(),
        };
    };

    let Some(record) = record else {
        return RuntimeEvidenceReplayRow {
            trace_id,
            replay_id: expected.replay_id.clone(),
            evidence_seqno: expected.evidence_seqno,
            api_family,
            symbol,
            runtime_mode,
            replacement_level: expected.replacement_level.clone(),
            decision_path,
            healing_action,
            expected_decision: action_name(expected.expected_decision).to_string(),
            actual_decision,
            expected_profile: expected
                .expected_profile
                .map(profile_name)
                .map(str::to_string),
            actual_profile,
            expected_policy_id: expected.expected_policy_id,
            actual_policy_id,
            evidence_snapshot,
            status: RuntimeEvidenceReplayStatus::MissingEvidenceRecord,
            failure_signature: Some(format!(
                "stale_ring_snapshot:evidence_seqno={}",
                expected.evidence_seqno
            )),
            artifact_refs: expected.artifact_refs.clone(),
        };
    };

    let mut status = RuntimeEvidenceReplayStatus::Passed;
    let mut failure_signature = None;

    if let Err(err) = record.validate_basic() {
        status = RuntimeEvidenceReplayStatus::InvalidEvidenceRecord;
        failure_signature = Some(format!("invalid_evidence_record:{err:?}"));
    }

    let decoded = if status == RuntimeEvidenceReplayStatus::Passed {
        match decode_decision_payload_v1(record.payload()) {
            Ok(decoded) => Some(decoded),
            Err(err) => {
                status = RuntimeEvidenceReplayStatus::InvalidDecisionPayload;
                failure_signature = Some(format!("invalid_decision_payload:{err:?}"));
                None
            }
        }
    } else {
        None
    };

    if let Some(decoded) = decoded {
        if let Some(family) = api_family_from_code(record.family()) {
            api_family = runtime_family_name(family).to_string();
            symbol = runtime_decision_symbol(family).to_string();
        }
        runtime_mode = runtime_mode_code_name(decoded.mode).to_string();
        let record_action = action_from_record_and_payload(record, decoded);
        decision_path = runtime_decision_path(record_action).to_string();
        healing_action = healing_action_name(decoded.healing_action).to_string();
        actual_decision = Some(action_name(record_action).to_string());
        actual_profile = Some(profile_code_name(record.profile()).to_string());
        actual_policy_id = Some(decoded.policy_id);
        evidence_snapshot = Some(RuntimeEvidenceSnapshot {
            epoch_id: record.epoch_id(),
            seqno: record.seqno(),
            decision_id: card.decision_id,
            payload_hash: record.payload_hash(),
            chain_hash: record.chain_hash(),
            addr_hint_redacted: decoded.addr_hint != 0,
            requested_bytes: decoded.requested_bytes,
            risk_upper_bound_ppm: decoded.risk_upper_bound_ppm,
            estimated_cost_ns: decoded.estimated_cost_ns,
        });

        if status == RuntimeEvidenceReplayStatus::Passed
            && (record_action != card.decision.action
                || record.profile() != profile_code(card.decision.profile)
                || record.family() != card.context.family as u8
                || decoded.policy_id != card.decision.policy_id
                || decoded.mode != decision_mode_code(card.reasoning_flags))
        {
            status = RuntimeEvidenceReplayStatus::MetadataMismatch;
            failure_signature = Some(format!(
                "metadata_mismatch:evidence_seqno={}",
                expected.evidence_seqno
            ));
        }

        if status == RuntimeEvidenceReplayStatus::Passed
            && (record_action != expected.expected_decision
                || expected
                    .expected_profile
                    .is_some_and(|profile| record.profile() != profile_code(profile))
                || expected
                    .expected_policy_id
                    .is_some_and(|policy_id| decoded.policy_id != policy_id)
                || expected
                    .expected_runtime_mode
                    .is_some_and(|mode| decoded.mode != mode_code(mode)))
        {
            status = if record_action != expected.expected_decision {
                RuntimeEvidenceReplayStatus::DecisionMismatch
            } else {
                RuntimeEvidenceReplayStatus::MetadataMismatch
            };
            failure_signature = Some(format!(
                "{}:evidence_seqno={}:expected={}:actual={}",
                replay_status_name(status),
                expected.evidence_seqno,
                action_name(expected.expected_decision),
                action_name(record_action)
            ));
        }
    }

    RuntimeEvidenceReplayRow {
        trace_id,
        replay_id: expected.replay_id.clone(),
        evidence_seqno: expected.evidence_seqno,
        api_family,
        symbol,
        runtime_mode,
        replacement_level: expected.replacement_level.clone(),
        decision_path,
        healing_action,
        expected_decision: action_name(expected.expected_decision).to_string(),
        actual_decision,
        expected_profile: expected
            .expected_profile
            .map(profile_name)
            .map(str::to_string),
        actual_profile,
        expected_policy_id: expected.expected_policy_id,
        actual_policy_id,
        evidence_snapshot,
        status,
        failure_signature,
        artifact_refs: expected.artifact_refs.clone(),
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

#[inline]
fn classify_decision_type(
    mode: SafetyLevel,
    ctx: RuntimeContext,
    decision: RuntimeDecision,
) -> DecisionType {
    match decision.action {
        MembraneAction::Repair(_) => DecisionType::Repair,
        MembraneAction::Deny => DecisionType::Escalation,
        MembraneAction::FullValidate if mode.heals_enabled() => DecisionType::PolicyOverride,
        MembraneAction::FullValidate => DecisionType::CertificateEvaluation,
        MembraneAction::Allow if ctx.bloom_negative => DecisionType::Quarantine,
        MembraneAction::Allow => DecisionType::CertificateEvaluation,
    }
}

#[inline]
fn derive_counterfactual_action(mode: SafetyLevel, action: MembraneAction) -> MembraneAction {
    match action {
        MembraneAction::Allow => MembraneAction::FullValidate,
        MembraneAction::FullValidate => MembraneAction::Allow,
        MembraneAction::Repair(_) => MembraneAction::Allow,
        MembraneAction::Deny if mode.heals_enabled() => {
            MembraneAction::Repair(HealingAction::ReturnSafeDefault)
        }
        MembraneAction::Deny => MembraneAction::Allow,
    }
}

#[inline]
fn decision_reasoning_flags(
    mode: SafetyLevel,
    ctx: RuntimeContext,
    decision: RuntimeDecision,
    adverse: bool,
    loss_evidence: Option<LossEvidenceV1>,
) -> u32 {
    let mut flags = 0u32;
    if ctx.is_write {
        flags |= 1 << 0;
    }
    if ctx.bloom_negative {
        flags |= 1 << 1;
    }
    if adverse {
        flags |= 1 << 2;
    }
    if matches!(mode, SafetyLevel::Hardened) {
        flags |= 1 << 3;
    }
    if decision.profile.requires_full() {
        flags |= 1 << 4;
    }
    if matches!(decision.action, MembraneAction::Repair(_)) {
        flags |= 1 << 5;
    }
    if matches!(decision.action, MembraneAction::Deny) {
        flags |= 1 << 6;
    }
    if loss_evidence.is_some() {
        flags |= 1 << 7;
    }
    flags
}

#[inline]
fn current_thread_id_u64() -> u64 {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish()
}

#[inline]
fn monotonic_elapsed_ns(start: Instant) -> u64 {
    let nanos = start.elapsed().as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

#[inline]
fn next_strict_timestamp_ns(start: Instant, last_timestamp_ns: &AtomicU64) -> u64 {
    let now_ns = monotonic_elapsed_ns(start);
    let mut observed = last_timestamp_ns.load(Ordering::Relaxed);
    loop {
        let candidate = if now_ns > observed {
            now_ns
        } else {
            observed.saturating_add(1)
        };
        match last_timestamp_ns.compare_exchange_weak(
            observed,
            candidate,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return candidate,
            Err(actual) => observed = actual,
        }
    }
}

#[inline]
const fn decision_mode_code(flags: u32) -> u8 {
    if (flags & (1 << 3)) != 0 { 1 } else { 0 }
}

#[inline]
fn runtime_family_name(family: ApiFamily) -> &'static str {
    match family {
        ApiFamily::PointerValidation => "pointer_validation",
        ApiFamily::Allocator => "allocator",
        ApiFamily::StringMemory => "string_memory",
        ApiFamily::Stdio => "stdio",
        ApiFamily::Threading => "threading",
        ApiFamily::Resolver => "resolver",
        ApiFamily::MathFenv => "math_fenv",
        ApiFamily::Loader => "loader",
        ApiFamily::Stdlib => "stdlib",
        ApiFamily::Ctype => "ctype",
        ApiFamily::Time => "time",
        ApiFamily::Signal => "signal",
        ApiFamily::IoFd => "io_fd",
        ApiFamily::Socket => "socket",
        ApiFamily::Locale => "locale",
        ApiFamily::Termios => "termios",
        ApiFamily::Inet => "inet",
        ApiFamily::Process => "process",
        ApiFamily::VirtualMemory => "virtual_memory",
        ApiFamily::Poll => "poll",
    }
}

#[inline]
fn runtime_decision_symbol(family: ApiFamily) -> &'static str {
    match family {
        ApiFamily::PointerValidation => "runtime_math::pointer_validation",
        ApiFamily::Allocator => "runtime_math::allocator",
        ApiFamily::StringMemory => "runtime_math::string_memory",
        ApiFamily::Stdio => "runtime_math::stdio",
        ApiFamily::Threading => "runtime_math::threading",
        ApiFamily::Resolver => "runtime_math::resolver",
        ApiFamily::MathFenv => "runtime_math::math_fenv",
        ApiFamily::Loader => "runtime_math::loader",
        ApiFamily::Stdlib => "runtime_math::stdlib",
        ApiFamily::Ctype => "runtime_math::ctype",
        ApiFamily::Time => "runtime_math::time",
        ApiFamily::Signal => "runtime_math::signal",
        ApiFamily::IoFd => "runtime_math::io_fd",
        ApiFamily::Socket => "runtime_math::socket",
        ApiFamily::Locale => "runtime_math::locale",
        ApiFamily::Termios => "runtime_math::termios",
        ApiFamily::Inet => "runtime_math::inet",
        ApiFamily::Process => "runtime_math::process",
        ApiFamily::VirtualMemory => "runtime_math::virtual_memory",
        ApiFamily::Poll => "runtime_math::poll",
    }
}

#[inline]
fn runtime_decision_path(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "mode->runtime_math_kernel->allow",
        MembraneAction::FullValidate => "mode->runtime_math_kernel->full_validate",
        MembraneAction::Repair(_) => "mode->runtime_math_kernel->repair",
        MembraneAction::Deny => "mode->runtime_math_kernel->deny",
    }
}

fn action_from_record_and_payload(
    record: &EvidenceSymbolRecord,
    payload: DecodedDecisionPayloadV1,
) -> MembraneAction {
    match record.action() {
        0 => MembraneAction::Allow,
        1 => MembraneAction::FullValidate,
        2 => MembraneAction::Repair(payload.healing_action),
        3 => MembraneAction::Deny,
        _ => MembraneAction::Allow,
    }
}

fn action_name(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "Allow",
        MembraneAction::FullValidate => "FullValidate",
        MembraneAction::Repair(_) => "Repair",
        MembraneAction::Deny => "Deny",
    }
}

fn healing_action_name(action: HealingAction) -> &'static str {
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

fn profile_name(profile: ValidationProfile) -> &'static str {
    match profile {
        ValidationProfile::Fast => "Fast",
        ValidationProfile::Full => "Full",
    }
}

fn profile_code_name(code: u8) -> &'static str {
    match code {
        0 => "Fast",
        1 => "Full",
        _ => "Unknown",
    }
}

fn runtime_mode_name(mode: SafetyLevel) -> &'static str {
    match mode {
        SafetyLevel::Strict => "strict",
        SafetyLevel::Hardened => "hardened",
        SafetyLevel::Off => "off",
    }
}

fn runtime_mode_code_name(code: u8) -> &'static str {
    match code {
        0 => "strict",
        1 => "hardened",
        2 => "off",
        _ => "unknown",
    }
}

fn card_runtime_mode_name(card: &DecisionCardV1) -> &'static str {
    runtime_mode_code_name(decision_mode_code(card.reasoning_flags))
}

fn runtime_evidence_level(action: MembraneAction) -> &'static str {
    match action {
        MembraneAction::Allow => "trace",
        MembraneAction::FullValidate => "info",
        MembraneAction::Repair(_) => "warn",
        MembraneAction::Deny => "error",
    }
}

fn healing_action_json_for_decision(action: MembraneAction) -> String {
    match action {
        MembraneAction::Repair(healing) => json_string_or_null(Some(healing_action_name(healing))),
        MembraneAction::Allow | MembraneAction::FullValidate | MembraneAction::Deny => {
            "null".to_string()
        }
    }
}

fn replay_status_name(status: RuntimeEvidenceReplayStatus) -> &'static str {
    match status {
        RuntimeEvidenceReplayStatus::Passed => "passed",
        RuntimeEvidenceReplayStatus::MissingDecisionCard => "missing_decision_card",
        RuntimeEvidenceReplayStatus::MissingEvidenceRecord => "missing_evidence_record",
        RuntimeEvidenceReplayStatus::InvalidEvidenceRecord => "invalid_evidence_record",
        RuntimeEvidenceReplayStatus::InvalidDecisionPayload => "invalid_decision_payload",
        RuntimeEvidenceReplayStatus::DecisionMismatch => "decision_mismatch",
        RuntimeEvidenceReplayStatus::MetadataMismatch => "metadata_mismatch",
    }
}

fn json_string_or_null(value: Option<&str>) -> String {
    value.map_or_else(
        || "null".to_string(),
        |value| format!("\"{}\"", json_escape(value)),
    )
}

fn json_u32_or_null(value: Option<u32>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(&mut out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

fn required_field<'a>(
    row: &'a Value,
    field: &'static str,
) -> Result<&'a Value, RuntimeEvidenceRowValidationError> {
    row.get(field)
        .ok_or(RuntimeEvidenceRowValidationError::MissingRequiredField(
            field,
        ))
}

fn expect_non_empty_string<'a>(
    row: &'a Value,
    field: &'static str,
) -> Result<&'a str, RuntimeEvidenceRowValidationError> {
    let value = required_field(row, field)?
        .as_str()
        .ok_or(RuntimeEvidenceRowValidationError::WrongType(field))?;
    if value.is_empty() {
        return Err(RuntimeEvidenceRowValidationError::EmptyString(field));
    }
    Ok(value)
}

fn expect_exact_string(
    row: &Value,
    field: &'static str,
    expected: &'static str,
) -> Result<(), RuntimeEvidenceRowValidationError> {
    let value = expect_non_empty_string(row, field)?;
    if value != expected {
        return Err(RuntimeEvidenceRowValidationError::UnexpectedValue(field));
    }
    Ok(())
}

fn expect_one_of(
    row: &Value,
    field: &'static str,
    allowed: &[&'static str],
) -> Result<(), RuntimeEvidenceRowValidationError> {
    let value = expect_non_empty_string(row, field)?;
    if !allowed.contains(&value) {
        return Err(RuntimeEvidenceRowValidationError::UnexpectedValue(field));
    }
    Ok(())
}

fn expect_bool(row: &Value, field: &'static str) -> Result<(), RuntimeEvidenceRowValidationError> {
    required_field(row, field)?
        .as_bool()
        .ok_or(RuntimeEvidenceRowValidationError::WrongType(field))
        .map(|_| ())
}

fn expect_u64(row: &Value, field: &'static str) -> Result<(), RuntimeEvidenceRowValidationError> {
    required_field(row, field)?
        .as_u64()
        .ok_or(RuntimeEvidenceRowValidationError::WrongType(field))
        .map(|_| ())
}

fn expect_context(row: &Value) -> Result<(), RuntimeEvidenceRowValidationError> {
    let context = required_field(row, "context")?
        .as_object()
        .ok_or(RuntimeEvidenceRowValidationError::WrongType("context"))?;
    for field in [
        "addr_hint_redacted",
        "requested_bytes",
        "is_write",
        "contention_hint",
        "bloom_negative",
    ] {
        if !context.contains_key(field) {
            return Err(RuntimeEvidenceRowValidationError::MissingRequiredField(
                "context",
            ));
        }
    }
    Ok(())
}

fn expect_healing_action(row: &Value) -> Result<(), RuntimeEvidenceRowValidationError> {
    let value = required_field(row, "healing_action")?;
    if value.is_null() {
        return Ok(());
    }
    let action = value
        .as_str()
        .ok_or(RuntimeEvidenceRowValidationError::WrongType(
            "healing_action",
        ))?;
    if action.is_empty() {
        return Err(RuntimeEvidenceRowValidationError::EmptyString(
            "healing_action",
        ));
    }
    Ok(())
}

fn expect_artifact_refs(row: &Value) -> Result<(), RuntimeEvidenceRowValidationError> {
    let refs = required_field(row, "artifact_refs")?.as_array().ok_or(
        RuntimeEvidenceRowValidationError::WrongType("artifact_refs"),
    )?;
    if refs.is_empty() {
        return Err(RuntimeEvidenceRowValidationError::EmptyArtifactRefs);
    }
    for artifact in refs {
        let value = artifact
            .as_str()
            .ok_or(RuntimeEvidenceRowValidationError::WrongType(
                "artifact_refs",
            ))?;
        if value.is_empty() {
            return Err(RuntimeEvidenceRowValidationError::EmptyString(
                "artifact_refs",
            ));
        }
    }
    Ok(())
}

/// Overwrite-on-full decision-card ring buffer.
pub struct DecisionCardRingBuffer<const CAP: usize> {
    next_decision_id: AtomicU64,
    slots: Vec<DecisionCardSlot>,
}

struct DecisionCardSlot {
    published_decision_id: AtomicU64,
    card: Mutex<DecisionCardV1>,
}

impl DecisionCardSlot {
    fn new() -> Self {
        Self {
            published_decision_id: AtomicU64::new(0),
            card: Mutex::new(DecisionCardV1::zeroed()),
        }
    }
}

impl<const CAP: usize> Default for DecisionCardRingBuffer<CAP> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAP: usize> DecisionCardRingBuffer<CAP> {
    #[must_use]
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(CAP);
        for _ in 0..CAP {
            slots.push(DecisionCardSlot::new());
        }
        Self {
            next_decision_id: AtomicU64::new(0),
            slots,
        }
    }

    pub fn allocate_decision_id(&self) -> u64 {
        self.next_decision_id
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1)
    }

    pub fn publish(&self, decision_id: u64, card: DecisionCardV1) {
        let idx = (decision_id as usize) % CAP;
        let slot = &self.slots[idx];
        debug_assert_eq!(card.decision_id, decision_id);
        *slot.card.lock() = card;
        slot.published_decision_id
            .store(decision_id, Ordering::Release);
    }

    pub fn set_next_decision_id_floor(&self, floor: u64) {
        let mut observed = self.next_decision_id.load(Ordering::Relaxed);
        while observed < floor {
            match self.next_decision_id.compare_exchange_weak(
                observed,
                floor,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => observed = actual,
            }
        }
    }

    #[must_use]
    pub fn snapshot_sorted(&self) -> Vec<DecisionCardV1> {
        let mut out = Vec::new();
        for slot in &self.slots {
            let d1 = slot.published_decision_id.load(Ordering::Acquire);
            if d1 == 0 {
                continue;
            }
            let card = *slot.card.lock();
            let d2 = slot.published_decision_id.load(Ordering::Acquire);
            if d1 == d2 && card.decision_id == d1 {
                out.push(card);
            }
        }
        out.sort_by_key(|card| card.decision_id);
        out
    }
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
    slots: Vec<EvidenceSlot>,
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
        let mut slots = Vec::with_capacity(CAP);
        for _ in 0..CAP {
            slots.push(EvidenceSlot::new());
        }
        Self {
            next_seqno: AtomicU64::new(0),
            slots,
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
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
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
    use serde_json::Value;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn unique_temp_file(name: &str) -> PathBuf {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "frankenlibc_{name}_{}_{}.journal",
            std::process::id(),
            ts
        ))
    }

    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(default)
    }

    fn average_ns_per_op(elapsed: Duration, operations: u64) -> u64 {
        if operations == 0 {
            return 0;
        }
        let total = elapsed.as_nanos();
        let avg = total / u128::from(operations);
        u64::try_from(avg).unwrap_or(u64::MAX)
    }

    fn replay_expectation(
        replay_id: &str,
        evidence_seqno: u64,
        expected_decision: MembraneAction,
        expected_profile: ValidationProfile,
        expected_policy_id: u32,
        expected_runtime_mode: SafetyLevel,
    ) -> RuntimeEvidenceReplayExpectation {
        RuntimeEvidenceReplayExpectation {
            replay_id: replay_id.to_string(),
            evidence_seqno,
            expected_decision,
            expected_profile: Some(expected_profile),
            expected_policy_id: Some(expected_policy_id),
            expected_runtime_mode: Some(expected_runtime_mode),
            replacement_level: "L0".to_string(),
            artifact_refs: vec![
                "crates/frankenlibc-membrane/src/runtime_math/evidence.rs".to_string(),
            ],
        }
    }

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

    #[test]
    fn decision_card_filter_matches_expected_fields() {
        let card = DecisionCardV1 {
            decision_id: 17,
            decision_type: DecisionType::Repair,
            thread_id: 99,
            symbol_id: 1234,
            timestamp_mono_ns: 50_000,
            epoch_id: 1,
            evidence_seqno: 9,
            context: RuntimeContext::pointer_validation(0xABCD, true),
            decision: RuntimeDecision {
                profile: ValidationProfile::Full,
                action: MembraneAction::Repair(HealingAction::IgnoreDoubleFree),
                policy_id: 1234,
                risk_upper_bound_ppm: 900_000,
                evidence_seqno: 9,
            },
            adverse: true,
            estimated_cost_ns: 12,
            reasoning_flags: 0,
            counterfactual_action: MembraneAction::Allow,
            loss_evidence: None,
        };

        let ok = DecisionCardFilter {
            decision_type: Some(DecisionType::Repair),
            min_timestamp_mono_ns: Some(40_000),
            max_timestamp_mono_ns: Some(60_000),
            thread_id: Some(99),
            symbol_id: Some(1234),
        };
        assert!(ok.matches(&card));

        let bad_thread = DecisionCardFilter {
            thread_id: Some(7),
            ..DecisionCardFilter::any()
        };
        assert!(!bad_thread.matches(&card));

        let bad_symbol = DecisionCardFilter {
            symbol_id: Some(55),
            ..DecisionCardFilter::any()
        };
        assert!(!bad_symbol.matches(&card));
    }

    #[test]
    fn systematic_log_records_queryable_decision_cards() {
        let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0xBEEF);
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0x1000,
            requested_bytes: 64,
            is_write: true,
            contention_hint: 2,
            bloom_negative: false,
        };

        let allow = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 41,
            risk_upper_bound_ppm: 120,
            evidence_seqno: 0,
        };
        let seq_allow =
            log.record_decision(SafetyLevel::Strict, ctx, allow, 9, false, None, 0, None);

        let repair = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::UpgradeToSafeVariant),
            policy_id: 42,
            risk_upper_bound_ppm: 900_000,
            evidence_seqno: 0,
        };
        let seq_repair = log.record_decision(
            SafetyLevel::Hardened,
            ctx,
            repair,
            11,
            true,
            Some(LossEvidenceV1 {
                posterior_adverse_ppm: 700_000,
                selected_action: 2,
                competing_action: 1,
                selected_expected_loss_milli: 30,
                competing_expected_loss_milli: 70,
            }),
            0,
            None,
        );

        assert!(seq_allow >= 1);
        assert!(seq_repair > seq_allow);

        let cards = log.decision_cards_snapshot_sorted();
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].decision_id, 1);
        assert_eq!(cards[1].decision_id, 2);
        assert!(cards[1].timestamp_mono_ns >= cards[0].timestamp_mono_ns);
        assert_eq!(cards[0].evidence_seqno, seq_allow);
        assert_eq!(cards[1].evidence_seqno, seq_repair);

        let repairs = log.query_decision_cards(DecisionCardFilter {
            decision_type: Some(DecisionType::Repair),
            ..DecisionCardFilter::any()
        });
        assert_eq!(repairs.len(), 1);
        assert_eq!(repairs[0].symbol_id, 42);
        assert!(repairs[0].loss_evidence.is_some());

        let symbol_41 = log.query_decision_cards(DecisionCardFilter {
            symbol_id: Some(41),
            ..DecisionCardFilter::any()
        });
        assert_eq!(symbol_41.len(), 1);
        assert_eq!(
            symbol_41[0].decision_type,
            DecisionType::CertificateEvaluation
        );

        let thread_cards = log.query_decision_cards(DecisionCardFilter {
            thread_id: Some(current_thread_id_u64()),
            ..DecisionCardFilter::any()
        });
        assert_eq!(thread_cards.len(), 2);

        let export = log.export_decision_cards_json();
        assert!(export.contains("\"schema\":\"decision_cards.v1\""));
        assert!(export.contains("\"count\":2"));
        assert!(export.contains("\"decision_id\":1"));
        assert!(export.contains("\"decision_id\":2"));
    }

    #[test]
    fn decision_card_timestamps_are_strictly_monotone() {
        let log: SystematicEvidenceLog<64> = SystematicEvidenceLog::new(0xCAFE_BABE);
        let ctx = RuntimeContext::pointer_validation(0x1000, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 7,
            risk_upper_bound_ppm: 10,
            evidence_seqno: 0,
        };

        for _ in 0..32 {
            let _ =
                log.record_decision(SafetyLevel::Strict, ctx, decision, 0, false, None, 0, None);
        }

        let cards = log.decision_cards_snapshot_sorted();
        assert_eq!(cards.len(), 32);
        for pair in cards.windows(2) {
            assert!(
                pair[1].timestamp_mono_ns > pair[0].timestamp_mono_ns,
                "timestamps must be strictly increasing: {} -> {}",
                pair[0].timestamp_mono_ns,
                pair[1].timestamp_mono_ns
            );
        }
    }

    #[test]
    fn decision_card_query_supports_exact_time_window() {
        let log: SystematicEvidenceLog<16> = SystematicEvidenceLog::new(0x1234_5678);
        let ctx = RuntimeContext::pointer_validation(0x2000, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 88,
            risk_upper_bound_ppm: 100,
            evidence_seqno: 0,
        };

        for _ in 0..5 {
            let _ =
                log.record_decision(SafetyLevel::Strict, ctx, decision, 1, false, None, 0, None);
        }

        let cards = log.decision_cards_snapshot_sorted();
        assert_eq!(cards.len(), 5);
        let target_ts = cards[2].timestamp_mono_ns;
        let filtered = log.query_decision_cards(DecisionCardFilter {
            min_timestamp_mono_ns: Some(target_ts),
            max_timestamp_mono_ns: Some(target_ts),
            ..DecisionCardFilter::any()
        });
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].timestamp_mono_ns, target_ts);
    }

    #[test]
    fn decision_card_export_is_valid_json() {
        let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0x1020_3040);
        let ctx = RuntimeContext::pointer_validation(0x3000, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 5,
            risk_upper_bound_ppm: 50,
            evidence_seqno: 0,
        };
        let _ = log.record_decision(SafetyLevel::Strict, ctx, decision, 3, false, None, 0, None);
        let _ = log.record_decision(SafetyLevel::Strict, ctx, decision, 3, false, None, 0, None);

        let export = log.export_decision_cards_json();
        let parsed: Value = serde_json::from_str(&export).expect("export must be parseable JSON");
        assert_eq!(
            parsed["schema"].as_str(),
            Some("decision_cards.v1"),
            "schema field mismatch"
        );
        assert_eq!(parsed["schema_version"].as_str(), Some("1.0"));
        assert_eq!(parsed["count"].as_u64(), Some(2));
        assert!(parsed["cards"].is_array());
        assert_eq!(parsed["cards"].as_array().unwrap().len(), 2);
        for card in parsed["cards"].as_array().expect("cards must be array") {
            assert!(
                card["trace_id"]
                    .as_str()
                    .is_some_and(|trace_id| trace_id.starts_with("runtime_math::decision_card::"))
            );
            assert!(card["mode"].as_u64().is_some());
            assert!(
                card["api_family"]
                    .as_str()
                    .is_some_and(|value| !value.is_empty())
            );
            assert!(
                card["symbol"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("runtime_math::"))
            );
            assert!(
                card["decision_path"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("mode->runtime_math_kernel->"))
            );
            assert_eq!(
                card["artifact_refs"][0].as_str(),
                Some("crates/frankenlibc-membrane/src/runtime_math/evidence.rs")
            );
            assert!(card["decision_id"].as_u64().is_some_and(|id| id > 0));
            assert!(card["policy_id"].as_u64().is_some_and(|id| id > 0));
        }
    }

    #[test]
    fn runtime_evidence_logging_policy_is_hot_path_off_and_bounded() {
        let log: SystematicEvidenceLog<32> = SystematicEvidenceLog::new(0xA11C_EE55);
        let policy = log.runtime_evidence_logging_policy();

        assert!(!policy.hot_path_io_enabled_by_default);
        assert!(!policy.journal_enabled_by_default);
        assert_eq!(policy.bounded_ring_capacity, 32);
        assert_eq!(policy.overflow_policy, "overwrite_oldest_ring_slot");
    }

    #[test]
    fn runtime_evidence_jsonl_export_covers_required_schema_fields() {
        let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0xE71D_EACE);
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0xDEAD_BEEF,
            requested_bytes: 96,
            is_write: true,
            contention_hint: 4,
            bloom_negative: false,
        };
        let allow = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 11,
            risk_upper_bound_ppm: 10,
            evidence_seqno: 0,
        };
        let repair = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::ReturnSafeDefault),
            policy_id: 12,
            risk_upper_bound_ppm: 900_000,
            evidence_seqno: 0,
        };
        let deny = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Deny,
            policy_id: 13,
            risk_upper_bound_ppm: 1_000_000,
            evidence_seqno: 0,
        };

        let _ = log.record_decision(SafetyLevel::Strict, ctx, allow, 8, false, None, 0, None);
        let _ = log.record_decision(SafetyLevel::Hardened, ctx, repair, 13, true, None, 0, None);
        let _ = log.record_decision(SafetyLevel::Hardened, ctx, deny, 21, true, None, 0, None);

        let jsonl = log.export_runtime_evidence_jsonl(
            "bd-b92jd.4.1",
            "schema-smoke",
            "0123456789abcdef0123456789abcdef01234567",
            &["tests/conformance/log_schema.json"],
        );
        let rows = jsonl.lines().collect::<Vec<_>>();
        assert_eq!(rows.len(), 3);

        let mut saw_repair = false;
        let mut saw_deny = false;
        for line in rows {
            let parsed: Value = serde_json::from_str(line).expect("runtime evidence row JSON");
            validate_runtime_evidence_row_v1(&parsed).expect("row must satisfy v1 schema");
            assert_eq!(
                parsed["schema"].as_str(),
                Some(RUNTIME_EVIDENCE_JSONL_SCHEMA_V1)
            );
            assert_eq!(parsed["bead_id"].as_str(), Some("bd-b92jd.4.1"));
            assert_eq!(
                parsed["source_commit"].as_str(),
                Some("0123456789abcdef0123456789abcdef01234567")
            );
            assert_eq!(
                parsed["artifact_refs"][0].as_str(),
                Some("tests/conformance/log_schema.json")
            );
            assert_eq!(
                parsed["bounded_policy"]["hot_path_io_enabled_by_default"].as_bool(),
                Some(false)
            );
            assert_eq!(parsed["bounded_policy"]["ring_capacity"].as_u64(), Some(8));
            assert_eq!(
                parsed["context"]["addr_hint_redacted"].as_bool(),
                Some(true)
            );
            assert!(parsed["context"].get("addr_hint").is_none());

            saw_repair |= parsed["healing_action"].as_str() == Some("ReturnSafeDefault");
            saw_deny |= parsed["denied"].as_bool() == Some(true);
        }

        assert!(saw_repair, "repair row must name the healing action");
        assert!(saw_deny, "deny row must set denied=true");
    }

    #[test]
    fn runtime_evidence_row_validator_fails_closed_on_missing_required_fields() {
        let log: SystematicEvidenceLog<4> = SystematicEvidenceLog::new(0xFA11_C105);
        let ctx = RuntimeContext::pointer_validation(0x3000, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 5,
            risk_upper_bound_ppm: 50,
            evidence_seqno: 0,
        };
        let _ = log.record_decision(SafetyLevel::Strict, ctx, decision, 3, false, None, 0, None);
        let first_line = log
            .export_runtime_evidence_jsonl(
                "bd-b92jd.4.1",
                "validator",
                "0123456789abcdef0123456789abcdef01234567",
                &[],
            )
            .lines()
            .next()
            .expect("runtime evidence JSONL row")
            .to_string();
        let row: Value = serde_json::from_str(&first_line).expect("runtime evidence row JSON");
        validate_runtime_evidence_row_v1(&row).expect("baseline row is valid");

        let mut missing_source = row.clone();
        missing_source
            .as_object_mut()
            .expect("row object")
            .remove("source_commit");
        assert_eq!(
            validate_runtime_evidence_row_v1(&missing_source),
            Err(RuntimeEvidenceRowValidationError::MissingRequiredField(
                "source_commit"
            ))
        );

        let mut missing_healing_action = row.clone();
        missing_healing_action
            .as_object_mut()
            .expect("row object")
            .remove("healing_action");
        assert_eq!(
            validate_runtime_evidence_row_v1(&missing_healing_action),
            Err(RuntimeEvidenceRowValidationError::MissingRequiredField(
                "healing_action"
            ))
        );

        let mut empty_artifacts = row;
        empty_artifacts["artifact_refs"] = Value::Array(Vec::new());
        assert_eq!(
            validate_runtime_evidence_row_v1(&empty_artifacts),
            Err(RuntimeEvidenceRowValidationError::EmptyArtifactRefs)
        );
    }

    #[test]
    fn decision_payload_decoder_roundtrips_loss_and_rejects_bad_versions() {
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0xABCD,
            requested_bytes: 128,
            is_write: true,
            contention_hint: 7,
            bloom_negative: true,
        };
        let decision = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::ClampSize {
                requested: 128,
                clamped: 64,
            }),
            policy_id: 77,
            risk_upper_bound_ppm: 700_000,
            evidence_seqno: 0,
        };
        let loss = LossEvidenceV1 {
            posterior_adverse_ppm: 2_000_000,
            selected_action: 2,
            competing_action: 3,
            selected_expected_loss_milli: 20,
            competing_expected_loss_milli: 90,
        };

        let payload =
            encode_decision_payload_v1(SafetyLevel::Hardened, ctx, decision, 55, true, Some(loss));
        let decoded = decode_decision_payload_v1(&payload).expect("decode decision payload");
        assert_eq!(decoded.mode, 1);
        assert_eq!(decoded.addr_hint, ctx.addr_hint);
        assert_eq!(decoded.requested_bytes, ctx.requested_bytes);
        assert!(decoded.is_write);
        assert!(decoded.bloom_negative);
        assert_eq!(decoded.policy_id, decision.policy_id);
        assert_eq!(
            decoded.healing_action,
            HealingAction::ClampSize {
                requested: 128,
                clamped: 64
            }
        );
        assert_eq!(
            decoded.loss_evidence.unwrap().posterior_adverse_ppm,
            1_000_000
        );

        let mut bad_magic = payload;
        bad_magic[0] = b'X';
        assert_eq!(
            decode_decision_payload_v1(&bad_magic),
            Err(DecisionPayloadError::BadMagic)
        );

        let mut bad_loss_version = payload;
        bad_loss_version[43] = 99;
        assert_eq!(
            decode_decision_payload_v1(&bad_loss_version),
            Err(DecisionPayloadError::UnsupportedLossBlockVersion(99))
        );
    }

    #[test]
    fn runtime_evidence_replay_gate_passes_and_redacts_pointer_hints() {
        let log: SystematicEvidenceLog<16> = SystematicEvidenceLog::new(0xBADA_5510);
        let ctx = RuntimeContext {
            family: ApiFamily::Allocator,
            addr_hint: 0xDEAD_BEEF,
            requested_bytes: 96,
            is_write: true,
            contention_hint: 4,
            bloom_negative: false,
        };
        let allow = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 101,
            risk_upper_bound_ppm: 10,
            evidence_seqno: 0,
        };
        let repair = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::ReturnSafeDefault),
            policy_id: 102,
            risk_upper_bound_ppm: 900_000,
            evidence_seqno: 0,
        };
        let deny = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Deny,
            policy_id: 103,
            risk_upper_bound_ppm: 1_000_000,
            evidence_seqno: 0,
        };

        let seq_allow =
            log.record_decision(SafetyLevel::Strict, ctx, allow, 8, false, None, 0, None);
        let seq_repair =
            log.record_decision(SafetyLevel::Hardened, ctx, repair, 13, true, None, 0, None);
        let seq_deny =
            log.record_decision(SafetyLevel::Hardened, ctx, deny, 21, true, None, 0, None);

        let expectations = vec![
            replay_expectation(
                "allow-path",
                seq_allow,
                MembraneAction::Allow,
                ValidationProfile::Fast,
                101,
                SafetyLevel::Strict,
            ),
            replay_expectation(
                "repair-path",
                seq_repair,
                MembraneAction::Repair(HealingAction::ReturnSafeDefault),
                ValidationProfile::Full,
                102,
                SafetyLevel::Hardened,
            ),
            replay_expectation(
                "deny-path",
                seq_deny,
                MembraneAction::Deny,
                ValidationProfile::Full,
                103,
                SafetyLevel::Hardened,
            ),
        ];

        let report = log.replay_runtime_evidence_v1("bd-bp8fl.9.4", &expectations);
        assert!(report.passed(), "{report:?}");
        assert_eq!(report.rows.len(), 3);
        assert!(
            report
                .rows
                .iter()
                .all(|row| row.status == RuntimeEvidenceReplayStatus::Passed)
        );

        let json = report.to_json();
        let parsed: Value = serde_json::from_str(&json).expect("replay report JSON");
        assert_eq!(
            parsed["schema"].as_str(),
            Some("runtime_evidence_replay.v1")
        );
        assert_eq!(parsed["bead_id"].as_str(), Some("bd-bp8fl.9.4"));
        assert_eq!(parsed["passed"].as_bool(), Some(true));
        assert!(!json.contains("3735928559"));
        assert!(!json.contains("DEAD_BEEF"));
        assert_eq!(
            parsed["rows"][0]["evidence_snapshot"]["addr_hint_redacted"].as_bool(),
            Some(true)
        );
    }

    #[test]
    fn runtime_evidence_replay_gate_reports_missing_stale_and_mismatch_cases() {
        let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0xF00D);
        let ctx = RuntimeContext::pointer_validation(0x1234, false);
        let allow = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 201,
            risk_upper_bound_ppm: 10,
            evidence_seqno: 0,
        };
        let seq = log.record_decision(SafetyLevel::Strict, ctx, allow, 5, false, None, 0, None);
        let cards = log.decision_cards_snapshot_sorted();
        let records = log.snapshot_sorted();

        let stale = replay_runtime_evidence_v1(
            "bd-bp8fl.9.4",
            &cards,
            &[],
            &[replay_expectation(
                "stale-ring",
                seq,
                MembraneAction::Allow,
                ValidationProfile::Fast,
                201,
                SafetyLevel::Strict,
            )],
        );
        assert_eq!(
            stale.rows[0].status,
            RuntimeEvidenceReplayStatus::MissingEvidenceRecord
        );
        assert_eq!(
            stale.rows[0].failure_signature.as_deref(),
            Some("stale_ring_snapshot:evidence_seqno=1")
        );

        let missing = replay_runtime_evidence_v1(
            "bd-bp8fl.9.4",
            &cards,
            &records,
            &[replay_expectation(
                "missing-card",
                seq + 99,
                MembraneAction::Allow,
                ValidationProfile::Fast,
                201,
                SafetyLevel::Strict,
            )],
        );
        assert_eq!(
            missing.rows[0].status,
            RuntimeEvidenceReplayStatus::MissingDecisionCard
        );

        let mismatch = replay_runtime_evidence_v1(
            "bd-bp8fl.9.4",
            &cards,
            &records,
            &[replay_expectation(
                "decision-mismatch",
                seq,
                MembraneAction::Deny,
                ValidationProfile::Fast,
                201,
                SafetyLevel::Strict,
            )],
        );
        assert_eq!(
            mismatch.rows[0].status,
            RuntimeEvidenceReplayStatus::DecisionMismatch
        );
        assert!(
            mismatch.rows[0]
                .failure_signature
                .as_deref()
                .is_some_and(|sig| sig.starts_with("decision_mismatch:evidence_seqno=1"))
        );
    }

    #[test]
    fn runtime_evidence_replay_gate_flags_out_of_order_snapshots() {
        let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0xCAFE);
        let ctx = RuntimeContext::pointer_validation(0x2222, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 301,
            risk_upper_bound_ppm: 11,
            evidence_seqno: 0,
        };
        let seq1 = log.record_decision(SafetyLevel::Strict, ctx, decision, 1, false, None, 0, None);
        let seq2 = log.record_decision(SafetyLevel::Strict, ctx, decision, 1, false, None, 0, None);
        let mut cards = log.decision_cards_snapshot_sorted();
        let mut records = log.snapshot_sorted();
        cards.reverse();
        records.reverse();

        let report = replay_runtime_evidence_v1(
            "bd-bp8fl.9.4",
            &cards,
            &records,
            &[
                replay_expectation(
                    "first",
                    seq1,
                    MembraneAction::Allow,
                    ValidationProfile::Fast,
                    301,
                    SafetyLevel::Strict,
                ),
                replay_expectation(
                    "second",
                    seq2,
                    MembraneAction::Allow,
                    ValidationProfile::Fast,
                    301,
                    SafetyLevel::Strict,
                ),
            ],
        );
        assert!(report.cards_out_of_order);
        assert!(report.records_out_of_order);
        assert!(!report.passed());
        assert_eq!(report.rows.len(), 2);
    }

    #[test]
    fn decision_card_ring_sustains_large_append_volume() {
        const N: u64 = 1_000_000;
        let log: SystematicEvidenceLog<512> = SystematicEvidenceLog::new(0xAA55_AA55);
        let ctx = RuntimeContext::pointer_validation(0x4000, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 99,
            risk_upper_bound_ppm: 0,
            evidence_seqno: 0,
        };

        for _ in 0..N {
            let _ =
                log.record_decision(SafetyLevel::Strict, ctx, decision, 0, false, None, 0, None);
        }

        let cards = log.decision_cards_snapshot_sorted();
        assert!(!cards.is_empty());
        assert!(cards.len() <= 512);
        assert_eq!(cards.last().unwrap().decision_id, N);
    }

    #[test]
    fn decision_card_query_latency_smoke_budget() {
        const CAP: usize = 256;
        let n = env_u64("FRANKENLIBC_EVIDENCE_QUERY_SAMPLE_SIZE", 200_000).max(10_000);
        let budget_ns = env_u64("FRANKENLIBC_EVIDENCE_QUERY_BUDGET_NS", 5_000_000).max(100_000);

        let log: SystematicEvidenceLog<CAP> = SystematicEvidenceLog::new(0xFACE_0123);
        let ctx = RuntimeContext::pointer_validation(0x5151, true);
        let allow = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 20,
            risk_upper_bound_ppm: 20,
            evidence_seqno: 0,
        };
        let repair = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::ClampSize {
                requested: 96,
                clamped: 64,
            }),
            policy_id: 21,
            risk_upper_bound_ppm: 800_000,
            evidence_seqno: 0,
        };

        for i in 0..n {
            let decision = if i % 5 == 0 { repair } else { allow };
            let _ = log.record_decision(
                SafetyLevel::Hardened,
                ctx,
                decision,
                11,
                true,
                None,
                0,
                None,
            );
        }

        let start = Instant::now();
        let repairs = log.query_decision_cards(DecisionCardFilter {
            decision_type: Some(DecisionType::Repair),
            ..DecisionCardFilter::any()
        });
        let elapsed_ns = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);

        let expected = log
            .decision_cards_snapshot_sorted()
            .into_iter()
            .filter(|card| card.decision_type == DecisionType::Repair)
            .count();
        assert_eq!(repairs.len(), expected);
        assert!(
            elapsed_ns <= budget_ns,
            "query_decision_cards latency {}ns exceeded budget {}ns (set FRANKENLIBC_EVIDENCE_QUERY_BUDGET_NS for slower hosts)",
            elapsed_ns,
            budget_ns
        );
        eprintln!(
            "decision_card_query_latency_smoke_budget: sample={}, visible={}, repairs={}, elapsed_ns={}, budget_ns={}",
            n,
            CAP,
            repairs.len(),
            elapsed_ns,
            budget_ns
        );
    }

    #[test]
    fn decision_card_journal_append_overhead_smoke_budget() {
        const CAP: usize = 512;
        let n = env_u64("FRANKENLIBC_EVIDENCE_APPEND_SAMPLE_SIZE", 100_000).max(20_000);
        let flush_every = env_u64("FRANKENLIBC_EVIDENCE_JOURNAL_FLUSH_EVERY", 4096).max(1);
        let budget_ns =
            env_u64("FRANKENLIBC_EVIDENCE_JOURNAL_OVERHEAD_BUDGET_NS", 200_000).max(1_000);

        let ctx = RuntimeContext::pointer_validation(0x6161, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 22,
            risk_upper_bound_ppm: 20,
            evidence_seqno: 0,
        };

        let baseline: SystematicEvidenceLog<CAP> = SystematicEvidenceLog::new(0xCA11_0001);
        let baseline_start = Instant::now();
        for _ in 0..n {
            let _ = baseline.record_decision(
                SafetyLevel::Strict,
                ctx,
                decision,
                5,
                false,
                None,
                0,
                None,
            );
        }
        let baseline_avg_ns = average_ns_per_op(baseline_start.elapsed(), n);

        let path = unique_temp_file("decision_card_journal_append_budget");
        let _ = std::fs::remove_file(&path);

        let journaled: SystematicEvidenceLog<CAP> = SystematicEvidenceLog::new(0xCA11_0002);
        journaled
            .enable_decision_card_journal(&path, flush_every)
            .expect("enable journal");
        let journal_start = Instant::now();
        for _ in 0..n {
            let _ = journaled.record_decision(
                SafetyLevel::Strict,
                ctx,
                decision,
                5,
                false,
                None,
                0,
                None,
            );
        }
        let journal_avg_ns = average_ns_per_op(journal_start.elapsed(), n);
        let overhead_ns = journal_avg_ns.saturating_sub(baseline_avg_ns);
        journaled
            .flush_decision_card_journal_for_tests()
            .expect("flush journal");

        let stats = journaled
            .decision_card_journal_stats_for_tests()
            .expect("journal stats present");
        assert_eq!(stats.0, n);
        assert!(stats.1 >= 1);
        assert_eq!(journaled.decision_card_journal_error_count_for_tests(), 0);
        assert!(
            overhead_ns <= budget_ns,
            "journal append overhead {}ns exceeded budget {}ns (baseline {}ns, journal {}ns per op); set FRANKENLIBC_EVIDENCE_JOURNAL_OVERHEAD_BUDGET_NS for slower hosts",
            overhead_ns,
            budget_ns,
            baseline_avg_ns,
            journal_avg_ns
        );
        eprintln!(
            "decision_card_journal_append_overhead_smoke_budget: sample={}, baseline_avg_ns={}, journal_avg_ns={}, overhead_ns={}, budget_ns={}, flush_every={}, flush_count={}",
            n, baseline_avg_ns, journal_avg_ns, overhead_ns, budget_ns, flush_every, stats.1
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn decision_card_journal_replays_after_restart() {
        let path = unique_temp_file("decision_card_replay");
        let _ = std::fs::remove_file(&path);

        let ctx = RuntimeContext::pointer_validation(0x4444, false);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Fast,
            action: MembraneAction::Allow,
            policy_id: 333,
            risk_upper_bound_ppm: 42,
            evidence_seqno: 0,
        };

        {
            let log: SystematicEvidenceLog<16> = SystematicEvidenceLog::new(0xABC0);
            let replayed = log
                .enable_decision_card_journal(&path, 1)
                .expect("enable journal");
            assert_eq!(replayed, 0);
            for _ in 0..3 {
                let _ = log.record_decision(
                    SafetyLevel::Strict,
                    ctx,
                    decision,
                    8,
                    false,
                    None,
                    0,
                    None,
                );
            }
            log.flush_decision_card_journal_for_tests()
                .expect("flush journal");
        }

        {
            let log: SystematicEvidenceLog<16> = SystematicEvidenceLog::new(0xABC1);
            let replayed = log
                .enable_decision_card_journal(&path, 1)
                .expect("enable journal");
            assert_eq!(replayed, 3);
            let cards = log.decision_cards_snapshot_sorted();
            assert_eq!(cards.len(), 3);
            assert_eq!(cards[0].decision_id, 1);
            assert_eq!(cards[2].decision_id, 3);

            let _ =
                log.record_decision(SafetyLevel::Strict, ctx, decision, 9, false, None, 0, None);
            log.flush_decision_card_journal_for_tests()
                .expect("flush journal");
        }

        {
            let log: SystematicEvidenceLog<16> = SystematicEvidenceLog::new(0xABC2);
            let replayed = log
                .enable_decision_card_journal(&path, 1)
                .expect("enable journal");
            assert_eq!(replayed, 4);
            let cards = log.decision_cards_snapshot_sorted();
            assert_eq!(cards.len(), 4);
            assert_eq!(cards.last().unwrap().decision_id, 4);
            assert!(
                cards
                    .windows(2)
                    .all(|w| w[1].timestamp_mono_ns >= w[0].timestamp_mono_ns)
            );
            assert_eq!(log.decision_card_journal_error_count_for_tests(), 0);
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn decision_card_journal_ignores_partial_tail_record() {
        let path = unique_temp_file("decision_card_partial_tail");
        let _ = std::fs::remove_file(&path);

        let ctx = RuntimeContext::pointer_validation(0x5555, true);
        let decision = RuntimeDecision {
            profile: ValidationProfile::Full,
            action: MembraneAction::Repair(HealingAction::IgnoreForeignFree),
            policy_id: 919,
            risk_upper_bound_ppm: 900_000,
            evidence_seqno: 0,
        };

        {
            let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0xDD01);
            log.enable_decision_card_journal(&path, 1)
                .expect("enable journal");
            let _ = log.record_decision(
                SafetyLevel::Hardened,
                ctx,
                decision,
                44,
                true,
                None,
                0,
                None,
            );
            log.flush_decision_card_journal_for_tests()
                .expect("flush journal");
        }

        {
            let mut f = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open journal for corruption");
            f.write_all(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
                .expect("append partial bytes");
            f.sync_data().expect("sync corrupted tail");
        }

        {
            let log: SystematicEvidenceLog<8> = SystematicEvidenceLog::new(0xDD02);
            let replayed = log
                .enable_decision_card_journal(&path, 1)
                .expect("enable journal");
            assert_eq!(replayed, 1);
            let cards = log.decision_cards_snapshot_sorted();
            assert_eq!(cards.len(), 1);
            assert_eq!(cards[0].decision_id, 1);
        }

        let _ = std::fs::remove_file(path);
    }
}
