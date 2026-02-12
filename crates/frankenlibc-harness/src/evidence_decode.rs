//! Offline decoding + proof verification for runtime evidence symbols.
//!
//! Bead: `bd-pc4`
//!
//! This is tooling-only: it ingests exported `EvidenceSymbolRecord` blobs and attempts to
//! reconstruct missing systematic symbols using the v1 deterministic XOR repair schedule
//! implemented in `glibc-rs-membrane` (`runtime_math/evidence.rs`).
//!
//! The decoder emits an explainable, deterministic `DecodeProof` suitable for diffs.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Serialize;
use thiserror::Error;

use frankenlibc_membrane::runtime_math::evidence::{
    EVIDENCE_RECORD_SIZE, EVIDENCE_SYMBOL_SIZE_T, EvidenceRecordError, EvidenceSymbolRecord,
    FLAG_REPAIR, FLAG_SYSTEMATIC, derive_repair_schedule_v1,
};

#[derive(Debug, Error)]
pub enum EvidenceDecodeError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("input length {len} is not a multiple of {record_size}")]
    MisalignedInput { len: usize, record_size: usize },
    #[error("no evidence records found")]
    EmptyInput,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodeReport {
    pub epochs: Vec<EpochDecodeProof>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EpochDecodeProof {
    pub epoch_id: u64,
    pub family: u8,
    pub mode: u8,
    pub seed: u64,
    pub k_source: u16,
    pub r_repair: u16,

    pub records_total: usize,
    pub systematic_records: usize,
    pub repair_records: usize,

    pub structural_errors: usize,
    pub payload_hash_mismatches: usize,
    pub chain_hash_mismatches: usize,
    pub duplicate_systematic_conflicts: usize,

    pub decoded_systematic: u16,
    pub missing_systematic: u16,

    pub verified_repairs: usize,
    pub repair_payload_mismatches: usize,

    pub status: DecodeStatus,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum DecodeStatus {
    Success,
    Partial,
    Failed,
}

#[derive(Debug, Clone)]
struct RepairEquation {
    unknown: Vec<u16>,
    value: [u8; EVIDENCE_SYMBOL_SIZE_T],
}

/// Decode all epochs found in the input file.
pub fn decode_evidence_file(
    input: &Path,
    epoch_filter: Option<u64>,
) -> Result<DecodeReport, EvidenceDecodeError> {
    let bytes = std::fs::read(input)?;
    if bytes.is_empty() {
        return Err(EvidenceDecodeError::EmptyInput);
    }
    if bytes.len() % EVIDENCE_RECORD_SIZE != 0 {
        return Err(EvidenceDecodeError::MisalignedInput {
            len: bytes.len(),
            record_size: EVIDENCE_RECORD_SIZE,
        });
    }

    let mut by_epoch: BTreeMap<u64, Vec<EvidenceSymbolRecord>> = BTreeMap::new();
    for chunk in bytes.chunks_exact(EVIDENCE_RECORD_SIZE) {
        let mut arr = [0u8; EVIDENCE_RECORD_SIZE];
        arr.copy_from_slice(chunk);
        let rec = EvidenceSymbolRecord::from_bytes(arr);
        if epoch_filter.is_some_and(|target| rec.epoch_id() != target) {
            continue;
        }
        by_epoch.entry(rec.epoch_id()).or_default().push(rec);
    }

    let mut epochs = Vec::with_capacity(by_epoch.len());
    for (epoch_id, mut records) in by_epoch {
        records.sort_by_key(EvidenceSymbolRecord::seqno);
        epochs.push(decode_epoch(epoch_id, &records));
    }

    Ok(DecodeReport { epochs })
}

fn decode_epoch(epoch_id: u64, records: &[EvidenceSymbolRecord]) -> EpochDecodeProof {
    let mut proof = EpochDecodeProof {
        epoch_id,
        family: 0,
        mode: 0,
        seed: 0,
        k_source: 0,
        r_repair: 0,
        records_total: records.len(),
        systematic_records: 0,
        repair_records: 0,
        structural_errors: 0,
        payload_hash_mismatches: 0,
        chain_hash_mismatches: 0,
        duplicate_systematic_conflicts: 0,
        decoded_systematic: 0,
        missing_systematic: 0,
        verified_repairs: 0,
        repair_payload_mismatches: 0,
        status: DecodeStatus::Failed,
        notes: Vec::new(),
    };

    if records.is_empty() {
        proof.notes.push("empty_epoch".to_string());
        return proof;
    }

    // Establish epoch parameters from first record; mismatches become notes.
    proof.family = records[0].family();
    proof.mode = records[0].mode();
    proof.seed = records[0].seed();
    proof.k_source = records[0].k_source();
    proof.r_repair = records[0].r_repair();

    // Integrity checks: payload hash + chain hash.
    let mut prev_chain = 0u64;
    for rec in records {
        if let Err(e) = rec.validate_basic() {
            proof.structural_errors += 1;
            proof
                .notes
                .push(format!("structural_error: {:?}", compact_record_error(e)));
            continue;
        }
        if rec.seed() != proof.seed
            || rec.k_source() != proof.k_source
            || rec.r_repair() != proof.r_repair
        {
            proof.notes.push("epoch_param_mismatch".to_string());
        }

        if !rec.verify_payload_hash_v1() {
            proof.payload_hash_mismatches += 1;
        }
        if !rec.verify_chain_hash_v1(prev_chain) {
            proof.chain_hash_mismatches += 1;
        }
        prev_chain = rec.chain_hash();
    }

    let k = usize::from(proof.k_source);
    if k == 0 {
        proof.notes.push("k_source_zero".to_string());
        proof.status = DecodeStatus::Failed;
        return proof;
    }

    // Collect symbols.
    let mut sources: Vec<Option<[u8; EVIDENCE_SYMBOL_SIZE_T]>> = vec![None; k];
    let mut equations: Vec<RepairEquation> = Vec::new();

    for rec in records {
        // Decoder policy: only ingest structurally-valid records with a matching payload hash.
        //
        // Chain-hash mismatches are still tolerated; they signal missing/out-of-order records,
        // not necessarily payload corruption.
        if rec.validate_basic().is_err() {
            continue;
        }
        if rec.seed() != proof.seed
            || rec.k_source() != proof.k_source
            || rec.r_repair() != proof.r_repair
        {
            continue;
        }
        if !rec.verify_payload_hash_v1() {
            continue;
        }

        let flags = rec.flags();
        let is_systematic = (flags & FLAG_SYSTEMATIC) != 0;
        let is_repair = (flags & FLAG_REPAIR) != 0;
        let esi = rec.esi();

        if is_systematic && !is_repair {
            proof.systematic_records += 1;
            let idx = usize::from(esi);
            if idx >= k {
                proof.structural_errors += 1;
                proof.notes.push("systematic_esi_out_of_range".to_string());
                continue;
            }
            let payload = *rec.payload();
            if let Some(existing) = &sources[idx] {
                if existing != &payload {
                    proof.duplicate_systematic_conflicts += 1;
                }
            } else {
                sources[idx] = Some(payload);
            }
            continue;
        }

        if is_repair {
            proof.repair_records += 1;
            if esi < proof.k_source {
                proof.structural_errors += 1;
                proof.notes.push("repair_esi_lt_k_source".to_string());
                continue;
            }
            let sched = derive_repair_schedule_v1(proof.seed, proof.k_source, esi);
            let unknown = sched.indices().to_vec();
            equations.push(RepairEquation {
                unknown,
                value: *rec.payload(),
            });
        }
    }

    // Peeling decode.
    peel_decode(&mut sources, &mut equations);

    let decoded = sources.iter().filter(|s| s.is_some()).count() as u16;
    let missing = proof.k_source.saturating_sub(decoded);
    proof.decoded_systematic = decoded;
    proof.missing_systematic = missing;

    // Repair verification: check any repair whose schedule is fully known.
    for eq in &equations {
        if schedule_fully_known(&sources, &eq.unknown) {
            proof.verified_repairs += 1;
            let expected = xor_sources(&sources, &eq.unknown);
            if expected != eq.value {
                proof.repair_payload_mismatches += 1;
            }
        }
    }

    proof.notes.sort();
    proof.notes.dedup();

    proof.status =
        if missing == 0 && proof.payload_hash_mismatches == 0 && proof.chain_hash_mismatches == 0 {
            DecodeStatus::Success
        } else if decoded > 0 {
            DecodeStatus::Partial
        } else {
            DecodeStatus::Failed
        };

    proof
}

fn peel_decode(
    sources: &mut [Option<[u8; EVIDENCE_SYMBOL_SIZE_T]>],
    equations: &mut [RepairEquation],
) {
    let mut progress = true;
    while progress {
        progress = false;

        // Reduce all equations using newly-known sources.
        for eq in equations.iter_mut() {
            if eq.unknown.is_empty() {
                continue;
            }
            let mut next_unknown = Vec::with_capacity(eq.unknown.len());
            for &idx in &eq.unknown {
                let i = idx as usize;
                if let Some(src) = sources.get(i).and_then(|v| v.as_ref()) {
                    xor_in_place(&mut eq.value, src);
                } else {
                    next_unknown.push(idx);
                }
            }
            eq.unknown = next_unknown;
        }

        // Solve singleton equations.
        for eq in equations.iter() {
            if eq.unknown.len() != 1 {
                continue;
            }
            let idx = eq.unknown[0] as usize;
            if idx >= sources.len() {
                continue;
            }
            if sources[idx].is_none() {
                sources[idx] = Some(eq.value);
                progress = true;
            }
        }
    }
}

fn xor_in_place(dst: &mut [u8; EVIDENCE_SYMBOL_SIZE_T], src: &[u8; EVIDENCE_SYMBOL_SIZE_T]) {
    for i in 0..EVIDENCE_SYMBOL_SIZE_T {
        dst[i] ^= src[i];
    }
}

fn schedule_fully_known(sources: &[Option<[u8; EVIDENCE_SYMBOL_SIZE_T]>], indices: &[u16]) -> bool {
    indices
        .iter()
        .all(|&idx| sources.get(idx as usize).and_then(|v| v.as_ref()).is_some())
}

fn xor_sources(
    sources: &[Option<[u8; EVIDENCE_SYMBOL_SIZE_T]>],
    indices: &[u16],
) -> [u8; EVIDENCE_SYMBOL_SIZE_T] {
    let mut out = [0u8; EVIDENCE_SYMBOL_SIZE_T];
    for &idx in indices {
        if let Some(src) = sources.get(idx as usize).and_then(|v| v.as_ref()) {
            xor_in_place(&mut out, src);
        }
    }
    out
}

fn compact_record_error(e: EvidenceRecordError) -> &'static str {
    match e {
        EvidenceRecordError::BadMagic => "bad_magic",
        EvidenceRecordError::UnsupportedVersion(_) => "unsupported_version",
        EvidenceRecordError::BadSymbolSize(_) => "bad_symbol_size",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use frankenlibc_membrane::config::SafetyLevel;
    use frankenlibc_membrane::runtime_math::evidence::{
        PAYLOAD_OFFSET, derive_repair_symbol_count_v1, encode_xor_repair_payload_v1,
    };
    use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction, ValidationProfile};

    type Payload = [u8; EVIDENCE_SYMBOL_SIZE_T];

    #[test]
    fn decode_epoch_success_when_no_loss_and_hashes_ok() {
        let (epoch_id, records) =
            build_epoch_records(0x1122_3344_5566_7788, 0x0102_0304_0506_0708, 16, 64);
        let proof = decode_epoch(epoch_id, &records);

        assert_eq!(proof.missing_systematic, 0);
        assert_eq!(proof.payload_hash_mismatches, 0);
        assert_eq!(proof.chain_hash_mismatches, 0);
        assert_eq!(proof.repair_payload_mismatches, 0);
        assert!(matches!(proof.status, DecodeStatus::Success));
    }

    #[test]
    fn decode_epoch_recovers_missing_systematic_but_chain_reports_gaps() {
        let (epoch_id, mut records) =
            build_epoch_records(0x99AA_BBCC_DDEE_F001, 0x0BAD_F00D_CAFE_BEEF, 16, 96);

        // Drop a few systematic records (loss); keep repairs.
        let lost_esis: [u16; 3] = [2, 7, 13];
        records.retain(|rec| {
            let is_systematic = (rec.flags() & FLAG_SYSTEMATIC) != 0;
            !(is_systematic && lost_esis.contains(&rec.esi()))
        });

        let proof = decode_epoch(epoch_id, &records);
        assert_eq!(proof.missing_systematic, 0, "{proof:?}");
        assert_eq!(proof.payload_hash_mismatches, 0);
        assert!(proof.chain_hash_mismatches > 0);
        assert_eq!(proof.repair_payload_mismatches, 0);
        assert!(matches!(proof.status, DecodeStatus::Partial));
    }

    #[test]
    fn decode_epoch_counts_payload_hash_mismatch_on_tamper() {
        let (epoch_id, mut records) =
            build_epoch_records(0xCAF0_1234_5678_9ABCu64, 0x4242_4242_1234_5678, 8, 32);

        // Flip one payload byte without updating payload_hash.
        let mut bytes = *records[0].as_bytes();
        bytes[PAYLOAD_OFFSET] ^= 0xFF;
        records[0] = EvidenceSymbolRecord::from_bytes(bytes);

        let proof = decode_epoch(epoch_id, &records);
        assert!(proof.payload_hash_mismatches >= 1, "{proof:?}");
    }

    #[test]
    fn loss_simulation_drop_within_r_recovers_all_sources() {
        let k_source: u16 = 32;
        let r_repair = derive_repair_symbol_count_v1(k_source, 50);
        let (epoch_id, mut records) = build_epoch_records(
            0x5EED_F00D_1234_0001,
            0x1111_2222_3333_4444,
            k_source,
            r_repair,
        );

        // Drop 8 systematic records (loss <= R; for this config, R=16).
        let mut drop_systematic = Vec::new();
        for esi in (0u16..k_source).step_by(4).take(8) {
            drop_systematic.push(esi);
        }

        records.retain(|rec| {
            let is_sys = (rec.flags() & FLAG_SYSTEMATIC) != 0;
            let esi = rec.esi();
            if is_sys && drop_systematic.contains(&esi) {
                return false;
            }
            true
        });

        let proof = decode_epoch(epoch_id, &records);
        assert_eq!(proof.missing_systematic, 0, "{proof:?}");
        assert_eq!(proof.payload_hash_mismatches, 0);
        assert_eq!(proof.repair_payload_mismatches, 0);
        assert!(proof.chain_hash_mismatches > 0);
    }

    #[test]
    fn loss_simulation_drop_beyond_r_fails_to_recover() {
        let k_source: u16 = 32;
        let r_repair = derive_repair_symbol_count_v1(k_source, 50);
        let (epoch_id, mut records) = build_epoch_records(
            0x5EED_F00D_1234_0002,
            0x1111_2222_3333_4444,
            k_source,
            r_repair,
        );

        // Drop all repair symbols (R) plus one systematic -> total loss > R.
        let drop_one_systematic = 3u16;
        records.retain(|rec| {
            let is_sys = (rec.flags() & FLAG_SYSTEMATIC) != 0;
            let is_rep = (rec.flags() & FLAG_REPAIR) != 0;
            if is_rep {
                return false;
            }
            !(is_sys && rec.esi() == drop_one_systematic)
        });

        let proof = decode_epoch(epoch_id, &records);
        assert!(proof.missing_systematic > 0, "{proof:?}");
    }

    #[test]
    fn corruption_bitflip_is_detected_and_corrupt_record_is_ignored() {
        let k_source: u16 = 16;
        let r_repair = derive_repair_symbol_count_v1(k_source, 200);
        let (epoch_id, mut records) = build_epoch_records(
            0x5EED_F00D_1234_0003,
            0x7777_6666_5555_4444,
            k_source,
            r_repair,
        );

        // Corrupt one systematic payload byte; payload hash check must catch this.
        let target_esi = 5u16;
        let idx = records
            .iter()
            .position(|rec| (rec.flags() & FLAG_SYSTEMATIC) != 0 && rec.esi() == target_esi)
            .expect("find systematic record");
        let mut bytes = *records[idx].as_bytes();
        bytes[PAYLOAD_OFFSET + 7] ^= 0xA5;
        records[idx] = EvidenceSymbolRecord::from_bytes(bytes);

        let proof = decode_epoch(epoch_id, &records);
        assert!(proof.payload_hash_mismatches >= 1, "{proof:?}");
        assert_eq!(proof.missing_systematic, 0, "{proof:?}");
        assert_eq!(proof.repair_payload_mismatches, 0);
    }

    fn build_epoch_records(
        epoch_id: u64,
        seed: u64,
        k_source: u16,
        r_repair: u16,
    ) -> (u64, Vec<EvidenceSymbolRecord>) {
        let family = ApiFamily::Allocator;
        let mode = SafetyLevel::Hardened;
        let action = MembraneAction::Allow;
        let profile = ValidationProfile::Fast;

        let k = usize::from(k_source);
        let src_payloads: Vec<Payload> = (0..k).map(|i| payload_for(seed, i as u16)).collect();

        let mut out = Vec::with_capacity(k + (r_repair as usize));

        let mut chain_hash = 0u64;
        let mut seqno = 0u64;

        for (esi, payload) in src_payloads.iter().enumerate() {
            let rec = EvidenceSymbolRecord::build_v1(
                epoch_id,
                seqno,
                seed,
                family,
                mode,
                action,
                profile,
                FLAG_SYSTEMATIC,
                esi as u16,
                k_source,
                r_repair,
                chain_hash,
                payload,
                None,
            );
            chain_hash = rec.chain_hash();
            seqno = seqno.wrapping_add(1);
            out.push(rec);
        }

        for i in 0..r_repair {
            let esi = k_source.wrapping_add(i);
            let payload = encode_xor_repair_payload_v1(seed, &src_payloads, esi);
            let rec = EvidenceSymbolRecord::build_v1(
                epoch_id,
                seqno,
                seed,
                family,
                mode,
                action,
                profile,
                FLAG_REPAIR,
                esi,
                k_source,
                r_repair,
                chain_hash,
                &payload,
                None,
            );
            chain_hash = rec.chain_hash();
            seqno = seqno.wrapping_add(1);
            out.push(rec);
        }

        (epoch_id, out)
    }

    fn payload_for(seed: u64, esi: u16) -> Payload {
        let mut out = [0u8; EVIDENCE_SYMBOL_SIZE_T];
        let mut state = seed ^ ((esi as u64) << 32) ^ 0xD6E8_FEB8_6659_FD93u64;
        for chunk in out.chunks_exact_mut(8) {
            let v = splitmix64_next(&mut state);
            chunk.copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    fn splitmix64_next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
