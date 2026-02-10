# EvidenceSymbolRecord Format (v1)

Bead: `bd-kom`

This document defines the byte-stable v1 evidence symbol format implemented in:
- `crates/glibc-rs-membrane/src/runtime_math/evidence.rs`

It is intentionally explicit (offset-based, little-endian) to avoid any `repr(packed)` / alignment pitfalls and to keep the runtime free of `unsafe`.

## Goals

- Provide a fixed-size, self-describing symbol envelope sufficient for offline decoding:
  - `epoch_id`, `seed`, `T`, `K_source`, `ESI`
  - integrity: `payload_hash`, `chain_hash`
- Carry a compact payload (`T` bytes) produced from runtime events.
- Be cheap to record (memcpy into an overwrite-on-full ring buffer).
- Reserve space for optional auth tags without format churn.

## Record Size and Regions

v1 is fixed at **256 bytes**:

- Header: 64 bytes
- Payload: `T = 128` bytes (exact)
- Auth tag: 32 bytes (optional; typically all zeros)
- Reserved: 32 bytes (future expansion; must be zero in v1)

All multi-byte integers are **little-endian**.

## Header Layout (64 bytes)

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 0 | 4 | `magic` | ASCII `EVR1` |
| 4 | 2 | `version` | `1` |
| 6 | 2 | `flags` | See below |
| 8 | 8 | `epoch_id` | epoch identity (deterministic mix of mode/family/counter) |
| 16 | 8 | `seqno` | global monotonic sequence number (ring publication) |
| 24 | 8 | `seed` | epoch seed (used by offline repair schedule; also seeds hashes) |
| 32 | 1 | `family` | `ApiFamily as u8` |
| 33 | 1 | `mode` | `SafetyLevel` code: strict=0, hardened=1, off=2 |
| 34 | 1 | `action` | `MembraneAction` code: allow=0, full=1, repair=2, deny=3 |
| 35 | 1 | `profile` | `ValidationProfile` code: fast=0, full=1 |
| 36 | 2 | `esi` | encoding symbol id (systematic source symbols are `0..K_source-1`) |
| 38 | 2 | `k_source` | `K_source` (v1 default `K_max = 256`) |
| 40 | 2 | `r_repair` | repair symbol count (v1: `0` for systematic-only) |
| 42 | 2 | `symbol_size_t` | `T` (v1: 128) |
| 44 | 8 | `payload_hash` | `H(payload; seed)` |
| 52 | 8 | `chain_hash` | `H(prev_chain_hash || header_prefix || auth_tag)` |
| 60 | 4 | `reserved` | must be 0 in v1 |

### Flags (`u16`)

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `SYSTEMATIC` | record is a systematic source symbol |
| 1 | `REPAIR` | record is a repair symbol |
| 2 | `AUTH_TAG_PRESENT` | auth tag bytes are meaningful (tooling should verify) |

## Payload Layout: Decision Event (EVP1)

The payload is `T = 128` bytes. v1 defines one stable payload mapping for runtime decisions:

- `payload[0..4] = "EVP1"` (payload magic)
- `payload[4] = 1` (payload version)
- `payload[5] = 1` (event kind: Decision)

Offsets (little-endian):

| Offset | Size | Field | Meaning |
|---:|---:|---|---|
| 8 | 8 | `addr_hint` | `RuntimeContext.addr_hint` |
| 16 | 8 | `requested_bytes` | `RuntimeContext.requested_bytes` |
| 24 | 1 | `ctx_flags` | bit0=is_write, bit1=bloom_negative |
| 25 | 1 | `mode_code` | same encoding as header `mode` |
| 26 | 2 | `contention_hint` | `RuntimeContext.contention_hint` |
| 28 | 4 | `policy_id` | `RuntimeDecision.policy_id` |
| 32 | 4 | `risk_upper_ppm` | `RuntimeDecision.risk_upper_bound_ppm` |
| 36 | 4 | `estimated_cost_ns` | clamped to `u32::MAX` |
| 40 | 1 | `adverse` | 0/1 |
| 41 | 1 | `heal_code` | 0=None, 1=ClampSize, 2=TruncateWithNull, 3=IgnoreDoubleFree, 4=IgnoreForeignFree, 5=ReallocAsMalloc, 6=ReturnSafeDefault, 7=UpgradeToSafeVariant |
| 44 | 8 | `heal_arg0` | action-specific |
| 52 | 8 | `heal_arg1` | action-specific |

All remaining bytes are reserved and must be zero in v1.

## Hashing / Integrity (v1)

v1 uses a small non-cryptographic 64-bit hash implementation (`evidence_hash64`) for:

- `payload_hash = H(payload; seed ^ domain)`
- `chain_hash = H(prev_chain_hash || header_prefix(with payload_hash) || auth_tag; constant)`

This is meant to detect torn writes / accidental corruption. It is not intended to resist a powerful adversary.

If stronger tamper resistance is needed for exported traces, tooling can set `AUTH_TAG_PRESENT` and fill the 32-byte auth tag region using a keyed MAC (e.g. BLAKE3 keyed mode).

## Ring Buffer Semantics

The in-memory storage is an overwrite-on-full ring buffer:

- Writers allocate a global monotonic `seqno`.
- Writers publish to slot `seqno % CAP`.
- Publication protocol:
  1. write record bytes
  2. store `published_seqno = seqno` with `Release`
- Readers (tooling) snapshot with:
  1. load `published_seqno` with `Acquire`
  2. copy record
  3. re-load `published_seqno` and accept only if unchanged

This yields a best-effort consistent snapshot under concurrent writers.

