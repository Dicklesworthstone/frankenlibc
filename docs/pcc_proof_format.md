# PCC Proof Format

FrankenLibC's current proof-carrying-code fast path is encoded as a verified
certificate manifest in [`crates/frankenlibc-abi/src/runtime_policy.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/src/runtime_policy.rs).
The manifest is intentionally compact and machine-checkable so ABI entrypoints
can switch between `runtime_policy.ffi_pcc.decide` and the regular runtime
policy path without heap allocation.

## Manifest Row

Each `FfiPccCertificate` row carries:

- `symbol`: ABI entrypoint name installed by `entrypoint_scope`.
- `family`: runtime-math family for the call.
- `policy_id`: stable PCC policy identifier in the `0x5043_43xx` namespace.
- `max_requested_bytes`: admitted request-size ceiling.
- `allow_write`: whether the certificate covers writable destinations.
- `allow_bloom_negative`: whether the proof tolerates non-membrane ownership.
- `skip_stage_ordering`: whether runtime stage reordering is bypassed.
- `skip_pointer_validation`: whether pointer-validation helpers may be skipped.

## Operational Contract

1. The ABI entrypoint installs an `entrypoint_scope("<symbol>")`.
2. `runtime_policy::decide` matches the active symbol against the verified PCC
   manifest.
3. On a match, the call records `runtime_policy.ffi_pcc.decide` and returns a
   fast `Allow` decision.
4. On a miss, the call falls back to the ordinary runtime-policy and membrane
   path.

## Current Certificates

The current manifest covers allocator entrypoints plus:

- `memcpy`
- `memcmp`
- `strlen`
- `snprintf`
- `vsnprintf`

The implementation is intentionally conservative: write-capable certificates
may bypass runtime-kernel routing and stage ordering, while full
pointer-validation bypass remains limited to read-only certificates.

## Soundness Proofs (bd-06bxm.5)

Each PCC certificate carries an implicit soundness claim. The proofs below
establish why bypassing the membrane is safe for these symbols:

### Allocator Certificates (malloc, calloc, realloc, free, memalign variants)

**Claim**: PCC certificates for allocator symbols are sound because double-free
detection occurs at the arena level, not the membrane policy level.

**Proof**: The membrane's arena (in `crates/frankenlibc-membrane/src/arena.rs`)
tracks slot state. When `arena.free()` is called on a pointer whose slot is
already in `Freed` or `Quarantined` state, it returns `FreeResult::DoubleFree`.
The ABI layer (`malloc_abi.rs:1778-1786`) then records
`HealingAction::IgnoreDoubleFree` in hardened mode. This detection is
independent of the `decide()` policy path—the PCC fast path does not bypass
the arena's safety checks.

**Test anchor**: `scripts/check_pcc_double_free_e2e.sh`

### String/Memory Certificates (memcmp, strlen)

**Claim**: PCC certificates for `memcmp` and `strlen` are sound because they
are read-only operations with no state mutation.

**Proof**: These functions scan memory but do not modify it. The certificates
use `FFI_PCC_READ_ONLY_FLAGS` which has `allow_write: false`. Memory safety
relies on the caller providing valid pointers and lengths per the C contract.
Membrane validation cannot improve on this since the bounds are implicit in
the call itself (for `strlen`) or explicit length parameters (for `memcmp`).

### memcpy Certificate

**Claim**: PCC certificate for `memcpy` is sound because copy bounds are
validated by the caller contract.

**Proof**: `memcpy` copies exactly `n` bytes from `src` to `dst`. Buffer
overflow would require the caller to pass incorrect bounds, which is undefined
behavior in the calling contract itself. The membrane cannot detect bounds
violations without caller cooperation (explicit size parameters), so
bypassing membrane validation does not reduce safety.

### Stdio Certificates (snprintf, vsnprintf)

**Claim**: PCC certificates for `snprintf` and `vsnprintf` are sound because
writes are bounded by the `size` parameter and null-termination is enforced.

**Proof**: `snprintf` writes at most `size-1` bytes plus a null terminator.
The implementation in `crates/frankenlibc-core/src/printf/format.rs` respects
this bound. Overflow is prevented by the size contract, not membrane
validation. Format string vulnerabilities are a separate concern that membrane
cannot address without semantic analysis.

## Verification Anchors

- PCC manifest verification and hash publication:
  [`crates/frankenlibc-abi/src/runtime_policy.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/src/runtime_policy.rs)
- `memcpy` PCC wiring regression:
  [`crates/frankenlibc-abi/tests/string_abi_test.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/tests/string_abi_test.rs)
- `snprintf` PCC wiring regression:
  [`crates/frankenlibc-abi/tests/stdio_abi_test.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/tests/stdio_abi_test.rs)
- PCC double-free E2E test (bd-06bxm.5):
  [`scripts/check_pcc_double_free_e2e.sh`](/data/projects/frankenlibc/scripts/check_pcc_double_free_e2e.sh)
