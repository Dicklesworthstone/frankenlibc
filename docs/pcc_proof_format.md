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

## Verification Anchors

- PCC manifest verification and hash publication:
  [`crates/frankenlibc-abi/src/runtime_policy.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/src/runtime_policy.rs)
- `memcpy` PCC wiring regression:
  [`crates/frankenlibc-abi/tests/string_abi_test.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/tests/string_abi_test.rs)
- `snprintf` PCC wiring regression:
  [`crates/frankenlibc-abi/tests/stdio_abi_test.rs`](/data/projects/frankenlibc/crates/frankenlibc-abi/tests/stdio_abi_test.rs)
