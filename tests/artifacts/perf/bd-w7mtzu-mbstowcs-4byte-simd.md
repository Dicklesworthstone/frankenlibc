# bd-w7mtzu - mbstowcs 4-byte SIMD decode keep

Date: 2026-06-13
Agent: BoldFalcon
Bead: `bd-w7mtzu`
Lever: four-codepoint SIMD UTF-8 4-byte decode window in `mbstowcs`
Verdict: KEPT
Score: `(Impact 5.0 x Confidence 5.0) / Effort 2.0 = 12.5`

## Target

After the retained 2-byte and 3-byte `mbstowcs` decode windows and the
2/3/4-byte `wcstombs` encode windows, the remaining profiled wchar residual was
`wchar_mbstowcs/astral_4byte`. The previous 4-byte encode artifact left this
lane open and measured it at roughly 11-12 us for 1024 UTF-8 code points.

Fresh same-worker baseline on `vmi1153651`:

```text
RCH_WORKER=vmi1153651 rch exec -- \
  cargo bench -j 1 -p frankenlibc-bench --bench wchar_bench -- \
  wchar_mbstowcs/astral_4byte --noplot --sample-size 60 \
  --warm-up-time 1 --measurement-time 3

wchar_mbstowcs/astral_4byte
  time:  [11.672 us 12.041 us 12.402 us]
  thrpt: [314.98 MiB/s 324.41 MiB/s 334.66 MiB/s]
```

## Change

`mbstowcs` now has one additional SIMD decode block after the existing 3-byte
decode block and before the scalar step:

- Read one 16-byte window as four 4-byte UTF-8 sequences.
- Validate `F0..=F7` leads and three plain continuation lanes.
- Preserve scalar overlong behavior with the exact `F0 => cont1 >= 0x90` guard.
- Assemble four `u32` code points and write them in source order.
- Fall back to scalar for ASCII, 2/3-byte, malformed, mixed-width, short-input,
  NUL, or destination-capacity edges.

This is one lever: it does not change `wcstombs`, ASCII, 2-byte decode, 3-byte
decode, 5/6-byte decode, or scalar error handling.

## Isomorphism

- Ordering: four decoded code points are copied to `dest[di..di+4]` in left to
  right source order.
- Tie-breaking: not applicable; there is no search or selection.
- Error behavior: any non-clean window breaks before writing and delegates to
  the existing scalar `mbtowc` step. Incomplete prefixes, bad continuations,
  overlong `F0` forms, NUL, and destination truncation therefore keep the same
  return values and write prefix.
- Numeric contract: the SIMD range matches the existing scalar decoder's
  glibc-compatible 4-byte `F0..=F7` contract. Code points above U+10FFFF encoded
  with `F5..=F7` remain accepted, as before.
- Floating point and RNG: not involved.

## Proof

RCH `vmi1153651`:

```text
cargo test -j 1 -p frankenlibc-core --lib \
  mbstowcs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1
```

Passed: `string::wchar::tests::mbstowcs_simd_isomorphic_to_scalar`.

```text
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_mbstowcs_simd \
  -- --nocapture --test-threads=1
```

Passed: 200,000 generated NUL-terminated inputs against live host glibc,
including 2-byte, 3-byte, 4-byte, ASCII, malformed, and boundary-straddling
cases.

```text
cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry \
  -- --nocapture --test-threads=1
```

Passed with unchanged golden hashes:

- `mbstowcs wide sha256=e52563fe0c036cc2d97d9b14a28d8d0e3adeec307686eecf8122466ca95dab50`
- `wcstombs back sha256=5f71c2382d1655e56994e4022f3e88be237d22350f6af9bd744680ec108aad6e`

Touched-file formatting:

```text
rustfmt --edition 2024 --check \
  crates/frankenlibc-core/src/string/wchar.rs \
  crates/frankenlibc-abi/tests/conformance_diff_mbstowcs_simd.rs
```

Passed.

Known unrelated environment noise:

- RCH builds report the existing missing SMT solver warning.
- ABI builds report the existing `wchar_abi.rs` `work_local` unused-assignment
  warning.

## Post

Same-worker RCH post on `vmi1153651`, same Criterion command:

```text
wchar_mbstowcs/astral_4byte
  time:  [1.8569 us 2.0934 us 2.4230 us]
  thrpt: [1.5744 GiB/s 1.8222 GiB/s 2.0544 GiB/s]
```

Middle-estimate improvement:

- Time: `12.041 us -> 2.0934 us`, `5.75x` faster.
- Throughput: `324.41 MiB/s -> 1.8222 GiB/s`.

`bd-w7mtzu` can now close: the named 2-byte, 3-byte, and 4-byte decode/encode
lanes have all shipped with separate same-worker proof.
