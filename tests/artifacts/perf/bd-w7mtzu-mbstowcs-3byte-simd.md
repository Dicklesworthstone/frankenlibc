# bd-w7mtzu - mbstowcs 3-byte UTF-8 SIMD decode

## Target

- Bead: `bd-w7mtzu`
- Lane: `mbstowcs` pure 3-byte UTF-8 / CJK decode.
- Worker: `vmi1153651`
- Lever: decode a clean 12-byte UTF-8 window into four `u32` codepoints with portable SIMD, falling back to the existing scalar `mbtowc` path for every mixed-width, malformed, NUL, truncated, overlong, or surrogate window.

## Baseline

Tracked Criterion baseline (`wchar_bench`, same worker):

- `wchar_mbstowcs/ascii_1k`: `[161.86 ns 168.05 ns 173.92 ns]`
- `wchar_mbstowcs/mixed_utf8`: `[3.3654 us 3.4895 us 3.6256 us]`
- `wchar_wcstombs/ascii_1k`: `[212.32 ns 219.15 ns 226.75 ns]`
- `wchar_wcstombs/mixed_utf8`: `[6.4523 us 6.6647 us 6.8658 us]`

Focused release probe (`zz_scratch_mbmb_bench`, same worker):

- `mbstowcs cyrillic_2b`: FrankenLibC `0.221 ns/byte`, glibc `1.668 ns/byte`, ratio `0.13`
- `mbstowcs cjk_3b`: FrankenLibC `2.840 ns/byte`, glibc `1.532 ns/byte`, ratio `1.85`

## Isomorphism

- Output ordering and tie-breaking are unchanged: the SIMD path writes codepoints in the same sequence as four scalar `mbtowc` calls.
- Error behavior is unchanged: the path only fires when all four 3-byte sequences satisfy lead `E0..EF`, continuation `80..BF`, `E0` second byte `>= A0`, and `ED` second byte `<= 9F`.
- Mixed-width, malformed, NUL, boundary-straddling, overlong, surrogate, and short-tail cases fall through to the existing scalar decoder.
- Floating point and RNG are not involved.

## Proof

Local:

- `cargo test -j 1 -p frankenlibc-core --lib mbstowcs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_mbstowcs_simd -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry -- --nocapture --test-threads=1`: passed.

RCH on `vmi1153651`:

- `cargo test -j 1 -p frankenlibc-core --lib mbstowcs_simd_isomorphic_to_scalar -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_mbstowcs_simd -- --nocapture --test-threads=1`: passed.
- `cargo test -j 1 -p frankenlibc-abi --test golden_wchar_conv_reentry -- --nocapture --test-threads=1`: passed.
- Golden SHA: `mbstowcs wide sha256=e52563fe0c036cc2d97d9b14a28d8d0e3adeec307686eecf8122466ca95dab50`.
- Golden SHA: `wcstombs back sha256=5f71c2382d1655e56994e4022f3e88be237d22350f6af9bd744680ec108aad6e`.

Known environment noise: RCH workers report the existing missing SMT solver warning. ABI builds also report the existing `wchar_abi.rs` `work_local` unused-assignment warning.

## Post

Focused release probe (`zz_scratch_mbmb_bench`, same worker):

- `mbstowcs cyrillic_2b`: FrankenLibC `0.182 ns/byte`, glibc `1.277 ns/byte`, ratio `0.14`
- `mbstowcs cjk_3b`: FrankenLibC `0.447 ns/byte`, glibc `1.505 ns/byte`, ratio `0.30`

Same-worker CJK improvement:

- FrankenLibC: `2.840 ns/byte -> 0.447 ns/byte`, `6.35x` faster.
- Versus glibc: `1.85x` slower -> `3.37x` faster.

The optional tracked Criterion post-run was attempted after the exact release post probe, but a concurrent peer `stdio/file.rs` change blocked `frankenlibc-core` compilation (`copy_from_slice` received `Vec<u8>` instead of `&[u8]` at `crates/frankenlibc-core/src/stdio/file.rs:1087`). That file is outside this bead's reservation and is intentionally not included in this commit.

## Score

Kept. Score `(Impact 5.0 x Confidence 5.0) / Effort 2.0 = 12.5`.
