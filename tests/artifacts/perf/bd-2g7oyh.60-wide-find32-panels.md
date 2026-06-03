# bd-2g7oyh.60 - 32-lane wide char-or-NUL panels

## Target

- Bead: `bd-2g7oyh.60`
- Surface: `crates/frankenlibc-core/src/string/wide.rs::{find_wide_or_nul,wcsrchr,wcsstr,wcschr}`
- Profile-backed baseline: RCH re-profile after commit `fb241f61` on `vmi1227854`
- Baseline hot rows:
  - `wcsrchr_absent_4096` p50 `299.358 ns/op`, p95 `391.000`, p99 `1307.273`, mean `331.153`
  - `wcsstr_absent_4096` p50 `289.328`, p95 `328.315`, p99 `460.000`, mean `295.900`
  - `wcschr_absent_4096` p50 `265.533`, p95 `289.605`, p99 `320.000`, mean `268.028`
- Peer-owned surfaces avoided: allocator/malloc for `bd-2g7oyh.51`; `str.rs` for `bd-2g7oyh.25`

## Lever

Widen the shared char-or-NUL portable-SIMD candidate panel from 16 `u32` lanes to 32 `u32` lanes. This affects the common candidate scanner used by `wcschr`, `wcsrchr`, and `wcsstr`. Exact scalar resolution inside candidate panels is unchanged.

Alien-graveyard primitive: vectorized execution plus SIMD group probing/block amortization. The larger group probe reduces horizontal-reduction frequency for long absent-candidate scans.

## Isomorphism Proof

- The candidate predicate remains exactly `ch == needle || ch == 0`.
- A clean 32-lane panel skip is equivalent to two adjacent clean 16-lane skips for the same predicate.
- `find_wide_or_nul` still resolves the first candidate panel scalar left-to-right, preserving first-candidate and NUL-before-needle ordering.
- `wcsrchr` still updates `last` scalar left-to-right inside candidate panels and returns immediately on the first NUL, preserving last-match-before-NUL semantics.
- `wcsstr` still advances by `i + 1` after a failed candidate and still stops on NUL, preserving candidate ordering and overlap behavior.
- Floating-point behavior is not involved.
- RNG behavior is not involved.

## Golden And Hash Proof

- Source before: `d15df1aea419aed7b33f8b0a64056699c9990175cd6f4e6483262ea45299482a`
- Source after: `e9e94a1c03458a08ba3651e8fa353dfdc7ca0e559450aab63dcaa599c6c94226`
- Golden command: `sha256sum -c sha256sums.txt` in `tests/conformance/golden`
- Golden before: `fixture_verify_strict_hardened.v1.md: OK`; `fixture_verify_strict_hardened.v1.json: OK`
- Golden after: `fixture_verify_strict_hardened.v1.md: OK`; `fixture_verify_strict_hardened.v1.json: OK`

## Benchmarks

Baseline command:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemchr_absent|wmemrchr_absent|wcslen|wcschr_absent|wcsrchr_absent|wcsstr_absent|wmemcmp_equal|memchr_absent|memcmp|strlen|strchr_absent|strrchr_absent|strstr_absent|strnstr_bounded_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Final benchmark command:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcsrchr_absent|wcsstr_absent|wcschr_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Final run: RCH remote `vmi1227854`, exit 0.

| Bench | Baseline p50 | Final p50 | Baseline mean | Final mean |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | `299.358` | `199.203` | `331.153` | `201.227` |
| `wcsstr_absent_4096` | `289.328` | `185.863` | `295.900` | `196.661` |
| `wcschr_absent_4096` | `265.533` | `179.304` | `268.028` | `186.338` |

The long-scan target cluster improves p50 by `1.48x` to `1.51x` and mean by `1.37x` to `1.65x`.

Small-size rows regress because the 32-lane panel is heavier for 16-element scans:

| Bench | Baseline p50 | Final p50 |
| --- | ---: | ---: |
| `wcsrchr_absent_16` | `4.599` | `11.693` |
| `wcsstr_absent_16` | `6.704` | `12.000` |
| `wcschr_absent_16` | `3.988` | `8.484` |

Keep decision: keep. The bead target was the profiled 4096-wide residual cluster, and all three target rows clear Score>=2.0.

Score: `(Impact 2.0 * Confidence 2.5) / Effort 1.0 = 5.0`.

## Validation

- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`: pass
- Local `git diff --check -- crates/frankenlibc-core/src/string/wide.rs`: pass
- RCH `cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture`: pass, 73 passed
- RCH `cargo check -p frankenlibc-core --all-targets`: pass
- RCH strict `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated peer-owned surfaces:
  - `crates/frankenlibc-core/src/malloc/allocator.rs:72`: `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/malloc/allocator.rs:78`: `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/stdlib/sort.rs:1000`: `clippy::unnecessary_cast`
- RCH lib-only clippy with only those unrelated lint classes allowed: pass
