# bd-2g7oyh.394 fnmatch rightmost literal absence certificate

Date: 2026-06-13
Agent: BoldFalcon
Status: kept

## Target

`glibc_baseline_fnmatch_bracket/fnmatch_bracket`

Workload:

- pattern: `*[ab]*[ab]*[ab]*[ab]*[ab]*c`
- text: `ababababababababab`
- flags: `FnmatchFlags::NONE`
- expected result: no match

Post-close RCH broad profile on `vmi1227854` showed a renewed residual:

- FrankenLibC p50/mean: `117.981 / 119.204 ns`
- host glibc p50/mean: `79.438 / 85.197 ns`

Prior fnmatch broad rows had collapsed under focused gates, so this bead required
a fresh same-worker baseline before source changes.

## Focused Baseline

Command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd394-fnmatch-baseline-target-20260613T2240 \
CRITERION_HOME=/data/tmp/frankenlibc-bd394-fnmatch-baseline-criterion-20260613T2240 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_fnmatch_bracket --noplot --sample-size 80 \
--warm-up-time 1 --measurement-time 4
```

RCH selected `vmi1227854`.

| implementation | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[113.16, 117.18, 121.21]` | `104.168` | `108.159` | `144.294` | `156.420` |
| host glibc | `[81.385, 85.277, 89.358]` | `82.337` | `86.238` | `119.195` | `125.909` |

Focused gap reproduced: `1.27x` p50 / `1.25x` mean.

## Lever

One source lever in `crates/frankenlibc-core/src/string/fnmatch.rs`:

- Add `required_plain_literal_absent_flags_none`.
- It runs only when `flags == FnmatchFlags::NONE`.
- It scans pattern tokens and returns no-match early only when a plain literal
  outside a simple closed bracket is absent from the text.
- It skips `*` and `?`, treats `\X` as required literal `X`, skips only simple
  brackets such as `[ab]` / `[!ab]`, and refuses to certify complex or
  parity-sensitive bracket syntax (`[]...]`, nested `[[:class:]]`, escapes,
  unterminated brackets), falling back to the existing matcher.

The harvested primitive is a pattern-matching necessary-literal prefilter: a
safe-Rust, certificate-style branch that proves a no-match before entering the
existing backtracking loop. This avoids another local bracket parser tweak and
leaves the authoritative matcher in control whenever the certificate is not
trivial.

## Isomorphism Proof

Ordering and tie-breaking:

- The new path only returns `false` when a literal required by the pattern is
  absent from the entire text.
- All successful matches and all uncertain no-match cases fall through to the
  existing matcher, preserving its left-to-right wildcard, bracket, escape, and
  trailing-star semantics.

Flag semantics:

- `PATHNAME`, `PERIOD`, `CASEFOLD`, `LEADING_DIR`, `NOESCAPE`, and `EXTMATCH`
  are unchanged by construction because the prefilter is gated to
  `FnmatchFlags::NONE`.

Bracket semantics:

- Simple bracket contents are skipped as a whole.
- POSIX classes, collating/equivalence elements, escaped bracket contents,
  first-content `]`, and malformed brackets do not participate in the
  certificate and continue through the existing parser.

Floating-point and RNG:

- Not involved.

Golden output:

- RCH `vmi1227854`:
  `cargo test -j 1 -p frankenlibc-core --lib golden_fnmatch_required_literal_corpus_sha256 -- --nocapture --test-threads=1`
- Passed 1/1.
- SHA-256:
  `6d4feb0c1506b8790756bd7cead949644dbb5d9f50feda15b1b17347fc0d048a`

Direct prefilter proof:

- RCH `vmi1227854`:
  `cargo test -j 1 -p frankenlibc-core --lib required_plain_literal_prefilter -- --nocapture --test-threads=1`
- Passed 2/2:
  - `required_plain_literal_prefilter_is_conservative`
  - `required_plain_literal_prefilter_matches_simple_on_short_none_corpus`

Live glibc differential proof:

- RCH `vmi1227854`:
  `cargo test -j 1 -p frankenlibc-abi --test fnmatch_differential_fuzz fnmatch_differential_fuzz_vs_glibc -- --nocapture --test-threads=1`
- Passed 1/1.
- `200000` randomized comparisons, `0` divergences vs host glibc.

## Validation

- RCH `vmi1227854`:
  `cargo check -j 1 -p frankenlibc-core --lib`
- Passed. Existing unrelated warnings remain in `math/float32.rs` and
  `math/special.rs`; no warning points at the touched fnmatch code.
- `git diff --check -- crates/frankenlibc-core/src/string/fnmatch.rs`: passed.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/fnmatch.rs`
  is blocked by pre-existing formatting differences in older `fnmatch.rs`
  functions. A temporary rustfmt run introduced formatter-only churn; it was
  manually reverted so this commit remains additions-only for the actual lever.

## Same-worker Post Benchmark

Exact final diff command:

```bash
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd394-fnmatch-final-post-target-20260613T2309 \
CRITERION_HOME=/data/tmp/frankenlibc-bd394-fnmatch-final-post-criterion-20260613T2309 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_fnmatch_bracket --noplot --sample-size 80 \
--warm-up-time 1 --measurement-time 4
```

RCH selected `vmi1227854`.

| implementation | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[26.765, 27.532, 28.378]` | `30.835` | `33.574` | `39.406` | `65.000` |
| host glibc | `[90.779, 94.350, 98.022]` | `100.948` | `105.878` | `135.647` | `150.695` |

Improvement:

- FrankenLibC p50: `104.168 -> 30.835 ns` (`3.38x` faster)
- FrankenLibC mean: `108.159 -> 33.574 ns` (`3.22x` faster)
- Final FrankenLibC vs host: `3.27x` faster by p50, `3.15x` faster by mean

## Verdict

Kept. Score `12.5` (`Impact 5 x Confidence 5 / Effort 2`).

Next route: reprofile on current head. If `fnmatch` reappears, avoid extending
this narrow certificate into complex bracket syntax; the next deeper primitive
should be a compiled-token or automaton-style matcher with live glibc
differential coverage. Otherwise move to the next reproduced no-gaps residual.
