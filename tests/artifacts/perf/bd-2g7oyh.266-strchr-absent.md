# bd-2g7oyh.266 - strchr_absent 4096-byte residual

## Target

- Bead: `bd-2g7oyh.266`
- Symbol/workload: `strchr`, 4096-byte scan for absent byte
- Runtime mode: strict
- Profile basis: pass-13 post-close broad RCH profile showed residual string scan rows; focused RCH baseline on `vmi1153651` confirmed `strchr_absent` was slower than host glibc.

## Lever

Replace the old combined `find_byte_or_nul(s, c)` path for `strchr(c != 0)` with a two-phase safe-Rust search:

1. Use the existing optimized `memchr(s, c, s.len())` to locate the first candidate needle.
2. If a candidate exists, scan only the prefix before that candidate for `NUL`.

This is a single structural lever: first-needle broad scan plus prefix certification. `strchrnul`, `strrchr`, and the SIMD helper bodies are unchanged.

## Baseline

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd266-clean-baseline-rch \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strchr_absent --noplot --sample-size 35 \
  --warm-up-time 1 --measurement-time 2
```

Worker/source:

- Worker: `vmi1153651`
- Source: clean detached worktree `/data/projects/frankenlibc-bd266-clean-baseline`
- Commit: `1a5e94fc`

Rows:

| Impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 95.336 | 135.997 | 166.980 | 105.993 |
| host glibc | 72.750 | 123.544 | 231.000 | 92.375 |

## Post-benchmark

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd266-post-rch \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strchr_absent --noplot --sample-size 35 \
  --warm-up-time 1 --measurement-time 2
```

Worker/source:

- Worker: `vmi1153651`
- Source: patched worktree `/data/projects/frankenlibc-pass13-profile-20260608-1052`

Rows:

| Impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 57.950 | 161.145 | 377.088 | 86.293 |
| host glibc | 92.951 | 210.000 | 1430.927 | 154.499 |

Delta:

- FrankenLibC p50: `95.336 -> 57.950 ns` (`39.2%` faster)
- FrankenLibC mean: `105.993 -> 86.293 ns` (`18.6%` faster)
- FrankenLibC p95/p99: noisy tail worsened in this run; host glibc tail also widened materially on the same worker/run. Keep decision is based on p50/mean and host-normalized ratio, with the tail caveat retained here.
- FL/host p50 ratio: `1.31x slower -> 0.62x` of host, i.e. FL faster on post p50.
- FL/host mean ratio: `1.15x slower -> 0.56x` of host, i.e. FL faster on post mean.

Additional cross-worker candidate smoke benchmark:

- Worker: `vmi1167313`
- FrankenLibC p50/mean/p99: `53.155 / 57.079 / 134.037 ns`
- host glibc p50/mean/p99: `63.804 / 68.018 / 141.000 ns`

## Behavior proof

Golden/proof command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd266-strchr-proof-rch \
  cargo test -p frankenlibc-core chr -- --nocapture --test-threads=1
```

Result:

- Worker: `vmi1167313`
- Status: passed
- Golden SHA-256 for `strchr`: `3656ba0841f975b7aa6d31cf8a01cac9b90635e6eecf66431ce80893bd859f18`
- Golden SHA-256 for `strrchr`: `a2d88c8fc144d9705080a44619c97736b57b2199a5425ea5b9367fe16c606afb`

Isomorphism:

- `c == 0`: new `strlen(s)` returns the first `NUL` index or `s.len()`, identical to old `find_byte_or_nul(s, 0)`.
- `c != 0`, no needle anywhere: new `memchr` returns `None`, identical to old first-of-needle-or-`NUL` path returning no found needle.
- `c != 0`, first needle before any `NUL`: new `memchr` returns the first needle and the prefix-`NUL` check is empty/negative, so `Some(first_needle)` is preserved.
- `c != 0`, `NUL` before a hidden later needle: new first-needle scan may observe the hidden later needle, but the prefix-`NUL` check returns positive and maps the result to `None`, preserving C-string observability.
- Ordering/tie-breaking: preserved by `memchr`'s first-position contract and the prefix certification.
- Floating-point: N/A.
- RNG: N/A.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed.
- RCH `cargo check -p frankenlibc-core --lib`: passed on `vmi1153651`.
- RCH `cargo clippy -p frankenlibc-core --lib -- -D warnings -A dead_code -A clippy::excessive_precision -A clippy::unnecessary_unwrap -A clippy::collapsible_if -A clippy::unnecessary_map_or`: passed on `vmi1167313`.
- Known warnings unrelated to this lever: missing SMT solver during stdio synthesis; existing `string/regex.rs` dead-code warning in bench builds.

## Score

| Impact | Confidence | Effort | Score |
| ---: | ---: | ---: | ---: |
| 4.0 | 3.0 | 1.0 | 12.0 |

Verdict: keep. The p50 and mean win is large on same-worker evidence, behavior is byte-for-byte covered by the existing golden transcript, and the lever replaces a combined byte-or-NUL scan with a structurally different first-needle plus prefix-certificate primitive.
