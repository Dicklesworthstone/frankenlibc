# bd-2g7oyh.261 - strrchr_absent 256-byte folded reverse-scan residual

## Target

- Bead: `bd-2g7oyh.261`
- Profile-backed row: `glibc_baseline_strrchr_absent`
- Retained source profile: `/data/tmp/frankenlibc-pass12-profile`
  - FrankenLibC p50 105.851 ns, mean 105.103 ns
  - Host glibc p50 85.786 ns, mean 85.728 ns
- Broad pre-edit reprofile on `ts2`
  - FrankenLibC p50 64.307 ns, mean 68.241 ns
  - Host glibc p50 55.179 ns, mean 58.739 ns

## One Lever

`strrchr` now uses the existing 256-byte `has_byte_or_nul_simd_folded_256`
certificate for the forward scan that tracks the last matching byte before the
terminating NUL. The scalar resolution inside a flagged block is unchanged. The
`c == 0` branch is unchanged.

The private 128-byte helper that was only used by this path was removed to keep
the code warning-free after the lever.

## Baseline

Clean detached baseline worktree:
`/data/projects/frankenlibc-bd261-clean-baseline`

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd261-clean-baseline-rch2 \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strrchr_absent --noplot --sample-size 35 \
  --warm-up-time 1 --measurement-time 2
```

Same-worker baseline on `vmi1153651`:

- FrankenLibC p50 106.564 ns, p95 172.407 ns, p99 305.660 ns, mean 118.650 ns
- Host glibc p50 97.389 ns, p95 156.044 ns, p99 165.264 ns, mean 106.552 ns
- FL/host p50 ratio: 1.094x

Earlier clean baseline on `vmi1156319`:

- FrankenLibC p50 97.780 ns, p95 155.000 ns, p99 255.842 ns, mean 105.994 ns
- Host glibc p50 82.129 ns, p95 119.346 ns, p99 123.543 ns, mean 88.688 ns

## Post

Clean detached candidate worktree:
`/data/projects/frankenlibc-bd261-clean-proof`

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd261-clean-post-rch \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strrchr_absent --noplot --sample-size 35 \
  --warm-up-time 1 --measurement-time 2
```

Post on `vmi1153651`:

- FrankenLibC p50 94.945 ns, p95 200.191 ns, p99 260.063 ns, mean 112.025 ns
- Host glibc p50 92.525 ns, p95 166.559 ns, p99 219.961 ns, mean 104.918 ns
- FL/host p50 ratio: 1.026x

Same-worker delta:

- FrankenLibC p50: 106.564 -> 94.945 ns, 10.9% faster
- FrankenLibC mean: 118.650 -> 112.025 ns, 5.6% faster
- FrankenLibC p99: 305.660 -> 260.063 ns, 14.9% faster
- FrankenLibC p95: 172.407 -> 200.191 ns, regressed under the noisy tail
- FL/host p50 ratio: 1.094x -> 1.026x

## Behavior Proof

RCH proof command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd261-clean-proof-rch3 \
  cargo test -p frankenlibc-core strrchr -- --nocapture --test-threads=1
```

Proof worker: `vmi1153651`

Result: passed. The run covered the existing `strrchr` tests, the property
`string_properties::prop_strchr_strrchr_both_find_or_miss`, and the new golden
transcript test.

Golden transcript SHA-256:
`a2d88c8fc144d9705080a44619c97736b57b2199a5425ea5b9367fe16c606afb`

Isomorphism:

- Ordering/tie-breaking: preserved by resolving every flagged 256-byte block
  left-to-right and updating `last` exactly as the prior scalar block resolver
  did.
- Terminator behavior: the first NUL still returns the last match observed
  before it; matches after the first NUL remain ignored.
- NUL needle behavior: unchanged `c == 0` fast branch returns `strlen(s)`.
- Unterminated behavior: unchanged tail scan returns the last byte match or
  `Some(s.len())` for `c == 0`.
- Floating point: not applicable.
- RNG: not applicable.

## Validation

- RCH `cargo check -p frankenlibc-core --lib` passed on `vmi1167313`.
- The only check warning was the existing missing-SMT-solver build warning.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`
  passed.
- Strict RCH `cargo clippy -p frankenlibc-core --lib -- -D warnings` on
  `vmi1153651` was blocked by existing non-strrchr lints in `math/exp.rs`,
  `stdio/file.rs`, `stdlib/sort.rs`, and `string/regex.rs`.
- RCH clippy with only those known lint families allowlisted passed on
  `vmi1167313`, confirming no new clippy class from the strrchr lever.

## Keep Gate

Score = Impact 3 * Confidence 3 / Effort 2 = 4.5

Verdict: kept. Same-worker p50, mean, p99, and FL/host p50 ratio improved with
the exact strrchr golden transcript unchanged.
