# bd-2g7oyh.329 memcmp_4096 exact-4096 superfold rejection

Date: 2026-06-10
Agent: BoldFalcon
Scope: `crates/frankenlibc-core/src/string/mem.rs`
Commit: `d63c4532c4c7a387df5f63ddecbb3340f6634b63`

## Target

Pass-57 selected `glibc_baseline_memcmp_4096`, equal 4096-byte buffers, after
excluding peer-owned `pow*` and `strncmp` work plus recently collapsed
allocator, copy, string, and fnmatch lanes.

Pinned same-worker focused baseline from the bead:

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 53.848 | 55.943 | 64.619 | 80.443 |
| host glibc | 39.451 | 41.832 | 45.125 | 75.000 |

This was RCH worker `vmi1227854`, build `29879662679165374`, at the same
source commit as this candidate pass.

## Candidate

One safe-Rust equality-control lever was tested in a clean detached worktree
`/data/projects/frankenlibc_b329_clean_20260610T2010`:

- Add an exact `count == 4096` path.
- Scan eight 512-byte super-panels with a single accumulated SIMD inequality
  mask per super-panel.
- Return `Equal` only if all super-panels are equal.
- If a super-panel differs, resolve ordering inside that 512-byte panel using
  the existing 128-byte folded probe, then 32-byte panel order, then byte order.

This intentionally did not retry the rejected slice-equality, broadword,
64-lane rank/select, 512-loop-unroll, foldback, or per-128 XOR/test-zero
families.

## Behavior Proof

Local focused proof before the RCH post run:

```text
cargo test -p frankenlibc-core --lib memcmp -- --nocapture --test-threads=1
```

Result: passed `32` focused `memcmp` / `timingsafe_memcmp` / `wmemcmp` tests,
including the candidate-only exact-4096 first-difference boundary guard.

Additional property/golden checks:

```text
cargo test -p frankenlibc-core --test property_tests golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
cargo test -p frankenlibc-core --test property_tests prop_memcpy_then_memcmp_is_zero -- --nocapture --test-threads=1
```

Both passed. The in-module golden memcmp digest remained
`458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`.

Touched-file checks:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs
```

Both passed.

The broader filtered command
`cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1`
was blocked by unrelated pre-existing compile errors in
`strftime_buffer_differential_probe.rs` and `strftime_differential_probe.rs`
(`BrokenDownTime` initializers missing `tm_gmtoff` and `zone`).

## Observed Post

Command:

```text
RCH_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=180 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd329-post-target-20260610T2027 \
CRITERION_HOME=/data/tmp/frankenlibc-bd329-post-criterion-20260610T2027 \
cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_memcmp_4096 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`, build `29879662679165699`. A concurrent
BoldFalcon closeout audit recorded overlap with another FrankenLibC baseline
attempt and other project jobs on the same worker, so these numbers are
recorded as rejection/routing evidence only, not keep-grade A/B proof.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 52.858 | 59.267 | 87.722 | 130.000 |
| host glibc | 38.106 | 40.409 | 47.428 | 70.000 |

## Isomorphism

- Ordering preserved: yes. Any non-equal exact-4096 input returned through the
  existing ordered 128-byte, 32-byte, then byte resolver.
- First-difference tie-breaking preserved: yes. The resolver still scans lower
  offsets before higher offsets.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: unchanged by focused golden checks.

## Verdict

Rejected and restored.

The primary p50 improved only `53.848 -> 52.858 ns` (`1.8%`), while mean
regressed `55.943 -> 59.267 ns` (`5.9%`) and tails regressed materially
(`p95 64.619 -> 87.722`, `p99 80.443 -> 130.000`). Host glibc also moved faster
in the post run, so the host-normalized p50 ratio worsened from `1.365x` to
`1.387x` and the mean ratio worsened from `1.337x` to `1.467x`.

Score: `0.0`. No source was kept. The live bead closeout uses the more
conservative overlap-aware artifact
`tests/artifacts/perf/bd-2g7oyh.329-memcmp-4096-superfold-rejection.md` as the
authoritative rejection record. Restoration proof:

```text
git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs
```

passed after restoring the candidate. Restored source SHA:

```text
561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd  crates/frankenlibc-core/src/string/mem.rs
```

Next route: do not retry exact-4096 equality superfolding without codegen proof
that it removes the horizontal-reduction cost without increasing tail variance.
The remaining useful memcmp work is an RCH-compatible assembly/IR extraction
path or a genuinely different kernel shape.
