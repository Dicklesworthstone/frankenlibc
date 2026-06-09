# bd-2g7oyh.280 memcmp_256 foldback rejection

Date: 2026-06-09
Worker: `vmi1227854`
Scope: `crates/frankenlibc-core/src/string/mem.rs`

## Target

Pass-24 target: `glibc_baseline_memcmp_256`, equal 256-byte buffers.

Bead basis after pass 23 selected `memcmp_256` as the next unowned clean residual:
FrankenLibC p50 `5.369 ns`, host glibc p50 `3.425 ns`.

## Candidate

Replace the exact-256 four-64-lane inequality certificate with two calls to the
existing 128-byte folded 32-lane certificate.

This candidate was behavior-isomorphic: both forms compute "any byte differs in
bytes 0..256". Non-equal buffers still fall through to the existing ordered
32-byte panel resolver, so first-difference ordering and unsigned-byte sign are
unchanged. Floating-point and RNG are not involved.

Risk noted before benchmarking: this effectively backs out the earlier
`bd-2g7oyh.161` four-64-lane keep, so it requires current same-worker evidence
that today's compiler/worker mix favors the older two-128 form.

## Same-worker baseline

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd280-baseline-rch-target \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_256 --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC: p50 `4.499 ns`, p95 `7.500 ns`, p99 `25.000 ns`, mean `5.590 ns`.
- host glibc: p50 `3.483 ns`, p95 `8.750 ns`, p99 `35.000 ns`, mean `4.575 ns`.

## Candidate post

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd280-candidate-rch-target \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_256 --noplot --sample-size 60 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC: p50 `4.930 ns`, p95 `8.125 ns`, p99 `30.000 ns`, mean `6.174 ns`.
- host glibc: p50 `3.364 ns`, p95 `6.250 ns`, p99 `30.000 ns`, mean `4.478 ns`.

## Verdict

Rejected and restored.

- p50 regressed `4.499 -> 4.930 ns` (`9.6%` slower).
- mean regressed `5.590 -> 6.174 ns` (`10.4%` slower).
- p95 regressed `7.500 -> 8.125 ns`.

Score: `0.0`.

No source kept. `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs`
is the restoration proof. Golden behavior is unchanged by construction.

Do not retry exact-256 foldback/two-128 replacement, 64-lane rank/select,
large folded equality certificates, broadword equality probes, or inline-only
memcmp levers without a fundamentally different proof-backed primitive.
