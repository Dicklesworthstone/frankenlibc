# bd-2g7oyh.427 strpbrk_absent focused no-code closeout

Date: 2026-06-15

## Target

Profile target ID: `bd-2g7oyh.427`

`bd-2g7oyh.427` targeted `glibc_baseline_strpbrk_absent`, a 4096-byte
NUL-terminated scan with an 8-byte accept set absent from the haystack.

Broad routing evidence from the pass 128 remote-only RCH profile on `ovh-a`
at current head `95ad42678`:

- FrankenLibC: p50 `345.656 ns/op`, mean `346.324 ns/op`
- host glibc: p50 `274.750 ns/op`, mean `276.889 ns/op`

Broad profile command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 \
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass126-broad-target-20260615T2050 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass126-broad-criterion-20260615T2050 \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- --noplot \
  --sample-size 40 --warm-up-time 1 --measurement-time 2
```

## Focused RCH Gate

Focused command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 \
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass126-strpbrk-target-20260615T2059 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass126-strpbrk-criterion-20260615T2059 \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_strpbrk_absent \
  --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Focused result on `ovh-a`:

- FrankenLibC Criterion: `[163.62 ns 164.40 ns 165.12 ns]`
- FrankenLibC row: p50 `163.997 ns/op`, mean `165.810 ns/op`, p95 `168.757 ns/op`, p99 `200.089 ns/op`
- host glibc Criterion: `[182.57 ns 183.21 ns 183.84 ns]`
- host glibc row: p50 `182.486 ns/op`, mean `190.126 ns/op`, p95 `268.000 ns/op`, p99 `290.500 ns/op`

## Verdict

No-code rejected, Score `0.0`.

The focused same-worker gate reversed the broad row: FrankenLibC is faster than
host by p50 and mean. A source edit would violate the profile-backed target
rule because there is no current focused vs-upstream gap to close.

The next admissible `strpbrk_absent` attack is not another surface branch or
folded-panel tweak. If a future focused gate reproduces a material residual,
route to a materially different primitive: sparse accept-set classification,
generated codegen/disassembly proof, or a backend-dispatch artifact with golden
output replay.

## Behavior Proof

No production source was edited.

Source hashes:

- `crates/frankenlibc-core/src/string/str.rs`: `18b74ea99e080c8c87e4f73914fcb0250645a6f3687f23bd446c76206ebbabc4`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `c506824bbc9d1919cb2143c307a583ba053d405214d76611eec3e34e0e71adc0`

Isomorphism:

- ordering/tie-breaking: unchanged by construction; `strpbrk` still returns the first haystack byte whose value is in the accept set before NUL
- NUL behavior: unchanged by construction; absent accept bytes before the terminal NUL still return `None`
- floating-point: N/A
- RNG: not used
- allocation/errno/locale: unchanged by construction
- golden output: no generated output changed; existing string conformance and ABI differential contracts remain the active behavior proof

## Tracker Note

The local `br create --parent bd-2g7oyh` attempt in the detached worktree tried
to allocate stale numeric children `bd-2g7oyh.424` and `.425`, which already
refer to current-history perf closeouts. Those JSONL additions were removed
before commit; `.beads/issues.jsonl` is intentionally unchanged in this pass.
