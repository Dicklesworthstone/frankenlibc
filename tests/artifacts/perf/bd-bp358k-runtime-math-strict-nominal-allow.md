# bd-2g7oyh.400 - strict nominal runtime-math Allow shortcut

Date: 2026-06-14
Agent: BoldFalcon
Scope: `RuntimeMathKernel::decide` strict-mode nominal pointer hot path

## Target

- Bead: `bd-2g7oyh.400`
- Lineage: follow-up to already-closed `bd-bp358k`, which was closed by a
  separate `atoi` ownership-probe lever while this runtime-kernel proof was
  running.
- Profile row: `runtime_math_decide_resample_free/strict`
- Source surface: `crates/frankenlibc-membrane/src/runtime_math/mod.rs`
- Problem: the strict runtime decision kernel is paid by tiny libc ABI calls.
  The prior full path aggregates many cached runtime controllers even when the
  context is nominal and the final decision is the default `Fast + Allow`.

## Baseline

Command:

```bash
RCH_FORCE_REMOTE=true RCH_REQUIRE_REMOTE=1 \
  RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN,FRANKENLIBC_MODE \
  RCH_WORKER=vmi1156319 RCH_WORKERS=vmi1156319 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_MODE=strict FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-bp358k-baseline-vmi1156319-target-20260614T0535 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-bp358k-baseline-vmi1156319-criterion-20260614T0535 \
  cargo bench -j 1 -p frankenlibc-bench --bench runtime_math_kernels_bench -- \
  runtime_math_decide_resample_free --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected worker `vmi1227854` from detached clean baseline worktree
`/data/projects/.scratch/frankenlibc-bd-bp358k-baseline2-20260614T0522`.

| row | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | `[121.18 ns 124.69 ns 128.34 ns]` | `118.100` | `117.337` | `138.008` | `162.177` |

## Candidate

One source lever:

- Add `try_strict_nominal_allow_decision` immediately after the existing
  resample cadence gate and before the hardened-only shortcut.
- The shortcut only fires for `SafetyLevel::Strict`,
  `ApiFamily::PointerValidation`, `requested_bytes == 0`, `is_write == false`,
  `bloom_negative == false`, `contention_hint == 0`, feedback disabled, no
  policy table, no cached risk/anomaly/pressure escalation, and no exhausted
  Pareto budget.
- It is disabled for sequences `<=4`, multiples of `16`, `512`, `4096`, and
  `16384`, preserving the existing router, Sobol/design, runtime-controller,
  and evidence cadences.
- It reuses the same base risk plus design-bonus calculation and the same
  `barrier.admissible(..., Fast, ...)` check as the normal default branch.
- It emits the same externally visible decision shape as the normal nominal
  branch: `profile=Fast`, `action=Allow`, `policy_id=compute_policy_id(...)`,
  `evidence_seqno=0`, `cached_policy_action_dist[Allow] += 1`, and normal
  mode/family/profile/action telemetry.

## Post Benchmark

Command:

```bash
RCH_FORCE_REMOTE=true RCH_REQUIRE_REMOTE=1 \
  RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN,FRANKENLIBC_MODE \
  RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_MODE=strict FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-bp358k-post-vmi1227854-target-20260614T0546 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-bp358k-post-vmi1227854-criterion-20260614T0546 \
  cargo bench -j 1 -p frankenlibc-bench --bench runtime_math_kernels_bench -- \
  runtime_math_decide_resample_free --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1227854`.

| row | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| candidate | `[114.96 ns 117.20 ns 119.40 ns]` | `113.809` | `110.399` | `127.537` | `129.761` |

Same-worker deltas:

- p50: `118.100 -> 113.809 ns` (`3.6%` faster)
- mean: `117.337 -> 110.399 ns` (`5.9%` faster)
- p95: `138.008 -> 127.537 ns` (`7.6%` faster)
- p99: `162.177 -> 129.761 ns` (`20.0%` faster)

Score: `(Impact 2 * Confidence 4) / Effort 4 = 2.0`. Kept because the row is
the direct runtime-kernel tax paid by many tiny ABI calls and the same-worker
tail improvement is larger than the p50 movement.

## Behavior Proof

Golden decision output:

```text
bd-bp358k strict-nominal-pointer-decision-v1
mode=strict
family=PointerValidation
ctx=requested_bytes:0,is_write:false,bloom_negative:false,contention_hint:0
sequence_guard=not(<=4|%16|%512|%4096|%16384)
profile=Fast
action=Allow
policy_id=compute_policy_id(strict,PointerValidation,Fast,Allow)
risk_upper_bound_ppm=base+design_bonus<full_validation_trigger
evidence_seqno=0
telemetry=allow_action_dist+1,mode/family/profile/action+1
```

Golden output SHA-256:

```text
3a13c577e25273ef1dee7e3df7459a83ddc284328de935640f4150234670e435
```

Isomorphism:

- Ordering/tie-breaking: no ordered data search is changed. The shortcut is a
  decision-control path only.
- Floating point: the strict hot path remains integer/atomic only. The shortcut
  performs no floating-point operations and is disabled at all monitor cadence
  points that may execute heavier controller work.
- RNG: no RNG state is read or mutated.
- Evidence: nominal strict `Allow` decisions still have `evidence_seqno=0`.
  Evidence cadence at sequence multiples of `16384` remains on the normal path.
- Risk/admissibility: shortcut returns only when all cached escalation states
  are default, risk is below the strict full-validation trigger, Pareto budget
  is not exhausted, and the barrier admits the `Fast` profile.
- Escalation preservation: hardened mode, writes, requested bytes, bloom-negative
  contexts, contention, policy tables, feedback mode, non-nominal pressure,
  anomaly states, high risk, cadence sequences, and SOS/approachability/
  localization escalation all fall through to the existing decision cascade.

## Validation

Passed:

```bash
RCH_FORCE_REMOTE=true RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-bp358k-check-vmi1227854-target-20260614T0552 \
  cargo check -j 1 -p frankenlibc-membrane --lib
```

Passed:

```bash
cargo fmt --package frankenlibc-membrane -- --check
```

Passed:

```bash
RCH_FORCE_REMOTE=true RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 \
  rch exec -v -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-bp358k-clippy2-vmi1227854-target-20260614T0608 \
  cargo clippy -j 1 -p frankenlibc-membrane --lib -- -D warnings
```

Blocked before test execution:

```bash
RCH_FORCE_REMOTE=true RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-bp358k-test-vmi1227854-target-20260614T0556 \
  cargo test -j 1 -p frankenlibc-membrane strict_nominal_pointer_shortcut --lib -- --nocapture
```

Failure reason: Cargo failed while compiling packaged
`asupersync-conformance 0.3.4` because the crate archive is missing
`artifacts/conformance_registry_contract_v1.json` and
`src/raptorq/rfc6330_systematic_index_table.inc`. The focused tests did not run.

Full `cargo fmt --check` is not a valid gate in the shared checkout because
unrelated ABI/core files and untracked scratch tests are already unformatted.

## Decision

KEPT.

Do not broaden this shortcut to writes, bloom-negative/untracked contexts,
requested-byte validations, hardened mode, or cadence sequences without a fresh
decision-stream proof and same-worker benchmark.
