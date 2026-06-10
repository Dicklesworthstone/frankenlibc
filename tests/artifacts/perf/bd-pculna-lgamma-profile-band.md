# bd-pculna - lgamma profile-band focused gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Fresh RCH broad profiling on current `main` after the erfc closeout showed
`lgamma` as an unowned special-function residual:

```text
FrankenLibC lgamma: p50 752.000 ns, p95 not recorded in progress log, mean 801.599 ns
host glibc lgamma: p50 582.125 ns, p95 not recorded in progress log, mean 565.540 ns
```

The candidate route was deliberately structural: a proof-carrying profile-band
rational/minimax `lgamma` kernel, grounded in the existing Cephes/Moshier
special-function artifact style and dense glibc ULP replay. No source was edited
before the focused baseline.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_ENV_ALLOWLIST='CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS' \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass36-lgamma-baseline-target-20260609T231800Z \
CRITERION_HOME=/data/tmp/frankenlibc-pass36-lgamma-baseline-criterion-20260609T231800Z \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/lgamma --quiet
```

Worker: `vmi1227854`

```text
FrankenLibC lgamma: p50 492.331 ns, p95 698.690 ns, p99 3064.000 ns, mean 584.672 ns
host glibc lgamma: p50 685.719 ns, p95 6990.500 ns, p99 9111.891 ns, mean 1497.447 ns
```

## Isomorphism

No source code was changed. Ordering, tie-breaking, floating-point behavior,
errno/range handling, signgam behavior, RNG behavior, and ABI routing are
unchanged by construction.

Golden fixture sha256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

## Verdict

NO-CODE REJECTED.

The focused same-worker gate did not reproduce the broad-profile gap. On this
run FrankenLibC was faster than host glibc by `1.39x` p50 and `2.56x` mean, so a
profile-band `lgamma` source edit would violate the profile-backed edit rule.

Score: `0.0`.

Next route: reprofile/route to a different reproduced residual. If `lgamma`
becomes hot again under a material focused same-worker gap, the next admissible
candidate remains a generated proof-carrying minimax/rational artifact with dense
glibc ULP replay over the exact hot interval.
