# bd-3kqk9k - exp10 focused compensated-kernel gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Fresh RCH broad profiling on current `main` after the erfc closeout showed
`exp10` as an unowned special-function residual:

```text
FrankenLibC exp10: p50 388.790 ns, mean 487.716 ns
host glibc exp10: p50 330.929 ns, mean 355.301 ns
```

The existing implementation is already a compensated `exp2(x * log2(10))`
route with exact integer handling and dense 4-ULP glibc oracle coverage. The
next candidate would therefore need to be a different generated profile-band
table/minimax artifact, not another tweak to the same reduction path. No source
was edited before the focused baseline.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_ENV_ALLOWLIST='CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS' \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass37-exp10-baseline-target-20260609T232500Z \
CRITERION_HOME=/data/tmp/frankenlibc-pass37-exp10-baseline-criterion-20260609T232500Z \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/exp10 --quiet
```

Worker: `vmi1227854`

```text
FrankenLibC exp10: p50 339.875 ns, p95 501.000 ns, p99 931.000 ns, mean 373.926 ns
host glibc exp10: p50 340.022 ns, p95 393.856 ns, p99 430.000 ns, mean 344.600 ns
```

The criterion filter also matched `exp10f`; it was not this bead's target, but
it confirms the f32 row is not a same-worker edit target on this run:

```text
FrankenLibC exp10f: p50 330.577 ns, p95 501.918 ns, p99 891.000 ns, mean 341.376 ns
host glibc exp10f: p50 334.154 ns, p95 552.776 ns, p99 644.821 ns, mean 368.395 ns
```

## Isomorphism

No source code was changed. Exact integer handling, range fallback, floating
point results, ordering/tie-breaking, errno behavior, RNG behavior, and ABI
routing are unchanged by construction.

Golden fixture sha256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

## Verdict

NO-CODE REJECTED.

The focused same-worker gate did not reproduce a material `exp10` gap. The p50
is parity (`339.875 ns` vs `340.022 ns`); the mean delta is only `1.09x` and
does not justify a source edit under the Score>=2.0 gate.

Score: `0.0`.

Next route: reprofile/route to a different reproduced residual. If `exp10`
reappears with a material focused same-worker gap, the next admissible candidate
is a generated profile-band table/minimax artifact with dense 4-ULP glibc replay
and exact integer semantics preserved.
