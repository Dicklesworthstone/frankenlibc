# bd-2g7oyh stdio membrane A/B and `snprintf` exact-format fast path

Agent: cod-a / BlackThrush
Date: 2026-06-20
Target dir: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a`

## Scope

Target: deployed `snprintf("%s")` / `snprintf("%s\n")` gaps against real host
glibc.

The host arm must resolve `snprintf` with `dlmopen(LM_ID_NEWLM, "libc.so.6")`.
Plain `libc::snprintf` is not a valid denominator in this crate because
FrankenLibC exports the same symbol and can shadow the benchmark's host arm.

## Negative Evidence: Stdio Runtime-Policy Consult

Hypothesis: adding `ApiFamily::Stdio` to the strict high-frequency family sets
would skip a cold runtime-kernel consult and remove the deployed `snprintf`
loss.

Result: rejected and reverted. A 6-run controlled A/B showed no stable benefit:
WITH-fix fl/glibc ratios `19.8x`, `22.4x`, `23.0x`; WITHOUT-fix `34.4x`,
`19.7x`, `16.7x`. The distributions overlap and the median slightly favors the
no-fix arm (`19.7x` vs `22.4x`). The consult cost is below this benchmark's
noise floor.

Retry predicate: do not re-add `Stdio` to the strict runtime-policy fast-path
sets for perf without a lower-variance stdio bench that can resolve sub-50 ns
effects.

## Kept Lever: Exact `%s` / `%s\n` Parser Bypass

The shipped change recognizes exact `"%s"` and `"%s\n"` before parsing format
segments or extracting a full argument plan. It copies directly into the
bounded destination, preserves the existing hardened repair behavior, emits the
same `runtime_policy::observe` telemetry, and returns the POSIX total output
length.

Same-worker A/B on `vmi1293453`, Criterion filter `snprintf_s`:

| Workload | Fast path enabled | Fast path disabled | FL self ratio | glibc in enabled run | Final FL/glibc |
|---|---:|---:|---:|---:|---:|
| `snprintf("%s\n")` | 615.58 ns | 785.41 ns | 0.784x | 65.319 ns | 9.424x |
| `snprintf("%s")` | 679.92 ns | 1.1712 us | 0.581x | 88.771 ns | 7.659x |

Verdict: keep as a measured FrankenLibC self-win, but do not count it as a
glibc win. The deployed `snprintf` surface remains 7.7-9.4x slower than real
glibc even after the direct path.

## Commands

```bash
AGENT_NAME=BlackThrush RCH_WORKER=vmi1293453 RCH_PREFERRED_WORKER=vmi1293453 \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench stdio_glibc_baseline_bench snprintf_s -- --noplot
```

Validation:

- `rch exec -- cargo test -p frankenlibc-abi --test conformance_diff_printf_fastpaths -- --nocapture`
  fell back to local because no workers were admissible; the full focused file
  passed 3/3 (`pure_literal_fastpath_matches_glibc`,
  `bare_f_fastpath_matches_glibc`, `bare_s_fastpath_matches_glibc`).
- `cargo check -p frankenlibc-abi --all-targets` remains blocked by pre-existing `zz_scratch_divmin` integration-test trait errors.
- `cargo fmt --check` remains blocked by broad pre-existing formatting drift; no mass rustfmt was applied.

## Next Route

The remaining loss is the printf architecture: variadic extraction, segment
parse, and TLS entrypoint machinery. The next useful lever is a generated or
table-driven exact-format printf mini-JIT/specializer for the hot format set,
benchmarked through the `dlmopen` host arm. Another runtime-policy-family tweak
is not a credible route.
