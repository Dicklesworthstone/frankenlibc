# Raw harness output, 2026-08-16

Unedited stdout from `incumbent_coverage_ab`, kept because the summarised tables
in the ledger drop the provenance lines a reader needs to judge them:
`BENCH_ELF_OBJECT`, `INCUMBENT_OBJECT`, `FL_OBJECT`, `ARM_DISTINCT`, the
pre/post `BENCH_HOST_WIDE_EXCLUSIVITY` verdicts, and every
`INCUMBENT_COVERAGE_CONTRACT` line with its A/A nulls and bootstrap CIs.

| file | what it is |
|---|---|
| `sscanf-family-prechange.log` | 12-case sscanf family, fl object `fd2c8e8b…`, BEFORE the engine-allocation removal. The row set the current target (`string_token` 2.238x) and dated the stale `long_string` 2.387x row. |
| `sinhf-coshf-base.log` | sinhf/coshf, fl object `fd3f5f7e…`, BEFORE coshf was delegated to the f64 kernel. `coshf` effect median 2.026995, `worst_coshf_ulp=1`. |
| `sinhf-coshf-candidate.log` | same, fl object `fd2c8e8b…`, AFTER. `coshf` effect median 1.763953, `worst_coshf_ulp=0`. |
| `sscanf-cert-base-VOID.log` / `sscanf-cert-candidate-VOID.log` | An attempt to certify the scanf allocation removals. **VOID — do not quote any ratio from these.** Both arms report exclusivity `verdict=clear` and every same-invocation A/A null holds, yet `single_int` and `two_ints` — cases served by the decimal-int fast path, which the change cannot touch — moved +16.9% and +13.4%. The launch context shows why: base at cpu8 4119585 kHz under loadavg 17.29, candidate at 2515185 kHz under 32.46. Kept as the worked example of a guard passing while the comparison is still invalid. |

Reproduce:

```
cargo build --profile release-perf -p frankenlibc-abi --lib
cargo build --profile release-perf -p frankenlibc-bench --features abi-bench \
    --example incumbent_coverage_ab
taskset -c 8 target/release-perf/examples/incumbent_coverage_ab \
    --family sscanf --fl-so <path-to-libfrankenlibc_abi.so>
taskset -c 8 target/release-perf/examples/incumbent_coverage_ab \
    --family sinhf_coshf --fl-so <path-to-libfrankenlibc_abi.so>
```

Two traps these logs exist to prevent, both of which cost a run on the day:

- **Do not filter the harness through `head`.** The first sinhf/coshf attempt
  piped each arm through `head -14`; that dropped every `coshf` row and read as
  "the harness does not measure coshf" rather than as truncation.
- **Read a control case before believing a treated one.** A cross-invocation A/B needs cases the
  change cannot affect; if those move, the run is void no matter how clean the nulls and the
  exclusivity verdict look. The two VOID logs above are that failure, caught only because
  `single_int` and `two_ints` bypass the engine entirely.
- **Do not compare across hosts.** The sscanf log is `thinkstation1`; the older
  2.387x `long_string` row is `hz1`. Ratios from different hosts are not
  comparable, and in this case the newer host also carries a fix the older row
  predates.

The `.so` files these logs name are NOT stored here — they are 38 MB each.
Rebuild from the commit named in the corresponding ledger row; the harness
self-reports the object's SHA-256 in every run, so a rebuild can be checked
against the log rather than assumed.
