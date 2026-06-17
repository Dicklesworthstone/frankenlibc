# bd-2g7oyh.451 current-head local routing profile

Pass: 168
Agent: BoldFalcon
Date: 2026-06-17
Mode: local cargo/Criterion because `ts1`/remote RCH is offline

## Command

```bash
env AGENT_NAME=BoldFalcon \
  RCH_REQUIRE_REMOTE=0 \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass168-routing-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass168-routing-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'memset_4096|strlen_4096|memmove_4096|strcpy_4096|memcmp_256|memcmp_4096|memchr_absent|printf_g_6|powf_irrational|exp10|/log' \
  --noplot --sample-size 50 --warm-up-time 0.5 --measurement-time 2
```

Log:

```text
/data/tmp/frankenlibc-pass168-routing.log
sha256 5d0f51399d644a9241ca932b3772918c33287d99be3089a091bba6493c61723f
```

The saved log is complete. A later duplicate broad sweep was interrupted and
discarded; this artifact uses the completed filtered run above.

## Route Table

| row | FL p50 ns | host p50 ns | p50 ratio | FL mean ns | host mean ns | mean ratio | route |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `strcpy_4096` | `72.400` | `42.785` | `1.692x` | `73.271` | `48.187` | `1.521x` | next focused/codegen primitive |
| `memchr_absent` | `30.176` | `19.787` | `1.525x` | `31.556` | `22.752` | `1.387x` | just focused; no-repeat without new primitive |
| `memcmp_256` | `5.782` | `4.174` | `1.385x` | `6.829` | `5.540` | `1.233x` | no-repeat without backend primitive |
| `memmove_4096` | `38.875` | `32.948` | `1.180x` | `42.372` | `36.317` | `1.167x` | lower priority, copy-codegen family |
| `exp10` | `343.817` | `316.556` | `1.086x` | `364.606` | `328.272` | `1.111x` | small + prior exp2 route rejects |
| `powf_irrational` | `400.901` | `371.659` | `1.079x` | `407.956` | `388.209` | `1.051x` | small, previously collapsed |
| `memset_4096` | `34.912` | `33.354` | `1.047x` | `36.328` | `34.395` | `1.056x` | too small |
| `memcmp_4096` | `46.296` | `42.594` | `1.087x` | `49.310` | `45.352` | `1.087x` | codegen routed out |
| `log` | `370.535` | `364.597` | `1.016x` | `382.059` | `469.756` | `0.813x` | mean faster, no edit |
| `memcpy_4096` | `35.885` | `36.156` | `0.993x` | `39.393` | `38.281` | `1.029x` | tied |
| `strlen_4096` | `17.764` | `21.256` | `0.836x` | `20.382` | `24.365` | `0.837x` | faster |
| `printf_g_6` | `134.312` | `142.383` | `0.943x` | `146.752` | `150.781` | `0.973x` | faster |
| `log2` | `184.338` | `322.654` | `0.571x` | `219.085` | `349.500` | `0.627x` | faster |
| `log10` | `406.446` | `503.547` | `0.807x` | `433.559` | `515.176` | `0.842x` | faster |
| `log1p` | `481.881` | `527.659` | `0.913x` | `503.357` | `607.605` | `0.828x` | faster |
| `exp10f` | `285.017` | `358.818` | `0.794x` | `288.601` | `366.624` | `0.787x` | faster |
| `log10f` | `173.229` | `349.187` | `0.496x` | `179.106` | `368.438` | `0.486x` | faster |
| `log2f` | `158.240` | `335.500` | `0.472x` | `167.261` | `338.769` | `0.494x` | faster |

## Behavior Proof

No implementation source changed. This is a routing-only profile pass.

Ordering/tie-breaking, floating-point behavior, RNG state, allocation behavior,
errno/locale state, and golden outputs are unchanged by identity.

## Verdict

ROUTING ONLY. Score `0.0`.

Next focused target is `strcpy_4096`, but not via the recent manual source
families. A source edit requires a materially different generated/backend
terminal/no-overlap primitive or compiler-lowering proof.
