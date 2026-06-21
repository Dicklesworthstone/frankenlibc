# bd-2g7oyh - strict sscanf exact triple-int transducer

Date: 2026-06-21
Agent: cod-a / BlackThrush

## Lever

`sscanf("%d %d %d")` was spending most of its time in the generic stdio scanner
after first walking caller strings through the membrane allocation-bounds path.
The kept lever has two parts:

- In strict passthrough mode, scan caller C strings and formats with the existing
  page-safe SWAR string scanner instead of `known_remaining`/allocation fallback.
- Add an exact strict transducer for `sscanf("%d %d %d")`: skip ASCII spaces,
  parse signed decimal `int` fields, write only successful destinations, preserve
  EOF before the first conversion, and return partial counts on later failures.

Hardened mode and all non-exact formats stay on the existing generic scanner.

## Benchmark

Command shape:

```text
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench sscanf_glibc_bench --profile release -- sscanf_three_ints \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

| Stage | Worker | fl median | glibc median | ratio fl/glibc | Verdict |
|-------|--------|-----------|--------------|----------------|---------|
| Current-head loss route before edits | `hz1` | 461.44 ns | 130.21 ns | 3.54x | LOSS |
| Strict SWAR caller-string scan only | `ovh-a` | 265.69 ns | 84.076 ns | 3.16x | LOSS |
| Final exact strict transducer | `ovh-a` | 15.659 ns | 81.986 ns | 0.191x | WIN |

Criterion reported the final `ovh-a` run improved over the prior same-worker
`ovh-a` candidate by -93.34% (p=0.00). Do not combine the `hz1` baseline and
`ovh-a` final row as an exact self-speedup; the acceptance proof is the final
same-run head-to-head ratio and the same-worker `ovh-a` delta.

## Conformance

Focused ABI differential:

```text
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -p frankenlibc-abi --test conformance_diff_stdio_printf \
  diff_sscanf_int_cases --release -- --nocapture
```

Result: PASS, 1/0. The differential now covers exact triple-int success,
partial input, matching failure, empty input EOF, and signed overflow wrapping
against host glibc.

Focused core scanner guard:

```text
AGENT_NAME=cod-a CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  rch exec -- cargo test -p frankenlibc-core scanf --release
```

Result: PASS, 71 scanf-related tests passed and 3111 filtered out, including
the existing scanf differential battery.

## Scorecard

- `sscanf_three_ints`: WIN, fl 15.659 ns vs glibc 81.986 ns, ratio 0.191x.
- Neutral: 0.
- Loss: 0.

## Residual

This is intentionally narrow. The exact common literal format now dominates
glibc, but broader scanf formats still use the generic parser. The next measured
route should be a small verified transducer table/cache for other hot literal
format strings, not a speculative rewrite of the general scanner.
