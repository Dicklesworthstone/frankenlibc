# bd-0ft0w3 cod-b strict exact snprintf direct path

Date: 2026-06-20
Agent: BlackThrush / cod-b
Scope: `snprintf("%s")` and `snprintf("%s\n")` in strict passthrough mode.

## Lever

`snprintf` exact string formats were still losing badly to glibc after the
earlier parser-bypass keep. The kept lever moves the exact `%s` / `%s\n` path
above `entrypoint_scope` and fuses the C-string scan with the destination copy.
It preserves the `snprintf` length contract, NUL termination, truncation, and
`(null)` behavior. Hardened mode and all non-exact formats keep the existing
runtime-policy plus printf-engine path.

## Benchmark Commands

All benchmark commands were per-crate and used:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo bench -j 1 -p frankenlibc-bench \
  --bench stdio_glibc_baseline_bench --features abi-bench -- \
  stdio_glibc_baseline_snprintf_s --noplot --sample-size 50
```

The current-head baseline was split across the exact group filters
`stdio_glibc_baseline_snprintf_s_newline` and
`stdio_glibc_baseline_snprintf_s_bare` before the candidate run.

## Results

| Stage | Worker | Workload | FrankenLibC | glibc | FL/glibc | Verdict |
|---|---|---:|---:|---:|---:|---|
| current head | `hz1` | `%s\n` | 392.83 ns | 32.120 ns | 12.23x | LOSS |
| current head | `vmi1293453` | `%s` | 561.55 ns | 84.221 ns | 6.67x | LOSS |
| first shortcut | `vmi1152480` | `%s\n` | 115.27 ns | 59.727 ns | 1.93x | LOSS |
| first shortcut | `vmi1152480` | `%s` | 98.274 ns | 43.500 ns | 2.26x | LOSS |
| fused direct path | `vmi1153651` | `%s\n` | 67.224 ns mean / 45.483 ns median | 86.029 ns mean / 82.265 ns median | 0.781x mean / 0.553x median | WIN |
| fused direct path | `vmi1153651` | `%s` | 63.297 ns mean / 52.282 ns median | 93.254 ns mean / 72.797 ns median | 0.679x mean / 0.718x median | WIN |

The first shortcut is recorded as negative evidence: parser bypass alone was
not enough. The fused scan+copy version is the kept source shape.

## Validation

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo build -j 1 -p frankenlibc-abi --release
```

Passed on `hz1` with the existing warning backlog.

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test conformance_diff_stdio_printf diff_snprintf_string_specifiers
```

Passed 1/1 on `vmi1293453`.

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test conformance_diff_stdio_printf diff_snprintf_truncation
```

Passed 1/1 on `vmi1153651`.

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test conformance_diff_printf_null_string
```

Passed 1/1 on `vmi1227854`.

`git diff --check -- crates/frankenlibc-abi/src/stdio_abi.rs` passed.
`cargo fmt -p frankenlibc-abi --check` remains blocked by broad pre-existing
formatting drift across ABI/table/test files and was not normalized in this
perf commit.
