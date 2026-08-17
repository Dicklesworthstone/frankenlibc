# sscanf re-baseline and engine-allocation removal — 2026-08-16

Raw results for the `sscanf` work of 2026-08-16. These lived only in a session
scratchpad until now, which meant nobody else could re-derive them; the commands
below reproduce every number from a clean checkout.

Ledger rows: `docs/NEGATIVE_EVIDENCE.md`, 2026-08-16 "RE-BASELINE: the sscanf
family's worst case is no longer `long_string`".

## 1. Per-case ratios against live glibc

Apparatus: `incumbent_coverage_ab --family sscanf`, host `thinkstation1`, pinned
to cpu8, `samples=36`, `reps_per_arm=600000`. fl object
`sha256=fd2c8e8bcf8385ded7c82dea179839bcd29716315cce6f134f7ed6f8e269368d`
(pre-change). Loadavg 10.92 17.13 19.92 at launch, cpu8 at 4292 MHz.

```
cargo build --profile release-perf -p frankenlibc-abi --lib
cargo build --profile release-perf -p frankenlibc-bench --features abi-bench \
    --example incumbent_coverage_ab
taskset -c 8 target/release-perf/examples/incumbent_coverage_ab \
    --family sscanf --fl-so target/release-perf/libfrankenlibc_abi.so
```

| case | fl ns | glibc ns | fl/glibc |
|---|---:|---:|---:|
| string_token | 93.765 | 41.880 | 2.238 |
| two_strings | 159.216 | 79.659 | 1.944 |
| dotted_quad | 207.251 | 115.692 | 1.788 |
| key_value | 140.575 | 81.743 | 1.716 |
| string_then_int | 120.780 | 70.698 | 1.707 |
| scanset_only | 103.203 | 61.172 | 1.689 |
| single_int | 80.107 | 50.699 | 1.584 |
| two_ints | 108.849 | 70.044 | 1.557 |
| mixed_record | 258.293 | 179.693 | 1.414 |
| long_string | 123.440 | 99.876 | 1.235 |
| long_hex | 86.075 | 79.500 | 1.086 |
| float_only | 112.797 | 104.489 | 1.080 |

Loadavg reached 46.54 by the end of the run. Treat the ORDERING as the result
and the magnitudes as provisional; a quiet-window re-run is owed.

**Do not quote these against the older hz1 row (`long_string` 2.387x).** That row
is a different host, and the lever it named — per-byte `%s` copy — has since been
taken, which is why `long_string` is now among the best cases here.

## 2. The decomposition that chose the lever

`single_int` never reaches the parsing engine (`strict_decimal_int_format_count`
plus `strict_scan_decimal_ints` serve pure-decimal-int formats from a fixed-size
struct) and still costs 80.107 ns against 50.699 ns. So ~29 ns is fixed overhead
OUTSIDE the engine, and the engine path adds the rest — for `string_token`, the
51.9 ns gap minus that ~29 ns leaves ~22 ns for the engine to account for.

That is the bound on what removing engine allocations could win, and it is why no
ratio was claimed for the change.

## 3. Allocation counts, which is what was actually verified

Counting is load-independent, so it holds on a busy box where a ratio would not.
Reproduce with the in-repo gate:

```
cargo test -p frankenlibc-abi --test sscanf_allocation_count -- --nocapture --test-threads=1
```

| format | before | after |
|---|---:|---:|
| `sscanf("hello world", "%s%n")` | 4 | 0 |
| `sscanf("3.5", "%f%n")` | 4 | 0 |
| `sscanf("key=value", "%[^=]%n")` | 4 | 1 |
| `sscanf("42", "%d")` (fast path) | 0 | 0 |

glibc allocates nothing on any of these. The remaining 1 is `%[...]`'s boxed
`ScanSet`; that table is now a 256-bit map (40 bytes, down from 257), so the
allocation that remains is small and its membership test touches one word.

Where the four were, and the commits that removed them:

1. `scan_input` collected into `Vec::new()` — first push allocated, then doubled.
2. and 3. `ScanDirective::Spec(Box<ScanSpec>)` boxed EVERY conversion, because
   `ScanSpec` embedded the 257-byte `ScanSet`. Boxing the TABLE instead lets the
   spec live inline.
4. `parse_scanf_format` returned `Vec<ScanDirective>`.

`782490a88` (1-4, via `InlineVec<T, N>`), `7cfb786c0` (the float token's scratch
`Vec`, removed by parsing in place).

## 4. What is still owed

- A certified fl-vs-glibc re-run of this family on a quiet host, base against
  candidate, to attach a ratio to the allocation removal.
- A profile of the ~29 ns of fixed non-engine overhead that `single_int` pays:
  `runtime_policy::decide`/`observe`, `strict_c_str_len`, and the variadic
  argument walk are the suspects, in that order. Preflight
  `docs/NEGATIVE_EVIDENCE.md` first — `decide`/`observe` are recorded as refuted
  levers for the ALLOCATOR, but they have not been priced on the stdio path.
