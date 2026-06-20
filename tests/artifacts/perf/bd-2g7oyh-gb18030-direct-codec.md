# bd-2g7oyh GB18030 Packed Direct Codec

Agent: cod-a / BlackThrush  
Date: 2026-06-20  
Worktree: `/data/projects/frankenlibc`  
Target dir: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a`

## Radical Lever

The iconv CJK sweep left a large GB18030 residual after the CP932 closeout:
GB18030's common CJK workload is a regular transducer shape:

- UTF-8 encode side: 3-byte BMP scalar -> GB18030 2-byte DBCS key.
- Decode side: GB18030 2-byte DBCS key -> 3-byte UTF-8 BMP scalar.

Instead of constructing `char`, returning `Result`, and running the generic
encoder/decoder for every scalar, this patch adds packed direct tables and emits
four code points per loop before falling back to the existing scalar body.

The direct tables are built from the same glibc-derived GB18030 tables already
used by `encode_gb18030`/`decode_gb18030`:

- `gb18030_utf8_bmp3_dbcs2_direct`: code point -> packed two-byte GB18030 key.
- `gb18030_bmp3_utf8_direct`: two-byte GB18030 key -> packed UTF-8 triple.

The fast paths consume input only when every byte is the exact hot shape. ASCII,
invalid UTF-8, overlong/surrogate UTF-8, GB18030 four-byte-only code points,
single-byte GB18030, incomplete leads, invalid pairs, and output-tail shortages
break before consuming and fall through to the pre-existing scalar path. That
preserves the old EILSEQ/EINVAL/E2BIG ordering.

## Baseline

Command:

```bash
env AGENT_NAME=BlackThrush \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_VERBOSE=1 RCH_WORKER=hz1 RCH_WORKERS=hz1 RCH_PREFERRED_WORKER=hz1 \
  RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench iconv_glibc_bench gb18030 -- --measurement-time 2 --warm-up-time 1 --noplot
```

Worker selected by `rch`: `hz1`.

| Workload | FrankenLibC p50 | glibc p50 | fl/glibc | Verdict |
|---|---:|---:|---:|---|
| `utf8_cjk_to_gb18030` | 5622.3 ns | 3495.2 ns | 1.609x | LOSS |
| `gb18030_to_utf8` | 121728.2 ns | 2603.6 ns | 46.756x | LOSS |

## Final Bench

Same command and target dir, but `rch` selected `hz2` despite the `hz1`
preference because worker availability changed. The in-run fl/glibc ratios are
valid head-to-head evidence; baseline-to-final self-speedup is directional rather
than same-worker proof.

| Workload | FrankenLibC p50 | glibc p50 | fl/glibc | Verdict |
|---|---:|---:|---:|---|
| `utf8_cjk_to_gb18030` | 1401.1 ns | 2592.7 ns | 0.540x | WIN |
| `gb18030_to_utf8` | 976.4 ns | 2206.2 ns | 0.443x | WIN |

Targeted scorecard: 2 WIN / 0 NEUTRAL / 0 LOSS vs glibc.

## Validation

- `cargo check -p frankenlibc-core` passed with pre-existing warnings.
- `cargo test -p frankenlibc-abi --test iconv_differential_fuzz iconv_cjk_differential_fuzz_vs_glibc -- --nocapture` passed: 216000 conversions, 0 divergences vs host glibc.
- `git diff --check` passed.
- `cargo fmt --check -p frankenlibc-core` remains blocked by broad pre-existing formatting drift across unrelated/generated files; no formatting changes were applied.
- `cargo clippy -p frankenlibc-core --lib -- -D warnings` remains blocked by pre-existing lint debt (`unused_mut`, generated dead table, large const array, doc lazy continuation, and unrelated stdio/resolv lints); no unrelated lint cleanup was folded into this perf commit.

## Verdict

Keep. The final deployed ABI head-to-head now beats glibc for both targeted
GB18030 directions. The packed table path closes the severe decode loss and turns
the encode loss into a win without changing unsupported/error-tail behavior.
