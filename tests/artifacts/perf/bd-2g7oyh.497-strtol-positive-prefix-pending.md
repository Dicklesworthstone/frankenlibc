# bd-2g7oyh.497 strtol positive digit-prefix pending bench

## Bead

- ID: `bd-2g7oyh.497`
- Title: `perf: strtol positive digit-prefix fast path pending bench`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

## Disk-Low Constraint

The root filesystem was at critical pressure during this pass:

```text
sbh status: overall critical
df -h /data/projects/frankenlibc: 50G available, 98% used
du -sh /data/projects/frankenlibc: 37G
```

Per the turn directive, no new `cargo bench`, `cargo build`, or `cargo test`
command was started.

## Code-Only Lever

`parse_strtol_c_string_fast` already handles deployed strict-mode base-10 and
base-16 `strtol` without the generic core parser. This pass splits out the
hottest positive-prefix cases:

- base 10, first byte is `0..9`;
- base 16, first byte is a hex digit, including the `0x`/`0X` prefix when it
  is followed by at least one hex digit.

Those paths parse directly from the initial cursor and skip the generic
whitespace/sign/base setup. Signed, whitespace-prefixed, invalid-base, and
non-10/16 cases still take the existing path.

## Pending Bench

Required next-turn gate, once disk pressure is handled:

```text
AGENT_NAME=BlackThrush RCH_WORKER=<same-worker> CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench strtol_glibc_bench -- strtol --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Expected rows to classify:

- `strtol_dec_short`
- `strtol_dec_long`
- `strtol_hex`

Keep only if same-worker head-to-head results improve the target rows without
regressing deployed conformance. Revert if the result is neutral/loss or if
the strtol family differential/fuzz gate diverges from host glibc.
