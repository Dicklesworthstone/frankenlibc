# bd-2jgvp9 stdio stream registry local integer hasher

## Attempt

- Bead: `bd-2jgvp9`
- Agent lane: `cod-b`
- Lever: replace only the stdio `StreamRegistry.streams` map with a local
  `usize`-specialized deterministic hasher. The shared `ArtifactHashMap`
  hasher remains unchanged.
- Target: hot `FILE*` registry lookup paths in `fwrite`, `fread`, `fflush`,
  `fgetc`, `fputc`, `fileno`, `feof`, `ferror`, and related stdio calls.
- Baseline comparator: host glibc stdio registry/stream lookup behavior in
  `stdio_glibc_baseline_bench`; timing is pending because this turn is
  restricted to cargo-check-only validation.

## Negative-Evidence Screen

| Candidate | Ledger decision |
| --- | --- |
| Codebase-wide `ArtifactHashMap` integer fast-path | Not attempted. It affects dirent, iconv, setjmp, io, pthread, wchar, stdio side registries, termios, and unistd maps. Several of those have observable iteration order or broad conformance risk. Retry only with full conformance clearance. |
| `memchr_absent` panel/width/SWAR families | Not retried. Prior same-worker ledgers mark those as no-ship or routing-only. |
| `memcmp` load-shape/source-loop retunes | Not retried. Prior focused gates rejected adjacent source-shape families. |
| `malloc_free_256` hot-list/slab micro retunes | Not retried. Prior focused gates closed this family as not a current source-edit target. |
| `log2f` exponent/atanh and nearby math micro-levers | Not retried. Prior proof-clean attempts regressed focused gates. |

## Proof Shape

- Ordering preserved: yes. Hash-table iteration order is not part of the
  public stdio contract, and all registry-wide flush/close snapshots now sort
  stream IDs before iterating.
- Tie-breaking unchanged: yes. Stream identity remains exact `usize` equality.
- Floating-point: N/A.
- RNG seeds: N/A.
- Safety: no new unsafe blocks; the change is a local hasher and ordered ID
  snapshot helper.

## Guard

- `stdio_stream_id_hasher_integer_fast_path_matches_usize_and_u64` pins the
  intended integer fast path.
- `stdio_flush_all_id_snapshot_is_sorted` pins the flush-all/close-all
  observable-order guard.

## Pending Keep/Reject Predicate

Batch validation should run the existing stdio head-to-head gates, at minimum:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo bench -p frankenlibc-bench --bench stdio_glibc_baseline_bench -- --noplot
```

Keep only if stdio registry-heavy rows improve or stay within noise and stdio
conformance remains green. Reject and restore this lever if the focused stdio
gate regresses by more than the active campaign threshold or if any flush-order
or close-all differential fails.

## Validation This Turn

Passed:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo check -p frankenlibc-abi
```

The run completed with existing warning debt in `frankenlibc-core` iconv and
`frankenlibc-abi` math/poll/signal/erf tables.

Attempted but not used as the official gate because it compiles unrelated
scratch tests:

```bash
AGENT_NAME=DarkRiver CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo check -p frankenlibc-abi --all-targets
```

That failed in pre-existing scratch targets (`zz_scratch_divmin`,
`zz_probe_dbcs`, `zz_probe_fmemread`) unrelated to this stdio hasher patch.
