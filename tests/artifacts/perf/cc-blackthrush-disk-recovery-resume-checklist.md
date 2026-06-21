# Resume checklist — cc/BlackThrush stdio membrane/lock campaign (disk-recovery gate)

During the DISK-CRITICAL window (root fs ~39G, ~98% used) cargo was paused entirely
(no build/check/bench). The following code-only commits shipped UNVERIFIED-COMPILE
(each is a line-for-line analog of an earlier built+benched pattern, but none was
compiled in its own turn). They are correctness-audited by inspection (see
`docs/NEGATIVE_EVIDENCE.md`), but must be build-verified and benched the moment disk
recovers, IN THIS ORDER, before any new lever.

## Step 1 — build-verify (one command covers all six)

```
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
  rch exec -- cargo build -p frankenlibc-abi --release
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
  rch exec -- cargo test -p frankenlibc-abi --lib   # cfg(test) path (fast-paths disabled) — expect 202/0
```

If either fails to compile, the offending commit is one of the six below — fix and re-push.

## Step 2 — the six unverified code-only commits (all in `crates/frankenlibc-abi/src/`)

| commit | change | file |
|--------|--------|------|
| `a8aad9c1d` | `is_cookie_stream` lock-free fast-path (COOKIE_STREAMS_PRESENT atomic) | stdio_abi.rs |
| `3341e1ff4` | `observe()` + ApiFamily::Stdio fast-path | runtime_policy.rs |
| `17ddbb942` | `decide()` STRICT + ApiFamily::Stdio fast-path | runtime_policy.rs |
| `05797abd6` | `sync_memstream_to_caller` lock-free fast-path (MEM_STREAM_SYNC_PRESENT) | stdio_abi.rs |
| `0d98f57a5` | `sync_fmemopen_full` lock-free fast-path (MEM_FIXED_SYNC_PRESENT) | stdio_abi.rs |
| `3551f58e3` | `decide()` HARDENED + ApiFamily::Stdio fast-path | runtime_policy.rs |

(The 6d2cd0c79 snprintf("%s") SWAR win was built+benched pre-disk and is already certified.)

## Step 3 — PENDING benches to record real fl-vs-glibc ratios (same-worker, in-process)

- `fgetc_4096`: `rch exec -- cargo bench -p frankenlibc-bench --features abi-bench --bench stdio_glibc_baseline_bench -- fgetc_4096`
  Expect fl < glibc (last measured 0.49x same-run after observe+decide Stdio). Records the observe/decide/cookie wins.
- `fputs_glibc_bench`: same harness, `--bench fputs_glibc_bench`.
  Records baseline write-path 6-12x loss AND any movement from the cookie/memstream/memfixed guards (note: write fast-path still holds the main registry() lock — see Step 4).
- open_memstream / fmemopen flush+close micro-bench (not yet written): exercises sync_memstream/sync_fmemopen guards.

Update each row's verdict in `docs/NEGATIVE_EVIDENCE.md` (PENDING -> WIN/NEUTRAL/LOSS). Revert any ~0-gain
single-thread guard ONLY if it also has no MT-contention value (these remove global locks, so keep unless a
clear regression appears).

## Step 4 — the real remaining architectural win (needs build+test, NOT a blind edit)

`bd-hqo6b6` / `bd-baifnq`: the deployed READ (`fgetc` double-lock) and WRITE
(`fputs`/`fwrite`/`fputc` single-lock) paths are dominated by the GLOBAL `registry()`
Mutex (6-12x vs glibc; glibc uses a lock-free inline buffer-pointer bump). The
safe-collapse plan + hazards (hardened-mode deadlock if `decide()` is held under
`registry()`; host-delegation reorder behavior change) are documented in-code as
`// PERF (bd-baifnq …)` at `fgetc` and `// PERF (bd-hqo6b6)` at
`write_bytes_without_runtime_policy`. The full fix is a sharded / per-FILE lock
(`Arc<Mutex<StdioStream>>` resolved via a read-mostly `RwLock<HashMap>`). Run it with
harness conformance — currently blocked by the pre-existing `frankenlibc-fixture-exec`
build break, which must be resolved first.
