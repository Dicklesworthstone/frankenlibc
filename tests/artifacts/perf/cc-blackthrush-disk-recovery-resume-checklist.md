# Resume checklist — cc/BlackThrush stdio membrane/lock campaign (disk-recovery gate)

During the DISK-CRITICAL window (root fs ~39G, ~98% used) cargo was paused entirely
(no build/check/bench). The following code-only commits shipped UNVERIFIED-COMPILE
(each is a line-for-line analog of an earlier built+benched pattern, but none was
compiled in its own turn). They are correctness-audited by inspection (see
`docs/NEGATIVE_EVIDENCE.md`), but must be build-verified and benched the moment disk
recovers, IN THIS ORDER, before any new lever.

## Step 0 — GATE: confirm disk actually recovered BEFORE any cargo

Disk hovered at 38–39G (~98% used) for ~10 turns. Do NOT run cargo on a wishful
"resume" signal — verify first, or a build will fail mid-way and waste the window:

```
df -h /data /            # expect comfortably below ~90% used, ample free GB
```

Also note (separate from this code-only campaign): if disk is still tight, the usual
culprits are accumulated `/data/projects/.rch-targets/*` build dirs and stray
`.scratch`/perf-proof git worktrees — those are a system/sbh concern, not edited here.
Only proceed to Step 1 once `df` shows real headroom.

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

Update each row's verdict in `docs/NEGATIVE_EVIDENCE.md` (PENDING -> WIN/NEUTRAL/LOSS).

KEEP/REVERT CRITERION (learned this campaign — apply it, don't relitigate):
- The 6 shipped guards are PURE LOCK-SKIPS — they skip a global mutex + lookup that would
  no-op anyway (no behavior change for any input). KEEP them even if a single-thread
  microbench shows ~0-gain: they remove a global serialization point (fewer global-lock
  acquisitions per op = real MT-contention reduction). Revert ONLY on a measured regression.
- DO NOT confuse them with the REVERTED fputs/puts/printf `scan_c_str_len`→`scan_c_string`
  swaps (commit ecf2043dd): those were lock-removal PLUS a SEMANTIC change (read-to-NUL vs
  the known_remaining bound for unterminated tracked buffers) AND registry-lock-dominated
  end-to-end. Different class — do not re-apply them blind. The same semantic caveat is why
  the scanf levers (Step 5) must be strict-gated + conformance-tested, not shipped byte-blind.

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

## Step 5 — NEW levers identified during the disk-low window (implement + bench)

These are snprintf("%s")-class wins (caller string, NO stream/registry lock, so
strlen+parse-dominated — a REAL gain, unlike the registry-lock-bound fputs). Each
swaps the `scan_c_str_len(_, None)` → `known_remaining` → `fallback_remaining`
(`lock_fallback_alloc_table()` MUTEX + up-to-1024 hash probe) for the lock-free SWAR
`string_abi::scan_c_string(_, None)`. NOT byte-identical (the `!*_terminated` early-out
is a hardening bound for fl-tracked-but-unterminated buffers), so GATE on strict mode
(glibc-compatible scan-to-NUL) and keep `scan_c_str_len` in hardened. Documented as
`// PERF (bd-2g7oyh …)` comments at each site.

| site | function(s) affected | bench |
|------|----------------------|-------|
| `sscanf`/`vsscanf` input scan (`scan_c_str_len(s, None)`) | sscanf, vsscanf | new sscanf-vs-glibc (dlmopen host, in-process) |
| `scanf_core_impl` format scan (`scan_c_str_len(format, None)`) | ALL scanf variants incl. stream-based fscanf/vfscanf | same harness; format is the broader instance |

Verify each against the scanf conformance + metamorphic gates (the `!terminated`
behavior change is UB-only: fl-malloc'd unterminated buffer → was EOF, becomes
glibc-style parse-to-NUL; differential-vs-glibc gates should pass since strict ==
glibc-compat).
