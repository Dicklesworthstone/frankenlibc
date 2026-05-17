# Changelog

All notable changes to FrankenLibC are documented in this file.

FrankenLibC has no formal releases, version tags, or GitHub Releases. The project is at **v0.1.0** (pre-release) and ships a single artifact: `target/release/libfrankenlibc_abi.so` used via `LD_PRELOAD`. This changelog is organized by capability milestones derived from the complete commit history (4,932 commits by a single author across 97 days of active development).

Repository: <https://github.com/Dicklesworthstone/frankenlibc>

---

## [Unreleased] -- HEAD (as of 2026-05-16)

**Current state:** **4119 classified symbols | 3705 Implemented + 414 RawSyscall = 100.0% native coverage** | 0 GlibcCallThrough | 0 WrapsHostLibc | 0 Stub. The classified support-matrix surface no longer reports any host-glibc call-through or wrapper rows; the shipping artifact is still the interpose-first `LD_PRELOAD` library (`libfrankenlibc_abi.so`), with replacement-level promotion gates and L1 evidence dashboards driving the path to a standalone replace artifact. Source of truth: `support_matrix.json` and `tests/conformance/reality_report.v1.json` (regenerated 2026-02-18 against the current matrix).

Methodology note: the entries in phases 1-7 below were assembled from raw commit history. Phases 8-16 below cover the post-Phase-7 burst of 4,281 additional commits (2026-03-22 .. 2026-05-16) and were assembled by mining git history, the local beads_rust (`br`) tracker, and the `tests/conformance/*_completion_contract.v1.json` evidence ledger. Bead IDs in `[bd-xxxxx]` correspond to issues tracked in `.beads/` and quoted in commit subjects for traceability.

---

## Phase 16 -- CLI-Contract Manifest Meta-Gates and Final Hardening (2026-05-16)

A single-day campaign (~255 commits) that locked down the harness CLI's machine-checkable contract. Every `*_cli_contract.v1.json` manifest now passes ~50 meta-gates covering shape, naming, JSON well-formedness, paired-test enforcement, and freshness. Final corrections to `gai_strerror`/`strsignal`/`strerror_np` text alignment with glibc. Directed fuzz seed corpora added for regex, ctype, c11threads, and adversarial printf.

### Harness CLI Contract Meta-Gate Framework

- Pin `cli_contract` manifests are well-formed JSON with no BOM/trailing garbage ([09d459a](https://github.com/Dicklesworthstone/frankenlibc/commit/09d459a7b4787819d7b1f399fe6dc4c293ae4471))
- Pin every `cli_contract` manifest has a matching paired gate test ([10db70e](https://github.com/Dicklesworthstone/frankenlibc/commit/10db70ea))
- Pin every paired gate test has a matching `cli_contract` manifest ([4fe4058](https://github.com/Dicklesworthstone/frankenlibc/commit/4fe40587ac38d30b184bc9140d5be83b253edd57))
- Pin `manifest_id` length in [10,80] sanity bounds ([4c368fc](https://github.com/Dicklesworthstone/frankenlibc/commit/4c368fc0))
- Pin `subcommand_name == manifest_id` minus `-cli-contract` suffix ([8d1ee97](https://github.com/Dicklesworthstone/frankenlibc/commit/8d1ee97a))
- Pin manifest `required_flags`/`optional_flags` are arrays, disjoint, deduplicated, and flag-only form (no `=` defaults) ([0fb5ec0](https://github.com/Dicklesworthstone/frankenlibc/commit/0fb5ec07), [d57ed44](https://github.com/Dicklesworthstone/frankenlibc/commit/d57ed441), [e2fd3c7](https://github.com/Dicklesworthstone/frankenlibc/commit/e2fd3c7b), [316b6bf](https://github.com/Dicklesworthstone/frankenlibc/commit/316b6bfb), [ec48819](https://github.com/Dicklesworthstone/frankenlibc/commit/ec488194), [2770891](https://github.com/Dicklesworthstone/frankenlibc/commit/2770891c))
- Pin `policy` keys are snake_case with at least one boolean rule ([8b42256](https://github.com/Dicklesworthstone/frankenlibc/commit/8b4e2256), [06daa70](https://github.com/Dicklesworthstone/frankenlibc/commit/06daa70b))
- Pin `rejected_evidence_kinds` entries are snake_case array ([302420b](https://github.com/Dicklesworthstone/frankenlibc/commit/302420b8), [5ba8a48](https://github.com/Dicklesworthstone/frankenlibc/commit/5ba8a482))
- Pin `jsonl_output_contract` has `required_fields` array (snake_case) and well-formed `record_count` ([7d4a67b](https://github.com/Dicklesworthstone/frankenlibc/commit/7d4a67b3), [933d68a](https://github.com/Dicklesworthstone/frankenlibc/commit/933d68aa), [c51849c](https://github.com/Dicklesworthstone/frankenlibc/commit/c51849c9))
- Pin `io_pattern` is snake_case descriptive (≥10 chars) ([406a469](https://github.com/Dicklesworthstone/frankenlibc/commit/406a4693))
- Pin `underlying_lib_functions` entries are Rust paths, unique, and singular form matches `plural[0]` ([bb3b95b](https://github.com/Dicklesworthstone/frankenlibc/commit/bb3b95bf), [4954d06](https://github.com/Dicklesworthstone/frankenlibc/commit/4954d064), [4c26c18](https://github.com/Dicklesworthstone/frankenlibc/commit/4c26c180))
- Pin `bead` field is canonical `beads_rust` id and timestamps are valid ISO-8601 ([3034398](https://github.com/Dicklesworthstone/frankenlibc/commit/3034398d), [a287f8c](https://github.com/Dicklesworthstone/frankenlibc/commit/a287f8c1))
- Pin `optional_flags <= 25` sanity ceiling, `summary` non-empty (object/array/string≥30) ([287cfc3](https://github.com/Dicklesworthstone/frankenlibc/commit/287cfc33), [a84c68f](https://github.com/Dicklesworthstone/frankenlibc/commit/a84c68ff))
- Pin paired gate tests reference `env!(CARGO_MANIFEST_DIR)` ([7a4481f](https://github.com/Dicklesworthstone/frankenlibc/commit/7a4481f3))
- Ban raw panic in CLI gates; reject manifest id double dashes ([49b8847](https://github.com/Dicklesworthstone/frankenlibc/commit/49b88471), [7a39a74](https://github.com/Dicklesworthstone/frankenlibc/commit/7a39a746))

### glibc Text Alignment

- Complete `strerror_np` errno tables ([b91af0e](https://github.com/Dicklesworthstone/frankenlibc/commit/b91af0e9fdc0a8a73b04ac3db46e8df07ddda205))
- Align `gai_strerror` text with glibc ([65163ad](https://github.com/Dicklesworthstone/frankenlibc/commit/65163ad09c28ce335a5bd0173b1703296160b11b))

### Fuzz Corpora

- Directed regex fuzz seed corpus ([d50ec5d](https://github.com/Dicklesworthstone/frankenlibc/commit/d50ec5d8))

---

## Phase 15 -- L1 CRT Proofs, Harness Panic Hygiene, Differential Aliases (2026-05-13 .. 2026-05-15)

Peak commit week (282 + 363 + 217 commits). L1 CRT proof rows shipped (Epic **bd-0qjk0**) for constructor order, destructor order, atexit order, errno TLS isolation, and init/fini array order. Systematic removal of panic surfaces across 50+ harness tests — every paired-gate test now returns `TestResult` instead of panicking. Differential coverage harnesses added for low-level glibc aliases. Three new ABI modules landed: `htm_fast_path.rs` (hardware-transactional-memory fast path for alien_cs), `owned_unwind_abi.rs` (owned unwinder for standalone artifact), and `nlist_abi.rs` (ELF symtab parsing).

### L1 CRT Proof Rollup

- Prove init/fini array order (Epic bd-0qjk0.5) ([3021dd6](https://github.com/Dicklesworthstone/frankenlibc/commit/3021dd6834f40cdd37f4610382f09e85157d4219))
- Prove errno TLS isolation (Epic bd-0qjk0.6) ([4514aa0](https://github.com/Dicklesworthstone/frankenlibc/commit/4514aa02d59f5411122e69a07453c490b05010c7))
- Close L1 CRT rollup gate (Epic bd-0qjk0.7) ([83b3e37](https://github.com/Dicklesworthstone/frankenlibc/commit/83b3e37dcdd2dd16bd24f06dcd506c6f797d829d))

### Harness Panic-Surface Removal

- Remove pthread bootstrap panic surfaces ([bdf3836](https://github.com/Dicklesworthstone/frankenlibc/commit/bdf3836a))
- Remove conformance fixture pipeline panics ([e1da28f](https://github.com/Dicklesworthstone/frankenlibc/commit/e1da28f86e0494c2d72f0683b0585c2f70ede7d0))
- Remove tail-stats metamorphic panics (Epic bd-1cb21) and 40+ similar panic-removal commits across stdio, pthread, allocator, fixture, runtime-math, and signal harnesses

### Differential Alias Coverage

- Unistd process wave-13 fixtures ([f9f9107](https://github.com/Dicklesworthstone/frankenlibc/commit/f9f91070813db0646ad18f7a989a2c94a9d6dd96))
- Internal copy alias differentials: `readdir64`, `scandir64`, `fdopendir`, `telldir`/`seekdir`, `readdir_r`, `ftw64`, `index`/`rindex`, `rawmemchr`, `memccpy`, `memcmpeq` ([73ebc7a](https://github.com/Dicklesworthstone/frankenlibc/commit/73ebc7a4db4e86a96fd57d0d7b95a9c075d27029))
- String mutating differentials for `strl*` family ([9c1e963](https://github.com/Dicklesworthstone/frankenlibc/commit/9c1e963a729f64e89216cb44edcb5f562f2c2925))

### vis() Family Completion

- Honor `vis` HTTP and MIME styles, NetBSD range flags, VIS_NOSLASH, C-style whitespace (Epic bd-vok9a) ([e51ca19](https://github.com/Dicklesworthstone/frankenlibc/commit/e51ca19719855a087ab400ba81925084090ca989))

### New ABI Modules

- `htm_fast_path.rs` — Hardware-transactional-memory fast path for alien_cs concurrency primitives (19 KB)
- `owned_unwind_abi.rs` — Owned unwinder for the future standalone replace artifact (3 KB)
- `nlist_abi.rs` — ELF symtab parsing surface (4 KB)
- `efun_abi.rs` — Extern "C" lock/poison recovery (12 KB)

### Bug Fixes

- Match `ns_makecanon` capacity boundary ([8f2a47b](https://github.com/Dicklesworthstone/frankenlibc/commit/8f2a47b7fc647fcb04e2018fbcf8c7f3573c58b1))

---

## Phase 14 -- Completion-Contract Binding and Audit-Debt Burndown (2026-05-09 .. 2026-05-12)

A 700+ commit window (62 + 291 + 145 + 228 commits across 2026-05-09 / 10 / 11 / 12) where bead closure stopped meaning "ticket marked closed" and started meaning "closure is backed by a binding evidence artifact." Each closed bead now requires a `*_completion_contract.v1.json` JSONL receipt pointing at the fixtures, harness output, or proof artifact that backs it. Hundreds of dotted child beads (`*.1`, `*.bind`, `*.close`) flushed audit debt left behind by earlier epics — architecture, allocator, pthread, runtime-math, TSM, evidence ring, tracker recovery.

### Completion-Contract Framework

- Bind tracker recovery backlog evidence (Epic bd-bp8fl.2.10) ([135ff4f](https://github.com/Dicklesworthstone/frankenlibc/commit/135ff4ff6c12ec6f11b92454d50deb2eacbaa5b1))
- Bind unistd fixture completion contract (Epic bd-qce2t.3) ([81c5841](https://github.com/Dicklesworthstone/frankenlibc/commit/81c58413f770473f271e0e49664e7b4aa9d74e1a))
- Archive architecture TODO ledger (Epic bd-mp4q1) ([e6abec6](https://github.com/Dicklesworthstone/frankenlibc/commit/e6abec643b1e0ba5b9bd0f4950da4840fe90fdb7))
- 240+ named completion contracts under `tests/conformance/*_completion_contract.v1.json` covering aarch64 raw-syscall TLS, allocator membrane invariants, pthread mutex futex core, iconv locale family, resolver NSS hardening, replacement levels L1/L2/L3, runtime math kernels, SOS barrier soundness, evidence ledger, and CLI contract gates

### Fixture Waves Per Subsystem

- Seed unistd filesystem wave 2 (Epic bd-pz1g1) ([40c4772](https://github.com/Dicklesworthstone/frankenlibc/commit/40c4772ba22de6ada3ee4cc6ee7a747300ba68c5))
- Stdio libio symbol fixtures (Epic bd-6cly1.1) ([e1829ff](https://github.com/Dicklesworthstone/frankenlibc/commit/e1829ff9631ba3d7c9dd7474b1c86668d1802b83))
- RPC legacy fixtures (Epic bd-mu4lw.1) ([3f5d41d](https://github.com/Dicklesworthstone/frankenlibc/commit/3f5d41d32d803fabb132de1bdf7c4f57f6637cf3))
- Close pthread mutex futex debt (Epic bd-z84.1) ([34744f7](https://github.com/Dicklesworthstone/frankenlibc/commit/34744f7666037742a0bb79c4f2c05108d1d5df4b))

### Epic Closures

- **EPIC bd-h5x closed:** raw syscalls + futex pthread primitives delivered ([ad4666e](https://github.com/Dicklesworthstone/frankenlibc/commit/ad4666ea30cf8d6108f3b6f9b3adbebcf94e166a))
- 11 new conformance harnesses across stdio, string, time, pthread, signal
- 5 audit-debt epics drained (bd-58e87f, bd-27e6p, bd-exbv9, bd-6epxt, bd-gxgr5, bd-vmp2v)

---

## Phase 13 -- Replacement-Level Promotion and Fail-Closed Source Gates (2026-05-03 .. 2026-05-08)

The "claim without evidence" loophole gets closed. L1 dashboard infrastructure, replacement-claim audit, latency-budget joins, and workload reproducer manifest all become first-class. Forge / smoke / CRT-TLS / host-probe / artifact-freshness gates become **fail-closed** ("reject stale source pins"). The /porting-to-rust epic lifted `/etc/`-database parsers (mntent, networks, protocols, aliases, netgroup, getopt, pwd/grp/shadow) into core, each with new fuzz coverage. Metamorphic test harnesses added for `inet_pton`/`inet_ntop` round-trip, `strto*`/`snprintf` round-trip, and base64 codec invertibility.

### Replacement-Level Promotion

- Seed replacement-acceleration beads (Epic bd-b92jd) ([41422c8](https://github.com/Dicklesworthstone/frankenlibc/commit/41422c8aa81a3322581f7e3bddf0a1b79da55996))
- L1 replacement-level promotion gate ([19a767c](https://github.com/Dicklesworthstone/frankenlibc/commit/19a767c7fe635ee546490b0a5e1e45430646ee96))
- L1 dashboard freshness policy ([85c6ac5](https://github.com/Dicklesworthstone/frankenlibc/commit/85c6ac5f9b3a278d68c48579f20025117fcb2c6d))
- Workload evidence loop handoff (Epic bd-fp4tm.6) ([46cf6d3](https://github.com/Dicklesworthstone/frankenlibc/commit/46cf6d3e7954fbfd9924cc14d7a6a8aee6232645))

### Runtime Evidence Pipeline

- Runtime evidence JSONL schema ([a476459](https://github.com/Dicklesworthstone/frankenlibc/commit/a476459d0bde690ca100da7ae29863f8978b3dea))
- Runtime evidence replay verifier ([777c463](https://github.com/Dicklesworthstone/frankenlibc/commit/777c46373a68cb106967c498c332e2f496131c58))

### /etc-DB Parser Lift to Core

- Fuzz coverage for 4 lifted parsers: `mntent`, `networks/protocols`, `aliases`, `netgroup` ([253d3ca](https://github.com/Dicklesworthstone/frankenlibc/commit/253d3cadbcb7a54f6458fef4ae2ee2ab4034468f))
- Core subsystem directories added: `mntent/`, `netgroup/`, `aliases/`, `getopt/`, `ether/`, `proc_maps/`, `idna/`, `fmtmsg/`, `crypt/`, `ftw/`, `search/`, `stat/`, `err/`, `rpc/`

### Metamorphic Test Harnesses

- `inet_pton`/`inet_ntop` relation harness ([ea5c696](https://github.com/Dicklesworthstone/frankenlibc/commit/ea5c69661430fc06c0ff89722bd7f0b36b8546b8))
- Metamorphic invariants on `strto*`/`snprintf` round-trips ([689dd82](https://github.com/Dicklesworthstone/frankenlibc/commit/689dd82fe975b7af5aa87c5a98b7124ff8623864))
- Base64 round-trip golden checks (extending `b64_ntop_golden.v1.json`)

---

## Phase 12 -- Single-Pass Hot-Path Perf and BSD/Linux Compat Fill-In (2026-04-27 .. 2026-05-02)

Hot-path rewrites of the string-scan family to single-pass implementations: `strchr`, `strrchr`, `strspn`, `strcspn`, `strpbrk`, `strsep`, `strstr`, `strcasestr`, `strchrnul`, `strnstr`, `wcsstr`, `wcsrchr`. BSD compat helpers ported in (`explicit_memset`, `reallocarr`, `consttime_bcmp`, `pidfile_signal`, `memset_explicit`, `stravis`). Linux 6.7+ futex2 wrappers (`futex_wake`/`futex_wait`/`futex_requeue`) added under Epic **bd-0ar9l**. NSS shadow/pwd/grp reentrant slot hardening.

### Single-Pass Hot-Path Rewrites

- Single-pass `strstr` absent-scan ([c3addaa](https://github.com/Dicklesworthstone/frankenlibc/commit/c3addaaa40db1d9f9c0263f21739e54bc5c645d3))
- Single-pass `strchr` miss-scan ([42aff22](https://github.com/Dicklesworthstone/frankenlibc/commit/42aff220975277b4cfe2f13173a1b42ac0981193))
- Route `explicit_memset` through ABI memset for guaranteed inviolability ([c8ae5bf](https://github.com/Dicklesworthstone/frankenlibc/commit/c8ae5bf5523e28c20352982195eb0bb5e317429f))

### BSD Compat and Linux 6.7+ Syscalls

- Port 4 BSD compat helpers (`reallocarr`, `consttime_bcmp`, `pidfile_signal`, `stravis`) ([80fb620](https://github.com/Dicklesworthstone/frankenlibc/commit/80fb620cf901a03807784705e0bb888d62593b37))
- Port 3 Linux 6.7+ futex2 syscall wrappers (Epic bd-0ar9l) ([d74e35e](https://github.com/Dicklesworthstone/frankenlibc/commit/d74e35eabb719f783c370c345b5aaadf4e571aec))

### NSS Hardening

- Harden shadow passwd reentrant slots ([4a5201b](https://github.com/Dicklesworthstone/frankenlibc/commit/4a5201b14ef606ea211ca50e5bc5ba9391b2fc31))

---

## Phase 11 -- Tracked-Region Buffer-Bound Sweep (2026-04-27)

A ~150-commit workday: every C-string and buffer entry point in the ABI got a systematic "bound X scan" hardening pass. Every input pointer scan is now bounded by a tracked-region check, defeating out-of-bounds reads on attacker-controlled buffers. A CVE-class hardening sweep finished in one day.

### Tracked-Region Bound Sweep

- Bound poll/select/epoll/timerfd buffers via tracked-region check ([13ae2cd](https://github.com/Dicklesworthstone/frankenlibc/commit/13ae2cdd57ab19eaa939702137acb6531ad0ca21))
- Bound IO syscall buffers via tracked-region check ([5dc958d](https://github.com/Dicklesworthstone/frankenlibc/commit/5dc958d03dd3e56a8841984e4c35da5d6d1dcce7))
- Bound socket syscall buffers ([01ec384](https://github.com/Dicklesworthstone/frankenlibc/commit/01ec384c785d1e57f5cba348532a3798c09432e0))
- Bound wchar descriptor names ([7ee075e](https://github.com/Dicklesworthstone/frankenlibc/commit/7ee075eb79ad3cb72b68849214a3f9c98112bf61))
- Bound DNS compression name scans ([1ebc198](https://github.com/Dicklesworthstone/frankenlibc/commit/1ebc198d444c8ff7a9f86d1da634ce91b3326daf))
- Bound stringlist find scans ([db3517c](https://github.com/Dicklesworthstone/frankenlibc/commit/db3517c9))
- Bound `gethostbyname2` request scan ([f970e5a](https://github.com/Dicklesworthstone/frankenlibc/commit/f970e5ae2217dbecf9576044c9e21cf81e7d3938))
- Bound host loader path scan ([da86933](https://github.com/Dicklesworthstone/frankenlibc/commit/da8693352c67d141ae3df2da0702d4e6aae14855))
- Bound scanf input scans ([45fffa6](https://github.com/Dicklesworthstone/frankenlibc/commit/45fffa61a05c8fdb8c25e93b45527d58808088f3))
- ~100 additional `fix: bound <X> scans` commits across pwd/grp, netgroup, mntent, mount path, environment lookup, glob, getopt, regex, and aliases — every C-string boundary became EFAULT-correct against malformed pointers

---

## Phase 10 -- Fuzzing Sweep and CVE-Class Bug Burndown (2026-04-22 .. 2026-04-26)

~25 new `cargo-fuzz` targets added in 5 days under Epics **bd-dvr22 / bd-jy4qu / bd-o4yda**. Real bugs found and fixed inside library code from those fuzzers, including a 4 GB XDR denial-of-service, `xdr_*` `elsize=0` OOB read, `printf %g` precision-overflow panic, reentrant malloc panic, and `atfork` lock-holding deadlock. stdio printf/scanf table-driven grammar/synthesis pipeline lands under Epic **bd-9chy.26**. Total exported symbol count crossed **4,119** (from ~3,980), propagated to README, FEATURE_PARITY, reality_report, and the CVE arena fixtures.

### New Fuzz Targets

- `fuzz_mmap` + 4 bug beads ([5fdae36](https://github.com/Dicklesworthstone/frankenlibc/commit/5fdae36de7843fb2e81c06a07deb1c8960b54e8b))
- `fuzz_socket` ([693bb76](https://github.com/Dicklesworthstone/frankenlibc/commit/693bb766c9ea99d5b36ed8cb6f4670eab046680b))
- `fuzz_signal` ([f117435](https://github.com/Dicklesworthstone/frankenlibc/commit/f117435b7f576a5f679e39a646fef63bd3bbe926))
- `fuzz_fortify` ([94a8c7a](https://github.com/Dicklesworthstone/frankenlibc/commit/94a8c7a7bc815b4fac520e991ce3343e072da894))
- `fuzz_setjmp` + `fuzz_dlfcn` ([d9c7c43](https://github.com/Dicklesworthstone/frankenlibc/commit/d9c7c43d))
- `fuzz_wchar` ([8ccb6b0](https://github.com/Dicklesworthstone/frankenlibc/commit/8ccb6b0933773b6e537ace0f812a66ca8d1494cb))
- `fuzz_pthread_sync_misc` ([9d04c07](https://github.com/Dicklesworthstone/frankenlibc/commit/9d04c07afed20372c9b45904de51d1badcb541f3))
- `fuzz_xdr` + close 4 GB DoS + elsize=0 OOB ([f7581b5](https://github.com/Dicklesworthstone/frankenlibc/commit/f7581b5e081e2307766faa62674493fddc01b136))
- Structure-aware harnesses across XDR, regex, scanf, malloc, printf, resolver, iconv, dirent, ctype, time/math/inet — 16 total fuzz targets

### Bug Fixes From Fuzz Discovery

- Cap printf float-format precision at 65535 to avoid fmt panic ([9502184](https://github.com/Dicklesworthstone/frankenlibc/commit/9502184f4763222a10d6894f90c40ccc313dbb25))
- `format_g` switches to `%e` when rounding overflows precision (Epic bd-ju24y) ([7df551a](https://github.com/Dicklesworthstone/frankenlibc/commit/7df551a56f0bb6a346cc2d318beb7d25f872217e))
- Per-thread reentry guards in malloc ([6c60fbf](https://github.com/Dicklesworthstone/frankenlibc/commit/6c60fbf7e482ccb40fb98f7229d955bb04a13835))
- Swap-extract `on_exit`/`at_quick_exit` handlers instead of holding lock (Epic bd-3jpoz) ([7fca17e](https://github.com/Dicklesworthstone/frankenlibc/commit/7fca17e9ee2415643b8f998f21c8e7001c724cc6))

### Symbol-Count Crossing

- Propagate `total_exported=4119` surface counts to README, FEATURE_PARITY, reality_report, and CVE arena ([141a797](https://github.com/Dicklesworthstone/frankenlibc/commit/141a797d))
- libcrypt aliases, `fchmodat2`, `eventfd2`, `rt_sig*` additions

---

## Phase 9 -- Syscall Surface Lockdown and Native-Only ABI (2026-04-16 .. 2026-04-21)

Closing out the `libc::syscall` callthrough census to **zero** (Epic **bd-h5x** finalization: 124 → 0 calls; see `memory/syscall_migration_complete.md`). New typed syscall wrappers added for io_uring, landlock, futex2, process_vm_*, scheduler, getrandom/arc4random, pidfd, statx, execveat, namespace ops, personality, and process_madvise/mrelease. Replacement-guard callthroughs aggressively trimmed across pthread, stdio, stdlib, unistd, and `glibc_internal_abi`. aarch64 arch-gate bring-up: `compile_error!` documents x86_64-primary + aarch64-supported (Epic **bd-10pq**).

### Native Syscall Wrapper Expansion

- io_uring, landlock, scheduling wrappers (22 callsites migrated) ([8f96a74](https://github.com/Dicklesworthstone/frankenlibc/commit/8f96a740d69c1805147dda0157952fe8f4b3bbe5))
- Specialized syscalls (20 callsites migrated) ([c62c477](https://github.com/Dicklesworthstone/frankenlibc/commit/c62c4770d2543f4f9c29de61b01ce1e77cb4b04e))
- Mount API wrappers + unistd callsite migration ([e4f2e6f](https://github.com/Dicklesworthstone/frankenlibc/commit/e4f2e6f7b50b7c26935df6eb320d80cc44d49ec7))
- Personality, `process_madvise`/`process_mrelease` wrappers ([d2c9740](https://github.com/Dicklesworthstone/frankenlibc/commit/d2c974053f7d4fd6aeb3eb81d00cbc152ad58d83))
- Eliminate all `libc::syscall` calls from `glibc_internal_abi.rs` ([f13f093](https://github.com/Dicklesworthstone/frankenlibc/commit/f13f0931ca4c95ea846174f5d7bd44c4c9b9b72c))

### Native-Only pthread

- Promote pthread mutex/cond/lifecycle to `Implemented` ([09ae220](https://github.com/Dicklesworthstone/frankenlibc/commit/09ae22010860fde585d5805a64acf510c12cd2a5))
- Make mutex and condvar ABI native-only ([70597c1](https://github.com/Dicklesworthstone/frankenlibc/commit/70597c14bb72c73f91d2f9a33be87bc062a38f84))

### Architecture Gate

- `compile_error!` arch gate documenting x86_64 + aarch64 support matrix (Epic bd-10pq) ([5cfb2fc](https://github.com/Dicklesworthstone/frankenlibc/commit/5cfb2fc5289a8fbe0499a36750a0716783d74ff2))
- Complete safety documentation for all `unsafe` syscall wrappers ([cb0d133](https://github.com/Dicklesworthstone/frankenlibc/commit/cb0d133f480c373cde6efbfd7f57cf473ca3bf9b))

---

## Phase 8 -- Conformance Harness Saturation and Raw-Syscall Migration (2026-03-22 .. 2026-04-15)

Conformance fixture coverage transitions from "selective" to "exhaustive per subsystem." A parallel campaign (Epic **bd-h5x**) replaces every `libc::syscall` callsite with native raw-syscall veneers. Membrane policy instrumentation and replacement-guard census become routine. Shared-futex support shipped for pthread sync primitives.

### Conformance Harness Saturation

- Locale, resource, termios ops conformance tests ([e91ed7e](https://github.com/Dicklesworthstone/frankenlibc/commit/e91ed7e472c1c4d70b578ef100027fc58b539bda))
- Pthread cond/mutex/thread harnesses ([4db6876](https://github.com/Dicklesworthstone/frankenlibc/commit/4db687658e6159bdf4926ba2cfb72da53c5c1e15))
- `signal_ops` + `time_ops` harnesses ([c976eab](https://github.com/Dicklesworthstone/frankenlibc/commit/c976eabf9c8a2c598cd1c79cd0de877093b12439))
- Final 6 conformance harnesses completing fixture coverage ([a675cca](https://github.com/Dicklesworthstone/frankenlibc/commit/a675cca96200e790c3d184a7cd286b2f27fa75ee))
- `stdio_evidence.rs` JSONL schema and parser ([b3682cf](https://github.com/Dicklesworthstone/frankenlibc/commit/b3682cfcd0fae511850b8f87810dcbdd415074bb))

### Raw-Syscall Migration (Epic bd-h5x: 124 → 0 libc::syscall calls)

- Migrate `malloc_abi` and `rpc_abi` to native syscalls ([aa960cd](https://github.com/Dicklesworthstone/frankenlibc/commit/aa960cd18f3ec5939dca1efa77461aadcf4b1cb9))
- `io_internal_abi` from `libc::syscall` to native raw syscalls ([02c0369](https://github.com/Dicklesworthstone/frankenlibc/commit/02c0369086a4c1d591caaa8de522b11304e7ac8f))
- Migrate 48 `libc::syscall` calls to raw syscalls in `glibc_internal_abi.rs` ([b0396cb](https://github.com/Dicklesworthstone/frankenlibc/commit/b0396cb41f54a256e68668a10e0705ea0e80bd21))

### pthread and stdio

- Shared futex support and conformance suite expansion ([9fc4eee](https://github.com/Dicklesworthstone/frankenlibc/commit/9fc4eee0da70548e8d780d0859ce0eec08bad12e))
- scanf length-modifier width wrapping + printf tweaks ([e0152ea](https://github.com/Dicklesworthstone/frankenlibc/commit/e0152ea4297f10351aba6210d6cf430d78208a61))

---



---

## Phase 7 -- Allocator Hardening and GCT Elimination Endgame (2026-03-19 .. 2026-03-21)

Final hardening pass across the allocator, membrane, and ABI boundary. Eliminated the last dlsym-forwarding stubs in gconv and RPC. Resolved deep startup-ordering issues in the pre-TLS allocator and dlerror paths.

### Allocator and Startup Safety

- Replace `dlvsym`-based `memcpy`/`memmove`/`memset` with `std` intrinsics and add fork safety ([31aafb4](https://github.com/Dicklesworthstone/frankenlibc/commit/31aafb45127751dfb35d973e1b81345baf184bf7))
- Add pre-TLS bump allocator, refactor `dirent`, fix `posix_spawn` PATH lookup ([ba364d2](https://github.com/Dicklesworthstone/frankenlibc/commit/ba364d29430f24496331a120daf20f3ea5cc0f54))
- Add `memalign` reentry guard, expose `validate_ptr` for Galois pointer safety ([c78aeab](https://github.com/Dicklesworthstone/frankenlibc/commit/c78aeab2bb396b55711dfa028827f16a411c6748))
- Prevent reentrant TLS panic in `dlerror` and add startup guard to runtime policy ([02f308d](https://github.com/Dicklesworthstone/frankenlibc/commit/02f308da4f5c6ea5516fbfde2830909213743437))
- Runtime policy refactoring and `startup_abi` cleanup ([8a6496e](https://github.com/Dicklesworthstone/frankenlibc/commit/8a6496e57360c94403c38e6f05c43b83ede00cfe))
- Allocator improvements and refinements ([b3f5814](https://github.com/Dicklesworthstone/frankenlibc/commit/b3f5814197d2d9eb3f1caa112c57516e3aa7318a), [0d01c5d](https://github.com/Dicklesworthstone/frankenlibc/commit/0d01c5ddea0f892b1207565d839fa98d0e2df7bb))

### GCT Elimination -- gconv, RPC, and dlfcn

- Phase-1 `dlfcn` replacement mode and comprehensive harness test coverage ([26cad3c](https://github.com/Dicklesworthstone/frankenlibc/commit/26cad3c623c7d532b208765119fbf94425ec5a40))
- Replace all RPC/gconv dlsym call-throughs with native safe defaults ([a42a835](https://github.com/Dicklesworthstone/frankenlibc/commit/a42a83531ffd2a0d5a8eb07f9f016d7a345139cc))
- Rewrite gconv shims as native iconv wrappers ([3c0d109](https://github.com/Dicklesworthstone/frankenlibc/commit/3c0d109cb2ca1b93d2032e301819f403c24428ff))
- Replace gconv dlsym-forwarding stubs with native safe-defaults ([11e257f](https://github.com/Dicklesworthstone/frankenlibc/commit/11e257ffb8903cc38e7da5792e0db1653ee19a82))
- Add gconv ABI unit tests and update support matrix ([6b0f2a3](https://github.com/Dicklesworthstone/frankenlibc/commit/6b0f2a306f39ec2282ac3bbcb8e95a23363e24df))
- Harden `alphasort`/`scandir` in dirent ([3c0d109](https://github.com/Dicklesworthstone/frankenlibc/commit/3c0d109cb2ca1b93d2032e301819f403c24428ff))

### Membrane and Arena

- Add `check_ownership` fast path, fix arena API, harden EBR test ([db20e51](https://github.com/Dicklesworthstone/frankenlibc/commit/db20e512d488387980a9df7c726f0bc5fb6e6a64))
- Replace manual JSON formatting with serde in validation pipeline ([f43840a](https://github.com/Dicklesworthstone/frankenlibc/commit/f43840ab980b62cfea98b98d807bb6e2230a24e8))
- Replace ioctl-based interface enumeration with `/sys/class/net` and fix runtime math ([7537aaf](https://github.com/Dicklesworthstone/frankenlibc/commit/7537aafadd33ab00795d6a15ce8f881e7bd5424d))
- Flat combiner tuning, `known_remaining` caching, EBR epoch advancement ([ec2f021](https://github.com/Dicklesworthstone/frankenlibc/commit/ec2f0214898bac74b27cdaa0247287731e044c43))

### Bug Fixes

- Pthread cancel type fix, stdio buffered I/O improvements, DNS resolver hardening ([3014cf9](https://github.com/Dicklesworthstone/frankenlibc/commit/3014cf99f881eacf527df979165a726ed670a214))
- POSIX octal alt-form zero output, saturating quarantine accounting, bloom filter optimization ([812640e](https://github.com/Dicklesworthstone/frankenlibc/commit/812640e1544cc994138053fec8936ffb4b51ed0a))
- `pthread_testcancel` now exits thread, glob NOESCAPE fixes ([654248e](https://github.com/Dicklesworthstone/frankenlibc/commit/654248e2985dda251038323759f9d961d2446ea2))
- Centralize `set_abi_errno`, replace dlsym passthrough macro with native implementations, fix pthread join/detach race ([988ab9a](https://github.com/Dicklesworthstone/frankenlibc/commit/988ab9aec7d68ae7cbe64a5e392a514c394885cf))
- Simplify service alias test fixtures and apply rustfmt to stdio ([a09b1ac](https://github.com/Dicklesworthstone/frankenlibc/commit/a09b1ac7018e6274dc32160a6511106f7580a7a6))

---

## Phase 6 -- Formal Proofs, EBR, IO Nativization, and Test Coverage (2026-03-12 .. 2026-03-20)

Major investment in formal verification infrastructure, epoch-based reclamation, IO internals nativization, and a massive test expansion campaign. Coverage grew from ~60% to near-complete across ABI modules.

### Formal Proofs and Verification

- 39 formal proofs for SOS certificates, barrier invariance, and HJI viability ([1da0390](https://github.com/Dicklesworthstone/frankenlibc/commit/1da0390e14963f353d03f39708ee6ad7ad719f72))
- 24 formal proofs for Galois connection, lattice monotonicity, and probability bounds ([1022898](https://github.com/Dicklesworthstone/frankenlibc/commit/1022898ccce9494c03bccb15dba8b659708971b6))
- 28 formal proofs for sheaf consistency, CPOMDP feasibility, coupling bounds, spectral witnesses ([28ae43f](https://github.com/Dicklesworthstone/frankenlibc/commit/28ae43f4d99c3e42cdd2edc879e3f330af694a33))
- 8 formal proofs for strict refinement, hardened safety, deterministic replay ([a709d93](https://github.com/Dicklesworthstone/frankenlibc/commit/a709d93a40efe6d89335557b2a0bf8350a2d7c9e))
- 12 E2E tests for branch-diversity, snapshot capture, multi-kernel interaction ([0e019cc](https://github.com/Dicklesworthstone/frankenlibc/commit/0e019cc145fb74b847fe5faf5d035cc2848efb72))
- CounterexampleWitness support in proof binder validator ([39bd169](https://github.com/Dicklesworthstone/frankenlibc/commit/39bd1695b66c15c44495fcb31bb395ff10a29fb4))
- POSIX obligation traceability matrix report and verification gate ([b730a06](https://github.com/Dicklesworthstone/frankenlibc/commit/b730a06f8b1a71885373f0ff16d5566ef76e7fea))

### Epoch-Based Reclamation (EBR)

- Add EBR property tests, fix TLS handle caching, reorganize symbols ([b22f391](https://github.com/Dicklesworthstone/frankenlibc/commit/b22f391535e98a6ff64c178c0db5bdc943fe82b6))
- Fix EBR reclaim off-by-one and TLS-cached handle UAF hazard ([853604f](https://github.com/Dicklesworthstone/frankenlibc/commit/853604f5d5735c6c448fe57381ccf70957a7f510))
- Integrate EBR deallocation, fix quarantine capture, support standalone builds ([9bbd9ba](https://github.com/Dicklesworthstone/frankenlibc/commit/9bbd9ba198af3e4d285341b9373e0f976496a485))
- Upgrade generation counters to u64 and rewrite persistence algorithm ([3e48d57](https://github.com/Dicklesworthstone/frankenlibc/commit/3e48d576eae568f9162c38b34a862bf5113ac462))
- Upgrade TLS cache epoch atomics to Acquire/Release ordering ([bb1dd9e](https://github.com/Dicklesworthstone/frankenlibc/commit/bb1dd9e320e4653d178fc1b9ab49a09279ca02c1))
- Reorder arena free to write quarantine state before epoch bump ([1314628](https://github.com/Dicklesworthstone/frankenlibc/commit/1314628099b025a1f804453daba76c652e708c55))

### IO Internal ABI Nativization

- Convert 16 glibc IO vtable stubs from call-through to native no-ops ([3011b48](https://github.com/Dicklesworthstone/frankenlibc/commit/3011b48bafe231431ce1d35ebee94f7af6ff71a4))
- Convert 6 `io_internal_abi` symbols from GlibcCallThrough to native Implemented ([2b081e7](https://github.com/Dicklesworthstone/frankenlibc/commit/2b081e72f26d6ea86ef8ac8af8bdc6617277b13e))
- Implement native `_IO_flush_all_linebuffered` and `_IO_getline` ([b877146](https://github.com/Dicklesworthstone/frankenlibc/commit/b877146038eb048b08e21d573adcac551de653ca))
- Expand IO internal ABI and refresh support matrix conformance ([3a987dc](https://github.com/Dicklesworthstone/frankenlibc/commit/3a987dc12d0397f5a41464658bde6a5c7a493ed3))
- Implement pure IO column adjustment and expand structured logging ([752d9f8](https://github.com/Dicklesworthstone/frankenlibc/commit/752d9f8cd0b02ec3142e51da8346c31c16a04f6b))

### Concurrency Primitives (Alien CS)

- Flat combining, RCU/QSBR, and seqlock concurrency primitives ([ac9be98](https://github.com/Dicklesworthstone/frankenlibc/commit/ac9be987c01af519e6c68770ad660bee65d64470))
- EBR + complete Alien CS test coverage with proptest and E2E scaling ([613e5b4](https://github.com/Dicklesworthstone/frankenlibc/commit/613e5b4160cfe8802dd91ed5974fe13b1bd6349c))
- Unified Alien CS metrics module with contention scoring ([80eba38](https://github.com/Dicklesworthstone/frankenlibc/commit/80eba3874edaa3ee84298164c9a5d72a29b564f1))
- Criterion benchmark suite for Alien CS concurrency primitives ([6aadc8d](https://github.com/Dicklesworthstone/frankenlibc/commit/6aadc8d06e09d86f721312987beccf18f2ee726a))

### Refactoring

- Rewrite printf/exit for stream-based I/O and extract atexit handlers ([943d0a9](https://github.com/Dicklesworthstone/frankenlibc/commit/943d0a9fbbb4b4ec55c64c5e7126fde5279826ec))
- Optimize pthread, implement IO natives, harden dlfcn, widen generation counters ([b53d925](https://github.com/Dicklesworthstone/frankenlibc/commit/b53d92589661e6bade3b751cc6a3430cbaa4e060))
- Improve iconv safety, fix `tdelete`, add spawn attrs ([971ba65](https://github.com/Dicklesworthstone/frankenlibc/commit/971ba65a781dff3f3fe7debfe0b442ced6ee1adc))
- Reduce arena lock contention and refresh CVE test artifacts ([2ae7374](https://github.com/Dicklesworthstone/frankenlibc/commit/2ae73740b12d8d84d939e06b1daf11f2ecb24d03))
- Extract shared `now_utc_iso_like` into dedicated util module ([66a35f1](https://github.com/Dicklesworthstone/frankenlibc/commit/66a35f1c697bd50c0db2155041b992ddbfbbae70))

### Test Expansion Campaign

- 21 TSM pipeline E2E tests ([042775b](https://github.com/Dicklesworthstone/frankenlibc/commit/042775b206babe6b4ec6c30f00fe79f1138b209b))
- Property-based testing framework with 43 properties ([794e7e1](https://github.com/Dicklesworthstone/frankenlibc/commit/794e7e18619714f9160e2169359c89f91f436ba2))
- Property-based tests for check_oracle and fingerprint modules ([066cc5f](https://github.com/Dicklesworthstone/frankenlibc/commit/066cc5f209d25a8dd0d5a4c9da42edfc9e5a6edf))
- E2E composition tests and test code cleanup ([85dcb9d](https://github.com/Dicklesworthstone/frankenlibc/commit/85dcb9d30dc132e6663c49ca2ab7f6e58a6611bd))
- Expand poll (19->56), socket (20->45), pwd (15->32), mmap (15->21) test coverage ([09ae95f](https://github.com/Dicklesworthstone/frankenlibc/commit/09ae95fb351419a915ed4e8310815bb0f15bce45), [880eab2](https://github.com/Dicklesworthstone/frankenlibc/commit/880eab21bfdee961a0b5542048785f6537c67524), [86c0a24](https://github.com/Dicklesworthstone/frankenlibc/commit/86c0a246192e4f6d502fd3ae07e3014f7b727af6), [e97da22](https://github.com/Dicklesworthstone/frankenlibc/commit/e97da2233b6f94291f8df335e51a5065499dcfc5))
- Expand fenv (11->19), err (17->26), dlfcn (12->17), isoc (26->37), string_ext (16->22) test coverage
- Expand 6 low-coverage test files (+33 tests) ([7af4c4a](https://github.com/Dicklesworthstone/frankenlibc/commit/7af4c4ad43fbfaee73ed626bf9fd02f657a162de))
- Fix `waitid` missing 5th `rusage` arg and serialize fork+wait-any tests ([60e6b9c](https://github.com/Dicklesworthstone/frankenlibc/commit/60e6b9caaaa963e8f7a5ebdf0ff5bcfa26d245b4))
- Errno edge-case prioritization report and pthread condvar conformance ([b13a67e](https://github.com/Dicklesworthstone/frankenlibc/commit/b13a67e09e1fa3e944e4de879138c7395c996197))

### Fuzzing

- Phase-2 fuzz targets: evidence ledger, SLO contracts ([0483906](https://github.com/Dicklesworthstone/frankenlibc/commit/048390624ecb5292d141db059ab5ee875d2cef29))
- Structure-aware string fuzz target ([888c01f](https://github.com/Dicklesworthstone/frankenlibc/commit/888c01f12bcd69a93ae2e62a24d4f6e1310c4fae))
- Structure-aware malloc and printf fuzz targets ([3907108](https://github.com/Dicklesworthstone/frankenlibc/commit/3907108524c2da1f394285dfe270809e28265eab))
- Phase-2 resolver, regex, scanf fuzz targets ([34eaba2](https://github.com/Dicklesworthstone/frankenlibc/commit/34eaba2f7536db4586044a8aefc6cb747b39606f))
- Fuzz nightly campaign runner and CI gate ([3f913fe](https://github.com/Dicklesworthstone/frankenlibc/commit/3f913feeca27e544cc831bc85ceb7904c831ebc6))
- Add iconv/dirent/resolv/pwd_grp fuzz targets (12->16 total) ([b27025a](https://github.com/Dicklesworthstone/frankenlibc/commit/b27025a9f37bd77dcae9d4fa31aba60ed22511e9))
- Stdlib, ctype, time/math/inet fuzz targets ([f697a0d](https://github.com/Dicklesworthstone/frankenlibc/commit/f697a0dec5f934a523623ad852e0515e52fb4976), [639d0bd](https://github.com/Dicklesworthstone/frankenlibc/commit/639d0bd79d8ac90afe1b0f4afedd105449739f39))

### Resolver

- Return multi-address addrinfo chains and add membrane policy to resolver functions ([d5d7525](https://github.com/Dicklesworthstone/frankenlibc/commit/d5d7525a9a3c23d6d51e7183c5bb93ae0d77ea71))

### setjmp/longjmp

- Add `JmpBuf` C ABI serialization and improve longjmp safety ([faa1790](https://github.com/Dicklesworthstone/frankenlibc/commit/faa17900fa74f8f54d4e21cd1ba762a2e40f527e))

### CI and Conformance

- Deterministic stub priority ranking generator with `--check` mode ([fe931e1](https://github.com/Dicklesworthstone/frankenlibc/commit/fe931e138f5c4bd1d28e38a7a3b3e7cee9b6a43a))
- Regenerate all conformance and evidence artifacts ([7f52483](https://github.com/Dicklesworthstone/frankenlibc/commit/7f524830da6570eae9d0b9d0b8d237312b87c46a))
- Resolve 44 workspace-wide clippy errors blocking CI ([d52870b](https://github.com/Dicklesworthstone/frankenlibc/commit/d52870b5879bf8996648488b6ed4428ff9a17195))
- Dynamic loader (dlfcn) conformance harness ([752609e](https://github.com/Dicklesworthstone/frankenlibc/commit/752609e0c432c3080c87729da802947c38985950))

### Bug Fixes

- Replace `eprintln!` with direct `sys_write_fd` in ABI error paths ([93be020](https://github.com/Dicklesworthstone/frankenlibc/commit/93be020564c4edec19f01a13bf982bce795c34e3))
- Sanitize non-finite floats in CliffordController observations ([fa9876b](https://github.com/Dicklesworthstone/frankenlibc/commit/fa9876bcd0dfaa9a1760e2160a786f43973cb97b))
- Add test isolation lock for global `CACHED_LEVEL` atomic state ([4de5d1e](https://github.com/Dicklesworthstone/frankenlibc/commit/4de5d1ed86ea3d7bdd31573f8ef6f4dda32990dd))

### Documentation

- Update README coverage table to reflect 3457 implemented symbols ([9ec086f](https://github.com/Dicklesworthstone/frankenlibc/commit/9ec086feae57c84cd74d3c9c4e4a224aa6c9fa84))
- Update feature parity to 97.1% native coverage and add baseline benchmark ([8fc357e](https://github.com/Dicklesworthstone/frankenlibc/commit/8fc357e34beafe0aa411dd94ae32d9eac1992b21))
- Major README expansion with ABI coverage and conformance documentation (+784 lines) ([1940361](https://github.com/Dicklesworthstone/frankenlibc/commit/1940361ecba359afab39bb4daee5b0a84a47d875))
- Major README refresh with updated architecture and usage documentation ([e1a9713](https://github.com/Dicklesworthstone/frankenlibc/commit/e1a97133cf9fa64e11f4c589ea28484a3cd03232))

---

## Phase 5 -- GCT Elimination Campaign and ABI Module Expansion (2026-02-25 .. 2026-03-10)

Systematic campaign to eliminate GlibcCallThrough (GCT) symbols. Started at 461 GCT, drove down to 117. Nativized XDR (68 symbols), RPC (35 symbols), DNS resolver internals, fenv (full x86_64 inline asm), ctype/wchar locale tables, and dozens of glibc internal symbols. Simultaneously expanded the classified surface past 3900 symbols and established the fuzz, benchmark, and Gentoo validation infrastructure.

### GCT Elimination (461 -> 117)

- Nativize all 68 XDR symbols with pure Rust RFC 4506 implementation ([d634f8e](https://github.com/Dicklesworthstone/frankenlibc/commit/d634f8e207dbed80b5e15bf4b5f2702ae1dd94db))
- Nativize 35 RPC symbols + add ABI test suites for ctype/rpc/search/stdbit ([fc193d0](https://github.com/Dicklesworthstone/frankenlibc/commit/fc193d08ec504bc11ecd7e4f28c17c97a60c9c46))
- Nativize `fenv_abi` with full x86_64 inline asm, nativize 80+ glibc_internal symbols ([89b8cfc](https://github.com/Dicklesworthstone/frankenlibc/commit/89b8cfc257572f7af81bce96aebdb01bde5f6352))
- Nativize ~60 glibc internal symbols, replacing dlsym passthrough with direct delegation ([238b93b](https://github.com/Dicklesworthstone/frankenlibc/commit/238b93b3110f355c24c27c75c559c0cfbbf957c8))
- Nativize `__ctype_b`/`tolower`/`toupper` and `__ctype_get_mb_cur_max` ([dcda524](https://github.com/Dicklesworthstone/frankenlibc/commit/dcda524f5772aec9128d3669ab44239398fc2a4c))
- Nativize 31 more GCT symbols: obstack, clone, pthread_cleanup, NSS, printf-ext ([4f695ec](https://github.com/Dicklesworthstone/frankenlibc/commit/4f695ecd73fb6dbf6d1769b46594a05fd8041ec9))
- Nativize `ns_name_*`, `inet6_opt_*`, `inet6_option_*`, `inet6_rth_*` symbol families ([3d13faa](https://github.com/Dicklesworthstone/frankenlibc/commit/3d13faa49e4e69eeb2a68cdeb3ef22fab6713cb5))
- Nativize 6 stdio vtable flow symbols: `__overflow`, `__uflow`, `__underflow`, `__woverflow`, `__wuflow`, `__wunderflow` ([cbc4312](https://github.com/Dicklesworthstone/frankenlibc/commit/cbc431202035eee899417f8d500c24bb25365ab1))
- Nativize 8 public `res_*` DNS API as forwarders to `__res_*` GCT ([c7fc431](https://github.com/Dicklesworthstone/frankenlibc/commit/c7fc4313c3ae6ca205e2e834a9cd04b55f130ec0))
- Nativize DNS resolver and f128 parse internals, fix stdio type safety ([6ce3042](https://github.com/Dicklesworthstone/frankenlibc/commit/6ce30428878982efd5c1b5ba693dfd5285de5f67))
- Nativize `dl_iterate_phdr` and `dladdr` with membrane-gated fallbacks ([8c923ae](https://github.com/Dicklesworthstone/frankenlibc/commit/8c923aef48a2e303a95d54d5922fafaf210c81a8))
- Nativize 13 GCT symbols: argp/ucontext/obstack ([ee2187c](https://github.com/Dicklesworthstone/frankenlibc/commit/ee2187cab45ee568d37df7fa425d6c885bea5881))
- Nativize `__ivaliduser` as deny-all (`.rhosts` auth deprecated) ([9b6c82c](https://github.com/Dicklesworthstone/frankenlibc/commit/9b6c82cad69aac8bf3fecb8c8f64d62570d7cfa3))
- Nativize `rcmd`/`rexec` deny, `parse_printf_format`, `__asprintf` ([ff05008](https://github.com/Dicklesworthstone/frankenlibc/commit/ff05008de49b44c87dada8033245c8cd191430f4))
- Nativize multicast filters, `pidfd_spawn`, `bindresvport`, `innetgr`, `sysctl` ([41fe83a](https://github.com/Dicklesworthstone/frankenlibc/commit/41fe83a7d109291cbb1c52943163b522fd162a5d))
- Nativize mcount, BSD regex, `mq_open`, `sem_clockwait`, NSAP ([531b6bb](https://github.com/Dicklesworthstone/frankenlibc/commit/531b6bb90bb0609cc5adf795930e5e5f35b65d36))
- Promote ctype/wchar locale variants to native implementations ([ebed1f8](https://github.com/Dicklesworthstone/frankenlibc/commit/ebed1f8c612c6286178af9836ab813ee812b0e91))
- Eliminate glibc call-throughs with native Rust implementations across 11 ABI modules ([4739c24](https://github.com/Dicklesworthstone/frankenlibc/commit/4739c24116671ccce97e2c1d3f337c6454434974))
- Remove 175 duplicate `#[no_mangle]` symbol definitions ([b01935c](https://github.com/Dicklesworthstone/frankenlibc/commit/b01935c3fdfe856f810ab56cec4b4d934592625c))
- Remove 7 duplicate dlsym_passthrough already native in pthread/fortify ([e314322](https://github.com/Dicklesworthstone/frankenlibc/commit/e314322703b77ed368800f667a5c4be487eda583))
- Remove dead `__libc_*` internal malloc aliases ([ba7ff23](https://github.com/Dicklesworthstone/frankenlibc/commit/ba7ff23f57f323545ec70d53f1d55c721e16b652))
- Fix `getsubopt` comma-aliasing bug, resolve 48 Rust 2024 E0133 warnings ([8b74b2a](https://github.com/Dicklesworthstone/frankenlibc/commit/8b74b2aa941b5ffd313c46db1944f004683c8867))
- Eliminate unsafe stdin access in `wscanf`/`vwscanf` via `stdin_stream_id()` ([026508a](https://github.com/Dicklesworthstone/frankenlibc/commit/026508a0ccca85421e6ba4248702fc4398d61604))

### New ABI Modules

- Add 6 new ABI modules: fortify, glibc internals, IO internals, ISO C, RPC, C23 stdbit ([e437a8b](https://github.com/Dicklesworthstone/frankenlibc/commit/e437a8b9aea4c81ac5c08ebca138b78767cdab5b))
- Massive expansion of existing ABI modules with glibc internal aliases, C23 compat, POSIX coverage ([563d01f](https://github.com/Dicklesworthstone/frankenlibc/commit/563d01f54eb5ae4c404854973187f117cceab7cc))
- C23 IEEE 754-2019 math functions and glibc internal ABI stubs ([62b1c78](https://github.com/Dicklesworthstone/frankenlibc/commit/62b1c7839219298f3e3b39b13a6a92d344248a8a))
- Nocancel wrappers, complex math, malloc stats flat-combining, glibc internal stubs ([5092343](https://github.com/Dicklesworthstone/frankenlibc/commit/5092343d469a4df0c5f00afbd94d394ec45c2662))

### Native Implementations

- Native named semaphores via `/dev/shm` + `mmap`, replacing glibc callthrough ([41bb6fc](https://github.com/Dicklesworthstone/frankenlibc/commit/41bb6fc9a0fc60965d8b5ce35e787597bdf2de20))
- Native `posix_spawn` family via fork+exec ([15656ab](https://github.com/Dicklesworthstone/frankenlibc/commit/15656ab4cb1733ae3bbfe32fcba44994354d15e9))
- Native `res_init` resolver bootstrap + `Send` impl for `HashSlot` ([21de3eb](https://github.com/Dicklesworthstone/frankenlibc/commit/21de3eb25e967bfebb1e4655d525914df9cba5e6))
- Native pthread cancellation, `strptime`, wchar extensions, memstream stdio ([606f3ee](https://github.com/Dicklesworthstone/frankenlibc/commit/606f3eecbe7b3677da3351cb534db4248fecec16))
- Native scanf engine, `drand48`/`base64`/`ecvt`/`random`/`glob` stdlib extensions ([30b5e1b](https://github.com/Dicklesworthstone/frankenlibc/commit/30b5e1bd66e87055c6c404ae8adf9e0ab59e4f7b))
- POSIX regex engine in core ([def95ab](https://github.com/Dicklesworthstone/frankenlibc/commit/def95abb86de2664b1a3e0f4ce1607e043504563))
- `MemBacking` for memory streams, split buffer cursors, wide string extensions ([def95ab](https://github.com/Dicklesworthstone/frankenlibc/commit/def95abb86de2664b1a3e0f4ce1607e043504563))
- Cross-thread `pthread_setname_np`/`getname_np` via procfs ([d46cf35](https://github.com/Dicklesworthstone/frankenlibc/commit/d46cf355bb74b64e550ed319030002e319eed176))
- Native IDNA/Punycode, TLS dtors, aarch64 clobber fix ([856b2c5](https://github.com/Dicklesworthstone/frankenlibc/commit/856b2c50fecb38a43a50991f2f202f9b3b314a1a))
- Nativize `obstack_vprintf`, expand process/glibc coverage ([562c57a](https://github.com/Dicklesworthstone/frankenlibc/commit/562c57af9e8defe99abe2258a54813010f6f357d))
- Setjmp/longjmp and `tcgetattr`/`tcsetattr` promoted from todo! to phase-1 deterministic stubs ([605c5c3](https://github.com/Dicklesworthstone/frankenlibc/commit/605c5c31034e86d8af826c6ed933412199301a1e))

### Membrane Hardening

- Harden runtime math controllers against integer overflow, add cached check orderings ([50c9abe](https://github.com/Dicklesworthstone/frankenlibc/commit/50c9abebc595f34161e8e20e06a450df7daf1808))
- SOS barrier soundness verification, size-class fast path, memory model audit ([7119c9c](https://github.com/Dicklesworthstone/frankenlibc/commit/7119c9cf7d5b327d959bab10a9b7def3154d8bdb))
- `RcuMigration<T>` shadow-mode migration wrapper ([3222e9d](https://github.com/Dicklesworthstone/frankenlibc/commit/3222e9d5283c5f7fd9614812b1d41a139851d405))
- `SeqLock<T>`, harden bandit/sos_barrier tests, simplify string_abi fast paths ([8e7a01e](https://github.com/Dicklesworthstone/frankenlibc/commit/8e7a01e2e25a207c8d613acbe6cf4e32d12938cb))
- Size-class admissibility SOS barrier certificate ([1ded9a2](https://github.com/Dicklesworthstone/frankenlibc/commit/1ded9a2e63b84da4fd3f34483b483e5c994092f7))
- Add dlfcn ABI stubs and expand runtime math modules ([9b7b97e](https://github.com/Dicklesworthstone/frankenlibc/commit/9b7b97e8ffae9bd6841094064187a6f060725536))
- K-theory runtime math refinements ([4017836](https://github.com/Dicklesworthstone/frankenlibc/commit/40178361d3fbf595ad58c525780f3ce715ce133a))
- Stabilize runtime math tests against conservative bounds ([549bdf2](https://github.com/Dicklesworthstone/frankenlibc/commit/549bdf2a448e504d51440c30c6294bdfb8396e77))

### Test Expansion

- 114 integration tests for `math_abi`: trig, exp/log, rounding, Bessel, C23 ([45e42a2](https://github.com/Dicklesworthstone/frankenlibc/commit/45e42a27ccbefa9819345bc21e594d0179c5a0d9))
- 81 integration tests for 7 previously untested ABI modules ([a1b9990](https://github.com/Dicklesworthstone/frankenlibc/commit/a1b99905775feec0bebdd81c8fdef86868e08483))
- 51 integration tests for `_FORTIFY_SOURCE` ABI + dedup 3 matrix symbols ([1ed3f65](https://github.com/Dicklesworthstone/frankenlibc/commit/1ed3f65d58ba07a622a12366ebfdc23629c2e251))
- 32 integration tests for `locale_abi` ([1951b86](https://github.com/Dicklesworthstone/frankenlibc/commit/1951b860068795c3b397c6852d0df32eb9e01b61))
- 20 integration tests for `glibc_internal_abi` ([da63ddb](https://github.com/Dicklesworthstone/frankenlibc/commit/da63ddb0daa1055ec7f1cc816e26111924bde338))
- Expand string (20->82), wchar (16->105), unistd (29->70), stdio (40->54) test suites ([b3e4c57](https://github.com/Dicklesworthstone/frankenlibc/commit/b3e4c57f8fe8f6690aae8a04b233d5a4d2bb028d), [e17ce36](https://github.com/Dicklesworthstone/frankenlibc/commit/e17ce368b28b5fbf3654f520e180e1478f66f871), [c40af8f](https://github.com/Dicklesworthstone/frankenlibc/commit/c40af8f04e38eab12a5c82bd5872742952592dd7), [220bcad](https://github.com/Dicklesworthstone/frankenlibc/commit/220bcad9ef2b7cde9764f4bef87983c932254ba1))
- Expand time/inet/signal/socket test coverage (+2088 lines) ([fdbd2f1](https://github.com/Dicklesworthstone/frankenlibc/commit/fdbd2f1b3f35a1da36220412cd0303609395267e))
- Expand resolv/dlfcn/ctype/stdio test coverage (+52 tests, +935 lines) ([9f67041](https://github.com/Dicklesworthstone/frankenlibc/commit/9f67041753a960de84d2dcd2a210a3781404dc9a))
- Improve mmap and resource ABI test robustness ([71d537b](https://github.com/Dicklesworthstone/frankenlibc/commit/71d537b2b3fb062e158cdcff06f1560973599e98))
- Flat-combining vs lock-based contention benchmark matrix ([8ecdf17](https://github.com/Dicklesworthstone/frankenlibc/commit/8ecdf1742c26c9f60b2ee80c5fca911eccf7c4da))

### Gentoo Validation

- Gentoo portage validation framework and documentation ([dc318cf](https://github.com/Dicklesworthstone/frankenlibc/commit/dc318cf11c8be3ba80f93f6b135de75629d3e00e))
- Binary package cache infrastructure for build-once/test-many validation ([df8cc44](https://github.com/Dicklesworthstone/frankenlibc/commit/df8cc440ce312dee3e6614867a65d3d5c500d5ea))

### Smoke Tests

- Failure signature classification and startup diagnostics in LD_PRELOAD smoke suite ([0f38944](https://github.com/Dicklesworthstone/frankenlibc/commit/0f38944004bcb979a088b94cd230a554669df939))
- Simplified trace emission with structured `detail_json` ([d7e712c](https://github.com/Dicklesworthstone/frankenlibc/commit/d7e712c919c0a886f73d84d0826b8ab03975606d))

### Runtime Policy

- Runtime policy enforcement for process/VM syscall wrappers ([66115d7](https://github.com/Dicklesworthstone/frankenlibc/commit/66115d7151446a3b786e29a698499f39a84155a5))
- Membrane `runtime_policy` enforcement for SysV IPC and `process_vm` syscalls ([36564b8](https://github.com/Dicklesworthstone/frankenlibc/commit/36564b8d6972a061d71a6f9946c7fd7359e52fb0))
- Harden alignment checks, fix probe chain corruption, add `%a` format ([97235ef](https://github.com/Dicklesworthstone/frankenlibc/commit/97235eff7dd2b715e6a9a46270f8c6c1236eea3a))
- C23 log/exp compound functions and `totalorder` improvements ([764ecae](https://github.com/Dicklesworthstone/frankenlibc/commit/764ecae4daa9928684ba8b010c635132a9ff19ca))

### Bug Fixes

- Correct `strsep` to return last token and fix next-pointer offset ([11f073b](https://github.com/Dicklesworthstone/frankenlibc/commit/11f073b85a092151267db20aa64613b401895d56))
- Correct `ungetc` LIFO ordering and align `strsep` test expectation ([4f26965](https://github.com/Dicklesworthstone/frankenlibc/commit/4f26965339da1c9b1d9c6ff7b083b923cb331698))
- Handle EINTR in stdio write loops with proper retry logic ([d1bcddf](https://github.com/Dicklesworthstone/frankenlibc/commit/d1bcddf6b5a84914d2bd34be9305b9df8caf645b))
- Correct `strtod` -NaN sign bit via IEEE 754 bit manipulation ([038560b](https://github.com/Dicklesworthstone/frankenlibc/commit/038560b05a221cf7b3a537c72f516dee85a2a36a))
- Prevent out-of-bounds read in string functions when `scan_c_string` hits bound limit ([1cbcf02](https://github.com/Dicklesworthstone/frankenlibc/commit/1cbcf025c9cf5690eb2bb4461960dbbc9adb244b))
- Thread stack reclamation, TLS destructor ABI, allocator and stdlib correctness ([66cd3f6](https://github.com/Dicklesworthstone/frankenlibc/commit/66cd3f671d60bbe1512c31cb80ecfdef85f583d9))
- Recursive/errorcheck mutexes, barrier race fix, pthread subsystem hardening ([ed1e7f5](https://github.com/Dicklesworthstone/frankenlibc/commit/ed1e7f5bbbbd7e5b34ebb8c16b98b1d2eb49b441))
- Cross-subsystem correctness fixes for dirent, poll, process, signal, string, termios, time, wchar ([79fecd1](https://github.com/Dicklesworthstone/frankenlibc/commit/79fecd139aac06eedfb16c99885122419fef61c2))
- Stdio EINTR handling, malloc aligned allocations through membrane, stdlib errno propagation ([d498e50](https://github.com/Dicklesworthstone/frankenlibc/commit/d498e50411d517784d835db6fe9d3687ba23b534))
- Propagate errno on membrane Deny paths and add fallback allocation tracking ([b1d88dc](https://github.com/Dicklesworthstone/frankenlibc/commit/b1d88dc91e05fffaa24deec9188da92039a0ef60))
- Add errno to `recvmsg`/`accept4` Deny paths, `fseek` overflow check ([8c7b7ca](https://github.com/Dicklesworthstone/frankenlibc/commit/8c7b7ca3219595df3d69d46fad86f426bf6ab5bf))
- Correct float formatting for extreme/subnormal values and time edge cases ([213d966](https://github.com/Dicklesworthstone/frankenlibc/commit/213d966df74a8c855becaf90b5a7619a8314ec25))
- Robust stdio buffering with partial write loop and real errno extraction ([16ea8b3](https://github.com/Dicklesworthstone/frankenlibc/commit/16ea8b3d3659de5a321bc3f23c1953d7d978f72e))
- Eliminate TLS isolation bug, condvar TOCTOU race, allocator overflow ([088295e](https://github.com/Dicklesworthstone/frankenlibc/commit/088295ed371760de3d76ad59d8c35462e877ad64))
- Refine poll/select strict-mode semantics and extract real errno ([167e938](https://github.com/Dicklesworthstone/frankenlibc/commit/167e9388df4f2e56d5c2323825c26e45bc884858))
- Add missing `set_abi_errno()` calls on membrane Deny paths ([a8fad55](https://github.com/Dicklesworthstone/frankenlibc/commit/a8fad553ed25e48c4dbae738d54ce016390337f0))
- Seed EWMAs on first observation and fix LZ76 self-extending match bound ([520b681](https://github.com/Dicklesworthstone/frankenlibc/commit/520b68132ea87ac1a95c38c8063d603455e1c6ea))
- Harden fingerprint, page oracle, and runtime math subsystems ([0795566](https://github.com/Dicklesworthstone/frankenlibc/commit/0795566c0918a58efac107e3ee92fce1a6e2bc31))
- Correct `strxfrm` null-terminator write when buffer is exactly filled ([ec07a35](https://github.com/Dicklesworthstone/frankenlibc/commit/ec07a35fd96e9c3872a16e82853c783fd605151d))
- Condvar TOCTOU race, stack overflow guard, unify test serialization ([96e9df1](https://github.com/Dicklesworthstone/frankenlibc/commit/96e9df1c8f011e0a2a98a6d2c861172a31a0f1fc))
- Make `rand`/`srand` thread-safe, harden hex float exponent arithmetic ([b9ed04f](https://github.com/Dicklesworthstone/frankenlibc/commit/b9ed04f016ab6591cbcf88540bfebef3477932f7))

### Iconv

- Iconv codec dispatch taxonomy, phase-1 lookup table, deterministic fallback policies ([a96ce7f](https://github.com/Dicklesworthstone/frankenlibc/commit/a96ce7f54f3c2bfb4906fb9aa0709b38bfc559d8))
- Iconv scope ledger gate, E2E shadow divergence reporting, LD_PRELOAD diagnostics ([f286251](https://github.com/Dicklesworthstone/frankenlibc/commit/f2862512ea9aafae755cc324252480ad0e3fe105))

---

## Phase 4 -- Rapid ABI Surface Expansion and First Call-Through Elimination (2026-02-17 .. 2026-02-23)

Massive sprint to expand the classified ABI surface from ~250 to 900+ symbols, then begin replacing GlibcCallThrough wrappers with native Rust implementations. Adopted MIT license. Added social media assets.

### ABI Surface Expansion (250 -> 900+)

Symbols added in tiered waves:

- Socket/network and signal family coverage ([c023c10](https://github.com/Dicklesworthstone/frankenlibc/commit/c023c1016d8cec8e903708da117fb8aa266190e2))
- Time family with 10 new functions ([2ab900f](https://github.com/Dicklesworthstone/frankenlibc/commit/2ab900f64f3a0c24f6151884b1d361fc21448352))
- Process family with 16 new functions ([ca240c2](https://github.com/Dicklesworthstone/frankenlibc/commit/ca240c2b27f38efea148950897ba932d5d6cc183))
- Filesystem, `*at()`, and I/O extensions with 36 new functions ([f4d9911](https://github.com/Dicklesworthstone/frankenlibc/commit/f4d99112f3234ac665825b2f7d3dc8676fcac7c5))
- Epoll, eventfd, timerfd, memory locking, scheduler ABI ([e6b0fe1](https://github.com/Dicklesworthstone/frankenlibc/commit/e6b0fe18ec44ddb7bd563a979910e82d6fe63614))
- Inotify, interval timers, mknod/mkfifo, sysconf ABI ([0eefec7](https://github.com/Dicklesworthstone/frankenlibc/commit/0eefec725996dda6d185a785bbb94f54a6a8a23f))
- 12 string/memory + 13 legacy string/memory symbols with membrane protection ([f34ae51](https://github.com/Dicklesworthstone/frankenlibc/commit/f34ae516d62e6bd993870e978825262c309df70c), [a8b89a4](https://github.com/Dicklesworthstone/frankenlibc/commit/a8b89a401a257ef50ce5fb62201fb607d9a8a95c))
- 15 stdlib math/utility, 11 ctype/wchar, 18 math utility symbols ([601f51f](https://github.com/Dicklesworthstone/frankenlibc/commit/601f51f7832467b92e7fbe31252d569f1e803e0f), [4becf80](https://github.com/Dicklesworthstone/frankenlibc/commit/4becf80bab48f67835220c9082ee0400998aa1bc), [6e5e9b2](https://github.com/Dicklesworthstone/frankenlibc/commit/6e5e9b2727852b8678cf6b33585be88c1cd2f250))
- 19 + 35 single-precision math ABI wrappers with errno handling ([e09e4b6](https://github.com/Dicklesworthstone/frankenlibc/commit/e09e4b65d6656d04e15e4faf22a661b95ab1368c), [4a34e00](https://github.com/Dicklesworthstone/frankenlibc/commit/4a34e00e7d41fc12461871ed45f2366dbd4bebb8))
- 11 stdio symbols with full test coverage (getc, putc, fgetpos, fsetpos, fdopen, freopen, remove, getdelim, getline, tmpfile, tmpnam) ([0707735](https://github.com/Dicklesworthstone/frankenlibc/commit/07077355a8f46a6e99acda6703d556a3cb2b0ca6))
- 88 symbols exported in `libc.map` version script ([21ce2bd](https://github.com/Dicklesworthstone/frankenlibc/commit/21ce2bd8a9100ce441ca2417195cd6bc3c63d8ce))
- 46 symbols across scanf, time, getopt, stdio, pthread families ([7d3bd00](https://github.com/Dicklesworthstone/frankenlibc/commit/7d3bd00bf397446821919d5a7309239713e995ec))
- v*printf family as GlibcCallThrough wrappers ([3a90968](https://github.com/Dicklesworthstone/frankenlibc/commit/3a90968912b0cf924a995c26a68d0e751bc37458))
- 33 GlibcCallThrough wrappers for syslog, regex, network, dir, POSIX ([bd0c3f7](https://github.com/Dicklesworthstone/frankenlibc/commit/bd0c3f76e0f10f42bf634d5cd1ccd094270cbdd1))
- 19 high-value symbols: `getrandom`, `posix_spawn`, `statx`, `gettext` ([f4142f8](https://github.com/Dicklesworthstone/frankenlibc/commit/f4142f8c9cbd168e14721c96ab7783e7c6ba944e))
- Tier 2: 33 symbols -- 64-bit LFS, preadv/pwritev, mremap, arc4random ([5b33d7d](https://github.com/Dicklesworthstone/frankenlibc/commit/5b33d7de3fd6fc1ff0ee48120a9e9bd5fb346d30))
- Tier 3: 27 symbols -- wchar, pthread, splice, memfd, reallocarray ([cda357e](https://github.com/Dicklesworthstone/frankenlibc/commit/cda357eb47c510749fb4eb68d2a688e71937de41))
- Tier 4: 32 symbols -- semaphores, message queues, shared mem, scheduler, pidfd ([f0d1d1c](https://github.com/Dicklesworthstone/frankenlibc/commit/f0d1d1c5ba4c1e1db680e148eed350b87d162593))
- Tier 5: 33 symbols -- xattr, PTY, crypt, pthread spin/barrier, dl_iterate_phdr ([59451f7](https://github.com/Dicklesworthstone/frankenlibc/commit/59451f7a375f6ca3b2199901e337a0e6b6a1e7ca))
- Tier 6: 16 symbols -- lxattr, prlimit, sysinfo, utmp, eventfd helpers ([95c5f52](https://github.com/Dicklesworthstone/frankenlibc/commit/95c5f52756d9a7ad77309d30c2478a57dc725dd5))
- Tier 7: 34 symbols -- SysV IPC, signal extras, network, exec variadic ([32619625](https://github.com/Dicklesworthstone/frankenlibc/commit/32619625e284121d6280632c221c347dda3b7b1f))
- Tier 8: 33 symbols -- stdio extras, wide I/O, stdlib temps ([b2d2d5d](https://github.com/Dicklesworthstone/frankenlibc/commit/b2d2d5da23385c3b9ae3715d190afe27e57b84f0))
- Tier 9: 41 symbols -- timers, aio, mntent, resolver, wchar extras ([d00d489](https://github.com/Dicklesworthstone/frankenlibc/commit/d00d4896ff2647f1da4872a41361e029e79bc984))
- Tier 10: 26 symbols -- namespace, mount, fanotify, process_vm, LFS64 ([2e5c310](https://github.com/Dicklesworthstone/frankenlibc/commit/2e5c310862f25e067ed222541b75974e045a1293))
- Cross 900 symbols with login/tty/hostname extras ([0262e81](https://github.com/Dicklesworthstone/frankenlibc/commit/0262e8189ec37e008d69845bbb2659fee080cb92))
- System, putenv, popen, pclose POSIX symbols ([42ef83b](https://github.com/Dicklesworthstone/frankenlibc/commit/42ef83bd45fcd20fc5ffdb9cfdee4052a7c90bc9))
- Replace static mut with Mutex for basename/dirname buffers ([59487cb](https://github.com/Dicklesworthstone/frankenlibc/commit/59487cb05087358b6a94b9708e0fd854d3acfcbe))

### First Call-Through Elimination Wave

- Eliminate glibc call-through for ~25 unistd/POSIX symbols with native and raw-syscall implementations ([0f83bcb](https://github.com/Dicklesworthstone/frankenlibc/commit/0f83bcbbe711de8623f29da52a446ccecfc60e58))
- Eliminate glibc call-through for getopt, scheduler, PTY, ttyname, nice ([3f2b93e](https://github.com/Dicklesworthstone/frankenlibc/commit/3f2b93e3498958bc14d30434063b1c1539140531))
- Replace glibc call-through wrappers with native Rust implementations ([696f59d](https://github.com/Dicklesworthstone/frankenlibc/commit/696f59dddffc3a4e3bd6feaf252509611af261ba))
- Reclassify libc symbols from GlibcCallThrough to native implementations ([faed43c](https://github.com/Dicklesworthstone/frankenlibc/commit/faed43c984285c55dfa2d30eb00115130fa24347))
- Raw syscall POSIX shared memory ([9e55986](https://github.com/Dicklesworthstone/frankenlibc/commit/9e55986823e31472ac42dd804339e7d308994607))
- Massive ABI coverage expansion across wchar, unistd, pthread, resolv, socket, stdlib ([5c10349](https://github.com/Dicklesworthstone/frankenlibc/commit/5c10349acbb371fc1041d9afda8ba5d1af75b598))
- Promote 4 `stdio_abi` symbols from GlibcCallThrough to Implemented ([d2699b4](https://github.com/Dicklesworthstone/frankenlibc/commit/d2699b4c6baa6acc84b62e584cd86a7af3b458a3))
- Expand ctype locale variants, wchar ops, harden stdlib/unistd implementations ([29a6bfa](https://github.com/Dicklesworthstone/frankenlibc/commit/29a6bfaa6940dc32ff8d5289b97b129d40f08648))
- Implement shadow password database, healing oracle, expand ABI surface ([94339ef](https://github.com/Dicklesworthstone/frankenlibc/commit/94339ef53f37cf38fab498e010f28b0727ab5729))
- Expand POSIX surface by 260+ symbols with conformance infrastructure ([ef43fbc](https://github.com/Dicklesworthstone/frankenlibc/commit/ef43fbcd72f62772fc3ea35e7fbd9d21d48c1d66))
- Major POSIX surface expansion with C11 threads, filesystem ops, enhanced stdio ([2557de3](https://github.com/Dicklesworthstone/frankenlibc/commit/2557de36c6499909ec510026e50c440791a37a47))

### Core Implementations

- Wchar support, expand time, stdlib, string, unistd implementations ([1ab3384](https://github.com/Dicklesworthstone/frankenlibc/commit/1ab3384b66ce473ec3090cd4149b2d2fa11af0f7))
- f32 function coverage: hyperbolic, special, decomposition, rounding ([c452646](https://github.com/Dicklesworthstone/frankenlibc/commit/c452646f8a72435db2a3349be031f1bf165640ed))
- Math ABI coverage: exp, float classification, trig implementations ([ea1eeed](https://github.com/Dicklesworthstone/frankenlibc/commit/ea1eeed67535c3d6dba20de1e306676e2707276d))
- `nexttoward`/`nexttowardf`, `lgamma_r`, glibc `__fp*` wrappers ([b35a716](https://github.com/Dicklesworthstone/frankenlibc/commit/b35a7163b5f63f33f05e4a2abe7f624e10113e74), [901d246](https://github.com/Dicklesworthstone/frankenlibc/commit/901d2467963e99ca5392b4a36fdfe951f1f417f4))
- Fenv ABI module and POSIX 2008 locale extensions ([9b50af7](https://github.com/Dicklesworthstone/frankenlibc/commit/9b50af7420ded453d3ce80dee8e5feaec142536b))
- Expand unistd symbol coverage ([358601e](https://github.com/Dicklesworthstone/frankenlibc/commit/358601e793d98fd643a9022731e720349decef05))
- Correct `statfs` `f_flags` offset and refresh conformance snapshots ([95a8d3a](https://github.com/Dicklesworthstone/frankenlibc/commit/95a8d3af4531eba08a7752de8b22d48bc33f011f))
- `mlock2`, `name_to_handle_at`, `open_by_handle_at` syscall wrappers ([7b92f09](https://github.com/Dicklesworthstone/frankenlibc/commit/7b92f09d5ed157d490e57d739205a3da85da04c4))

### Membrane and Runtime Policy

- Versioned host delegation for dl* calls, expanded fallback alloc table, hardened runtime policy init ([730791c](https://github.com/Dicklesworthstone/frankenlibc/commit/730791cec592c185676a48180cdca0b7571e8bbf))
- Stdio runtime policy guards, replacement claim view, cross-arch fingerprint fix ([682f3f9](https://github.com/Dicklesworthstone/frankenlibc/commit/682f3f91f328b600ab2a8e9396719fff2b39e9d3))
- Runtime-math admission gate with policy ledger and integrity validation ([cfa6577](https://github.com/Dicklesworthstone/frankenlibc/commit/cfa6577d24dbc45374dc8b8354d10734fec9cb59))
- Deterministic pressure sensing regime-transition gate ([9ea75f6](https://github.com/Dicklesworthstone/frankenlibc/commit/9ea75f6fcb9ae14d77db668f570e22d5dc16116f))
- Return Calibrating when no bundles have frozen baselines in K-theory controller ([24abcfa](https://github.com/Dicklesworthstone/frankenlibc/commit/24abcfa14ae238a62fc66536f2d1bb427430bf05))
- Use EWMA effective sample size for Bernstein bound in matrix concentration ([1a0f209](https://github.com/Dicklesworthstone/frankenlibc/commit/1a0f209205ab8aa25f80e17dab1f13ecaf8fe0c2))
- Track peak severity across cadence boundaries in alpha investing ([4013e12](https://github.com/Dicklesworthstone/frankenlibc/commit/4013e12b519c0f51dd6d2c59105d808e23d9f72a))

### Licensing

- Adopt MIT + OpenAI/Anthropic rider across workspace ([6fcec0f](https://github.com/Dicklesworthstone/frankenlibc/commit/6fcec0f4d14a34eddd674df35e6fb3141cfbf7c5))

### Iconv

- Deterministic iconv table generation pipeline with checksum provenance ([5a73587](https://github.com/Dicklesworthstone/frankenlibc/commit/5a73587797a33bff85b55ac5511a27567c810137))

### Documentation and Assets

- Add WebP illustration to README ([89d36d8](https://github.com/Dicklesworthstone/frankenlibc/commit/89d36d80384b822199a690acec7a44c89a19652f))
- Add GitHub social preview image (1280x640) ([74d2c6e](https://github.com/Dicklesworthstone/frankenlibc/commit/74d2c6e6c09e9ce2df6d8ea9d2fc5019c7bfd79b))

---

## Phase 3 -- Conformance Infrastructure, Threading, and Stdio (2026-02-13 .. 2026-02-16)

Deep work on pthread correctness (futex-based condvar, self-join deadlock resolution, native thread lifecycle), conformance test infrastructure (golden fixtures, release gates, CVE arena), stdio (printf conformance, FILE operations), and string/stdlib hardened implementations.

### Pthread Threading

- Futex-based condvar core implementation ([cf060c9](https://github.com/Dicklesworthstone/frankenlibc/commit/cf060c9d406720aef38905d1b02624c7ce629937))
- Expand futex-based condvar, TLS edge handling, RCU module, pressure sensing ([8178dab](https://github.com/Dicklesworthstone/frankenlibc/commit/8178dab8c7b4e381851e0150d40f525b89045e2e))
- Replace glibc call-through with native thread management, add latency ingestion pipeline ([effcb00](https://github.com/Dicklesworthstone/frankenlibc/commit/effcb000d0330313b7aeaaa1db513ea06b2f18c6))
- Promote 5 pthread symbols to native, add arena quarantine tests ([52b563f](https://github.com/Dicklesworthstone/frankenlibc/commit/52b563f620bb2c2a649b4fdf7ce1cf6849bfbf39))
- Self-join deadlock resolution: spin-wait for TID publication ([12850bc](https://github.com/Dicklesworthstone/frankenlibc/commit/12850bc9c7871c56d46b9841d6c13ed06d4d6dd0))
- Dual-layer self-join deadlock prevention with early TID publication ([1667024](https://github.com/Dicklesworthstone/frankenlibc/commit/1667024d3eba2db1c5bee05e56c5122a156d3534))
- Trylock rwlock, `pthread_once`, TSD key/getspecific/setspecific, `cond_timedwait` ([039562f](https://github.com/Dicklesworthstone/frankenlibc/commit/039562f56b6ba331e3f643cbd42e71d74a79fa6b))
- Implement POSIX mutex contracts, expand replacement guard testing ([eb2d09f](https://github.com/Dicklesworthstone/frankenlibc/commit/eb2d09f9f8153743417ee1479f3a6fe7b703d8fa))
- Expand pthread condvar and mutex ABI with enhanced runtime policy support ([e8438d6](https://github.com/Dicklesworthstone/frankenlibc/commit/e8438d6b980e3ab3f7d9665b5f97130b3f57ebb8))
- Expand pthread thread implementation and lifecycle tests ([aceed27](https://github.com/Dicklesworthstone/frankenlibc/commit/aceed27b32601bdb51c56cf3b6d9ba6cd2e2c2b9))
- Pthread TLS rewrite, conformance test fixtures, hotpath CI, CVE arena results ([f94f859](https://github.com/Dicklesworthstone/frankenlibc/commit/f94f859a5da2a9bb0b3cf774c7469b41b7502f4f))
- `FORCE_NATIVE_THREADING` and `FORCE_NATIVE_MUTEX` flags to bypass host delegation in tests ([1004257](https://github.com/Dicklesworthstone/frankenlibc/commit/1004257b9cbef6291887d3d589ebb8de78ea0a63), [dde7106](https://github.com/Dicklesworthstone/frankenlibc/commit/dde71062d58b15e5b25973559850392214f984fc))

### Conformance and Release Gates

- Golden test fixtures for 20 POSIX subsystems and release gate infrastructure ([0319c07](https://github.com/Dicklesworthstone/frankenlibc/commit/0319c0713569d25e04993c4ae6b513bb041219f3))
- Rust integration tests for release gate scripts ([ef0bfdf](https://github.com/Dicklesworthstone/frankenlibc/commit/ef0bfdf860f5ffb2395081b90d2388a0471429b8))
- Expand fixture verification with ELF/resolver/DNS differential cases ([e653911](https://github.com/Dicklesworthstone/frankenlibc/commit/e653911d255fcd859028ab21e13306bb0b5c07c1))
- Gentoo security validation, CVE arena, CI gates, new C fixtures ([fe8c231](https://github.com/Dicklesworthstone/frankenlibc/commit/fe8c231addf8c2bb00f33e5017ec97c089314eab))
- Comprehensive test harness, Gentoo tooling, conformance validation ([96ffeb7](https://github.com/Dicklesworthstone/frankenlibc/commit/96ffeb72fd80789c0adbdd5a2ce6547bc8b33179))
- Add E2E manifest validation, Gentoo test tooling, expanded harness coverage ([6c1f3ce](https://github.com/Dicklesworthstone/frankenlibc/commit/6c1f3ce5a309712f3b7ff114422ebbc9ebbf41b8))

### Stdio

- Expand FILE operations with `fread`/`fwrite` and buffer-flush semantics ([dd47c22](https://github.com/Dicklesworthstone/frankenlibc/commit/dd47c2256344b27d1b0a8e23c7985d22b6b294eb))
- Phase-2 printf-family integration tests and ABI definitions ([d5481d2](https://github.com/Dicklesworthstone/frankenlibc/commit/d5481d2a2ffff846c93ebc312dd89336be35ad28))
- Printf conformance with C fixture integration tests and support matrix for stdio ABI ([b94610d](https://github.com/Dicklesworthstone/frankenlibc/commit/b94610d3fc38d52e88b2584fd48cb415a7885a73))
- Wire stdio fixture dispatch with printf/snprintf/fopen/fclose executors ([f59a91f](https://github.com/Dicklesworthstone/frankenlibc/commit/f59a91f6cadcfe25a45ef58a680acd5f9d948d83))
- Fread, fwrite, fseek, ftell, fflush stdio file I/O conformance tests ([f4233d2](https://github.com/Dicklesworthstone/frankenlibc/commit/f4233d2f10593a885c86c0920989eed0d1612231))

### String / Stdlib

- `strncmp` with hardened bounds checking and export new symbols ([5e2ddd8](https://github.com/Dicklesworthstone/frankenlibc/commit/5e2ddd8e625206f6debf28376a5c237bdea9ff1b))
- `strnlen` with hardened bounds checking ([0a68e99](https://github.com/Dicklesworthstone/frankenlibc/commit/0a68e99665614dc1b44aa2baf806021908f00e27))
- `strchrnul` with hardened bounds checking ([300efd4](https://github.com/Dicklesworthstone/frankenlibc/commit/300efd4efbc1c4b77d0977c7e472a82c2690c0c6))
- `atoll`, `strtoll`, `strtoull`, `strtoimax`, `strtoumax`, `secure_getenv` ([a6c7ec4](https://github.com/Dicklesworthstone/frankenlibc/commit/a6c7ec46be7448d945c245c1a4aca078c1ae88d1))

### Signal

- Use kernel sigset size in `rt_sigaction` syscall and add signal ABI tests ([9ec4316](https://github.com/Dicklesworthstone/frankenlibc/commit/9ec4316d0ee92fd054b35bd751076a3f6aa859c6))
- Refine signal ABI implementation and expand test coverage ([e557436](https://github.com/Dicklesworthstone/frankenlibc/commit/e5574363b8f64688e81cf42d2c66ff695e65deae))

### Math

- Replace std intrinsics with libm for cross-platform determinism ([e244e0c](https://github.com/Dicklesworthstone/frankenlibc/commit/e244e0c8eeda668ca3e18864dcc303df8ddd5a22))

### Smoke and E2E Tests

- E2E test suite and substantially expanded LD_PRELOAD smoke test coverage ([f602a62](https://github.com/Dicklesworthstone/frankenlibc/commit/f602a62819cfbeefef903d8fc4117e2700c83f2c))
- Further E2E test suite expansion for LD_PRELOAD interception scenarios ([b4bcfdb](https://github.com/Dicklesworthstone/frankenlibc/commit/b4bcfdbc831e9014745aa087ac9e053194be7e6a))

### Membrane

- Expand ApiFamily coverage to all 19 families and harden golden-value tests ([a7375f0](https://github.com/Dicklesworthstone/frankenlibc/commit/a7375f0489511e1a6800b68b852da743cf891f0f))
- Allocator lifecycle logging, native rwlock, SOS fragmentation certificates ([7f22a7c](https://github.com/Dicklesworthstone/frankenlibc/commit/7f22a7c596322062354680b9be757f9a4831d067))
- Decision card ledger, promote 5 pthread symbols to native, update fixtures ([484eb69](https://github.com/Dicklesworthstone/frankenlibc/commit/484eb699b9c74f75250af93df3d28bd550043531))
- SOS certificate generation pipeline and fragmentation/provenance/quarantine benchmarks ([02a3756](https://github.com/Dicklesworthstone/frankenlibc/commit/02a37567b20eba24d8f3759dd4f07ddd5c0bfbac))
- Warning-vs-blocking regression policy with SOS barrier violation guard ([39b61fb](https://github.com/Dicklesworthstone/frankenlibc/commit/39b61fb7042af7af687b773e0d88d23e570e7465))

### CI

- Comprehensive GitHub Actions workflow for FrankenLibC ([59969f2](https://github.com/Dicklesworthstone/frankenlibc/commit/59969f2896a53dbf4e4acddb12269cc3babd1096))
- Enable `--all-targets` and update conformance snapshots ([b0d4917](https://github.com/Dicklesworthstone/frankenlibc/commit/b0d49177c2b2f13cec6c6204aa53cd242b29e94e))

### Pwd / Grp / NSS

- TLS-cached lookups in reentrant `_r` functions, comprehensive reentrant tests ([e4b3875](https://github.com/Dicklesworthstone/frankenlibc/commit/e4b3875ebd5c9f70ab1a820a3c71ae46397a8cf3))
- NSS path overrides and cache invalidation tests ([898e202](https://github.com/Dicklesworthstone/frankenlibc/commit/898e202c60c903709e5ac0dcd8ca7cca80395737))
- Deterministic cache fingerprinting and parse stats ([4c9834b](https://github.com/Dicklesworthstone/frankenlibc/commit/4c9834ba73f35ce0ff7fa0de6c6776835ffb3592))

### Iconv

- Expand iconv codec implementation and add scope ledger conformance ([15bd241](https://github.com/Dicklesworthstone/frankenlibc/commit/15bd241aa85e1ceff23bf57b5c376fb125dbb45e))

### Resolver

- `/etc/hosts` file-backend lookup for `getaddrinfo` ([2a6d8aa](https://github.com/Dicklesworthstone/frankenlibc/commit/2a6d8aa511440bbeeed562babcae9a114c2594ca))
- `nl_langinfo` locale ABI and expand startup conformance matrix ([83cbee0](https://github.com/Dicklesworthstone/frankenlibc/commit/83cbee026a53af40cdf70caadec274fc4770e0af))

---

## Phase 2 -- Workspace Restructure, POSIX Expansion, and Membrane Maturity (2026-02-10 .. 2026-02-12)

Transition from `glibc_rust` prototype to the FrankenLibC name and structured workspace. Expanded POSIX module coverage across 12 subsystems, built out the conformance and evidence infrastructure, and established the membrane's statistical monitors and CVE arena.

### Project Rename

- Rename `glibc_rust` to FrankenLibC across all crates ([6c012a1](https://github.com/Dicklesworthstone/frankenlibc/commit/6c012a1227ef087835379b431cbfcc49dcde491d))
- Complete FrankenLibC rename in source files and scripts ([ddf93bc](https://github.com/Dicklesworthstone/frankenlibc/commit/ddf93bc45c39b10fe4368dabf24cdb2e8683064e))
- Complete FrankenLibC rename in remaining source and docs ([b9501be](https://github.com/Dicklesworthstone/frankenlibc/commit/b9501be302282ed306bbf5214df4c4e981cd2cfe))

### ABI Expansion

- Process/mmap/poll ABI modules, expand stdio to full POSIX surface, wire pthread sync ops ([1e34ce5](https://github.com/Dicklesworthstone/frankenlibc/commit/1e34ce5e446adec1ca19f8cb71e98e0df6c5e51d))
- Expand POSIX module coverage across 12 subsystems ([7a7173d](https://github.com/Dicklesworthstone/frankenlibc/commit/7a7173dae9d44415622954e1d9ef2e710ffd8bed))
- Phase-1 character encoding conversion engine (iconv) ([f494ad0](https://github.com/Dicklesworthstone/frankenlibc/commit/f494ad0cbcb2b62b6f0d66a28dee364f1d4f0c4a))
- Passwd and group database modules: `getpwnam`/`getgrnam` families ([f8ba8e4](https://github.com/Dicklesworthstone/frankenlibc/commit/f8ba8e4bcf95a21b9f6cfbe9f3d5c9adb63fd6d9))
- DNS resolver with `/etc/hosts` and `/etc/services` file-based backends ([2f7fdc2](https://github.com/Dicklesworthstone/frankenlibc/commit/2f7fdc2c012df2749b7d29e5916e9ab7445e9df7))
- Startup introspection ABI and C fixture test ([a06427b](https://github.com/Dicklesworthstone/frankenlibc/commit/a06427b7f2f47a97538c31f46c224de9d9f6fe73))
- Expand pthread ABI surface, add math retirement gate and stub priority ([28f8806](https://github.com/Dicklesworthstone/frankenlibc/commit/28f88065149d11910c48429bfdbcc86e7e897619))
- Wire new modules into crate roots and expand versioned symbol map ([b030dcf](https://github.com/Dicklesworthstone/frankenlibc/commit/b030dcff74ee39c9a294cdde417116d88e8ae4f8))
- Raw syscall veneers, managed-mutex discrimination, conformance gate suite ([6512fcc](https://github.com/Dicklesworthstone/frankenlibc/commit/6512fcca484ab43ebf914d20c9140d22369614a5))
- Strip `runtime_policy` overhead from pthread mutex ops, C fixture test suite ([b2169a7](https://github.com/Dicklesworthstone/frankenlibc/commit/b2169a7715b0343daa1267da3c37ada71014c755))
- Eliminate glibc call-throughs, add re-entrancy guards, conditional `no_mangle` ([e4f489f](https://github.com/Dicklesworthstone/frankenlibc/commit/e4f489fd1f19cfe0bba9fbe6e2abfc45a3a74308))
- 250-symbol surface documented ([219cf7e](https://github.com/Dicklesworthstone/frankenlibc/commit/219cf7eea6e9af9f31126c10fb124e8c7c4aa0c7))

### Membrane -- Statistical Monitors and Evidence

- 13 advanced statistical monitors for runtime kernel ([d72b56d](https://github.com/Dicklesworthstone/frankenlibc/commit/d72b56de122c86b1902a532843cb1d483b56356e))
- Wire 13 new monitors into runtime kernel snapshot pipeline ([668aee5](https://github.com/Dicklesworthstone/frankenlibc/commit/668aee54e6115c3294bee26e169c5b8f3a624d79))
- V1 deterministic XOR repair symbol encoder + fix msync/test correctness ([cb5d2dd](https://github.com/Dicklesworthstone/frankenlibc/commit/cb5d2dd55e7a63e55263d56876a5c91630d69985))
- Policy table lookup, redundancy tuner, hot-path optimizations ([6714ec8](https://github.com/Dicklesworthstone/frankenlibc/commit/6714ec82ab4dc0a26d6eeccae84bb8a1cc8bff74))
- CVE arena test infrastructure for real-world vulnerability reproduction ([40916cf](https://github.com/Dicklesworthstone/frankenlibc/commit/40916cf8af89177593a8711fedf9447aaee94b14))
- Harden TLS cache safety, expand runtime math tests, apply clippy fixes ([a1e3c0e](https://github.com/Dicklesworthstone/frankenlibc/commit/a1e3c0e01ba4b27cc12e2c3878ee33ba513c60cf))
- SOS barrier property tests, kernel integration test, sobol quasi-random controller ([039a10f](https://github.com/Dicklesworthstone/frankenlibc/commit/039a10f17ca34622c86827285405a25c9aaa282e))
- Integrate localization chooser + approachability tests + fix Grobner wiring ([f475682](https://github.com/Dicklesworthstone/frankenlibc/commit/f475682d1fdbc67e23e3d43a69db155d6aa0fc57))
- Approachability, localization_chooser, policy_table, sos_barrier controllers ([6ce365b](https://github.com/Dicklesworthstone/frankenlibc/commit/6ce365bd4154b1fd18670663070820cfb78ebd31))
- Alpha_investing controller with cadence-gated meta-observe ([debf416](https://github.com/Dicklesworthstone/frankenlibc/commit/debf416ac73276b5951910df3b75276109bb6a8f))
- Coupling/loss snapshot fields + fusion SIGNALS consistency tests ([55bc39d](https://github.com/Dicklesworthstone/frankenlibc/commit/55bc39df0a7fc55ed3787f5cd2f6953d6635e848))
- 3 new runtime math meta-controllers + evidence symbol record format ([864395b](https://github.com/Dicklesworthstone/frankenlibc/commit/864395b22f0a3b812205afd3c58eab81ee00e0fa))
- Add `evidence_seqno` to `RuntimeDecision` ([c67fefb](https://github.com/Dicklesworthstone/frankenlibc/commit/c67fefba20bdc02678d14afb64e1b83ec3b07b18))

### Core

- Mmap/poll/process modules, rewrite stdio buffer+file+printf engines, refactor pthread to validators ([8426870](https://github.com/Dicklesworthstone/frankenlibc/commit/8426870b80f6688780aba0c8b179a1be8aeb46ce))
- Rewrite pthread thread creation with clone syscall, add syscall wrappers, iconv UTF-32 support ([9b22cfc](https://github.com/Dicklesworthstone/frankenlibc/commit/9b22cfca1e09046609bb0736ba966283a9d2b57f))
- ELF loader module and DNS resolver protocol support ([546cefe](https://github.com/Dicklesworthstone/frankenlibc/commit/546cefea7b34267ba764999672702a64ce31718f))
- Harden pthread thread lifecycle and expand CI/E2E infrastructure ([e2d829d](https://github.com/Dicklesworthstone/frankenlibc/commit/e2d829ddf382b7d289abdf05ee17af3437bfbcab))

### Conformance and Harness

- ABI audit tooling, conformance golden gate, support matrix ([39cdd32](https://github.com/Dicklesworthstone/frankenlibc/commit/39cdd32c79b8175d0d7f1800201f48465bb656e1))
- Snapshot gate and golden update scripts, wired into CI ([6233d09](https://github.com/Dicklesworthstone/frankenlibc/commit/6233d0931a1026f00a98296189f71a859b758f19))
- Module inventory and wiring drift detectors, wired into CI ([5b5e380](https://github.com/Dicklesworthstone/frankenlibc/commit/5b5e380c9d1f8ac57eba8f50e6e78536e1bbc516))
- Kernel snapshot capture/diff commands, asupersync orchestrator ([f3b8ff2](https://github.com/Dicklesworthstone/frankenlibc/commit/f3b8ff24b1b4c9c0b241f35a73feff1de8f9e147))
- Evidence decode CLI, restructured CI, updated golden snapshots ([2428990](https://github.com/Dicklesworthstone/frankenlibc/commit/2428990b77726d499a95cfcfab6b25252db86baa))
- Evidence compliance validator + triage CLI ([ac4a0ba](https://github.com/Dicklesworthstone/frankenlibc/commit/ac4a0ba0a701676b71b5f1e27f9bcde2185c2051))
- Deterministic gate DAG + dry-run runner ([78ca744](https://github.com/Dicklesworthstone/frankenlibc/commit/78ca7449c1a05d36de476d050504a7cfd19d14a8))
- Closure contract schema + validator gate ([a0d136d](https://github.com/Dicklesworthstone/frankenlibc/commit/a0d136d18804622725ee811b32db5ecfe18abdee))
- Evidence trace propagation + runtime_decision explainability ([e485128](https://github.com/Dicklesworthstone/frankenlibc/commit/e485128884a324df270144dd468d40284af883e4))
- Entrypoint tracing scopes for malloc family functions ([8f4dea9](https://github.com/Dicklesworthstone/frankenlibc/commit/8f4dea926fcbad42d01a8ad5144fff19effec5e2))
- Snapshot+test coverage matrix checker, wired into CI ([7b7275d](https://github.com/Dicklesworthstone/frankenlibc/commit/7b7275d64ab703b3c037698a086901a192b82ea7))
- Determinism proof verification script and CI integration ([7878f6b](https://github.com/Dicklesworthstone/frankenlibc/commit/7878f6b69c8437565c790c3d8dbae76698298646))
- Runtime_math classification matrix artifact + integrity gate ([fcfa5ea](https://github.com/Dicklesworthstone/frankenlibc/commit/fcfa5ea3a53c24cc8c46c9b812a53db563aba9c0))
- Runtime_math profile gates ([4d3bd6c](https://github.com/Dicklesworthstone/frankenlibc/commit/4d3bd6cac01c72b06781c44f72c25111068202c0))

### Membrane -- Fix Dobrushin Ergodicity and Doob Drift

- Improve Dobrushin test ergodicity and Doob drift rate semantics ([e6a16a5](https://github.com/Dicklesworthstone/frankenlibc/commit/e6a16a5ed14ad0b4f1876cbc4a0722cf0b9c0760))
- Bump fusion SIGNALS constant to 61 for sos_barrier severity slot ([2ceebb5](https://github.com/Dicklesworthstone/frankenlibc/commit/2ceebb58a1507314d7c1adb3f66c223939121544))

---

## Phase 1 -- Workspace Scaffold and Runtime Math Kernel (2026-02-08 .. 2026-02-09)

Project created as `glibc_rust`. Established the four-crate workspace (`frankenlibc-abi`, `frankenlibc-core`, `frankenlibc-membrane`, `frankenlibc-harness`), wired the Transparent Safety Membrane, built out the runtime math kernel with dozens of controllers, implemented the first ABI entrypoints (malloc, free, strlen, strcmp, memset), and established the conformance fixture engine.

### Project Setup

- Initial workspace scaffold and architecture docs ([b45e3ac](https://github.com/Dicklesworthstone/frankenlibc/commit/b45e3ac35c87a52992a797d178179ed6ecdf04a8))
- Wire runtime-math into all ABI families + add 6 new math monitors ([e130fb2](https://github.com/Dicklesworthstone/frankenlibc/commit/e130fb2a683f3a5ea0a2ded276d6c5d711e2f8ca))

### Runtime Math Kernel

The runtime math kernel provides the statistical foundation for the Transparent Safety Membrane's decision-making. Dozens of controllers were added in this phase:

- P-adic valuation monitor, symplectic reduction controller, Stdlib API family ([e4acdee](https://github.com/Dicklesworthstone/frankenlibc/commit/e4acdeebe49f81016e06cbeab692a7b5808b5cd8))
- Sparse-recovery and robust fusion runtime math controllers ([aaa6820](https://github.com/Dicklesworthstone/frankenlibc/commit/aaa682096cd9f328aebc0cf21a8d3bc843e9f759))
- Optimal experiment design controller for probe budget allocation ([f35f73f](https://github.com/Dicklesworthstone/frankenlibc/commit/f35f73f4aaffe197f3bc501603327a0b18e15c88))
- Clifford algebra, microlocal analysis, Serre spectral sequence controllers ([dcb004e](https://github.com/Dicklesworthstone/frankenlibc/commit/dcb004e0d234bc6cf3551a2b44915e0266eb52e8))
- 12 new controllers: algebraic, combinatorial, information-theoretic domains ([16587b8](https://github.com/Dicklesworthstone/frankenlibc/commit/16587b82997adba2b878c5a64d516a9edf9b52fd))
- Wire 12 new controllers into RuntimeMathKernel and extend pthread ABI stage tracking ([4e03b0f](https://github.com/Dicklesworthstone/frankenlibc/commit/4e03b0febfef8cdcf45dc88261fb282d73719083))
- 9 new runtime_math controllers and refine existing modules ([d2dd0e1](https://github.com/Dicklesworthstone/frankenlibc/commit/d2dd0e1d9a4b106742e1ac209a5498bb80084a95))
- 7 new controllers and expanded existing modules ([077d812](https://github.com/Dicklesworthstone/frankenlibc/commit/077d812c592b9707521260d896ea761a0b20bed0))
- 3 new runtime math monitors, wire Process/VirtualMemory/Poll into kernel ([be71e75](https://github.com/Dicklesworthstone/frankenlibc/commit/be71e756ff1586cb15d48763d41734b908290ed8))

### Membrane Infrastructure

- Arena aligned allocation, public quarantine entries, validator pipeline ([f512b37](https://github.com/Dicklesworthstone/frankenlibc/commit/f512b379a820192410796496ff5439c3b19e49ee))
- Pointer validator with string-aware safety checks ([68fcc37](https://github.com/Dicklesworthstone/frankenlibc/commit/68fcc378a16d0f6c8f9bc122a2a6f73d872c3cb3))
- Expand pointer validation with boundary checks and alignment guards ([8ef5083](https://github.com/Dicklesworthstone/frankenlibc/commit/8ef508375fa2c227a2b9fb04056d6469c31e6962))
- Identity module and refined pointer validation/healing ([1973006](https://github.com/Dicklesworthstone/frankenlibc/commit/197300602992dbff846f3c412181121dc1cd4b6f))
- Criterion microbench suite, profiling recipe, idiomatic loop refactors ([81e14d0](https://github.com/Dicklesworthstone/frankenlibc/commit/81e14d0911840d1611e83c7289846f27188405a0))
- Benchmark rewrite with parameterized safety levels and percentile reporting ([bd60972](https://github.com/Dicklesworthstone/frankenlibc/commit/bd60972dd148a85ec3c21311933c360021bb20e4))

### Runtime Math Evidence Tracking

- Extend runtime math evidence tracking ([b5e9d33](https://github.com/Dicklesworthstone/frankenlibc/commit/b5e9d33ef33c2956b3c8dddc5d8c39040ccd4f13))
- Expand evidence tracking with convergence metrics (+87 lines) ([f41dac4](https://github.com/Dicklesworthstone/frankenlibc/commit/f41dac4c5539bed8ebf1d0d977c0f7531bd86f61))
- Improve runtime math module with numerical stability fixes (+70 lines) ([17fabc5](https://github.com/Dicklesworthstone/frankenlibc/commit/17fabc5f535e7373823593ebe8eb37c2f9759457))
- Alien CS metrics collection (+233 lines) ([00787e1](https://github.com/Dicklesworthstone/frankenlibc/commit/00787e178028cd3e6e3ee8ce2032089c7dbb197c))
- Comprehensive metrics collection and aggregation (+199 lines) ([a867683](https://github.com/Dicklesworthstone/frankenlibc/commit/a8676835f34fb28d07e12c8ab1d942891f969149))
- Improve alien CS metrics aggregation accuracy ([739f5e2](https://github.com/Dicklesworthstone/frankenlibc/commit/739f5e254e11480ad988975c290fcc55d30b57a6))
- Tighten pointer validator boundary check ([8c19fff](https://github.com/Dicklesworthstone/frankenlibc/commit/8c19fff3415ce8bab914543b31b5c5df81332e98))
- Correct attenuation bias in obstruction detector and entropy window-boundary trigger ([0e646ae](https://github.com/Dicklesworthstone/frankenlibc/commit/0e646ae3c43b7b08248ca264dc37511be62b2653))

### Numerical Primitives

- Major runtime math expansion (+346 lines) ([cad72aa](https://github.com/Dicklesworthstone/frankenlibc/commit/cad72aa5f8d3822144b2c90abb2709adc5cbc565))
- Root-finding primitives ([5010b7c](https://github.com/Dicklesworthstone/frankenlibc/commit/5010b7c5a80575ed79e2d3d036885e52e7a323de))
- Interpolation and approximation (+48 lines) ([824783d](https://github.com/Dicklesworthstone/frankenlibc/commit/824783d7d13c085ab61da699e7e808241a25c6b6))
- ODE solver and numerical integration (+165 lines) ([43cfc4b](https://github.com/Dicklesworthstone/frankenlibc/commit/43cfc4b7f8b62f52ab5f91589bceb4ace784638b))
- FFT and convolution primitives (+104 lines) ([c36e084](https://github.com/Dicklesworthstone/frankenlibc/commit/c36e084646680947d4fa80e5ac972387a96e8ff8))
- Sparse matrix primitives (+31 lines) ([c184f32](https://github.com/Dicklesworthstone/frankenlibc/commit/c184f3227a44e904bc651f52ae39cf34e5a979d7))
- Additional numerical primitives (+63 lines) ([fb24efb](https://github.com/Dicklesworthstone/frankenlibc/commit/fb24efbb7a58239d708c55bdd7e62635652194dd))

### Core Implementations

- Errno TLS, stdlib numeric/exit/sort, wide string operations ([ce78bec](https://github.com/Dicklesworthstone/frankenlibc/commit/ce78becb68e69cbda712d8d3e48c5a580316c510))
- Core math implementations for exp, float, special, and trig families ([836dfac](https://github.com/Dicklesworthstone/frankenlibc/commit/836dfac5bcc033134861782eb0a1ef10906a9d6d))
- Expand core math implementations for exp, float, special, and trig families ([836dfac](https://github.com/Dicklesworthstone/frankenlibc/commit/836dfac5bcc033134861782eb0a1ef10906a9d6d))

### ABI Entrypoints

- Wire malloc through membrane pipeline, add stdlib/stdio/unistd/wchar ABI exports ([2218394](https://github.com/Dicklesworthstone/frankenlibc/commit/2218394a0ce9bdc0a2c86e055145de16a29bd5cc))
- Preview ABI entrypoints for malloc, free, strlen, strcmp, memset ([b91f2e8](https://github.com/Dicklesworthstone/frankenlibc/commit/b91f2e84fb29765986d3c24293618bc9e070228a))
- Expand ABI surface for math functions, string operations, and runtime policy ([921a07a](https://github.com/Dicklesworthstone/frankenlibc/commit/921a07a4dd1dc94d6b89080ce3b0e6f387a55679))
- Allocator stage-context helpers and pipeline wiring ([f85a1e6](https://github.com/Dicklesworthstone/frankenlibc/commit/f85a1e6bf1232bab90c3cdddf59592d0e4f9cf7d), [a102642](https://github.com/Dicklesworthstone/frankenlibc/commit/a102642a4416d3e7c865308884a77d27f799080d))
- Resolver ABI wiring ([2f628df](https://github.com/Dicklesworthstone/frankenlibc/commit/2f628df7cca3971f739f65a0dc6fbafe7898165e))

### Conformance

- Unified fixture execution engine and 9 new test fixture sets ([e989cc3](https://github.com/Dicklesworthstone/frankenlibc/commit/e989cc378236c059de8b7ee99327a979465080a3))
- Refresh symbol latency baselines and expand string benchmarks ([e14db7a](https://github.com/Dicklesworthstone/frankenlibc/commit/e14db7aa7793bc48c911d684e234e3ff540a3427))
- Improve runtime math, HJI reachability, and alien CS metrics ([1c5dc12](https://github.com/Dicklesworthstone/frankenlibc/commit/1c5dc127c334d90c9fd7b32b6095cc2839933852))

---

## Workspace Crate Map

| Crate | Purpose |
|---|---|
| `frankenlibc-abi` | `#[no_mangle]` exported symbols; the `libfrankenlibc_abi.so` artifact |
| `frankenlibc-core` | Safe Rust implementations of libc behavior (string, math, pthread, stdio, malloc, locale, resolver, etc.) |
| `frankenlibc-membrane` | Transparent Safety Membrane: pointer validation, arena allocator, quarantine, runtime math kernel, EBR |
| `frankenlibc-harness` | CLI harness for conformance verification, evidence compliance, release gates, membrane verification |
| `frankenlibc-bench` | Criterion benchmarks for membrane, allocator, and concurrency primitives |
| `frankenlibc-fixture-exec` | Fixture execution engine for conformance tests |
| `frankenlibc-fuzz` | Structure-aware fuzz targets for string, malloc, printf, resolver, regex, scanf, iconv, and more |
| `frankenlibc_conformance` | Conformance test infrastructure and fixture packs |

---

## Symbol Classification Legend

| Status | Meaning |
|---|---|
| **Implemented** | Native Rust-owned behavior behind the ABI symbol |
| **RawSyscall** | ABI path delegates directly to a Linux syscall |
| **WrapsHostLibc** | Native wrapper that still calls host libc symbols internally (currently zero in the classified surface) |
| **GlibcCallThrough** | Delegates to host glibc via `dlsym` (currently zero in the classified surface) |
| **Stub** | Exported but returns a fixed value or documented degraded contract (currently zero in the classified surface) |

---

## Project Facts

- **No tags or GitHub Releases** exist in this repository as of the [Unreleased] snapshot date at the top of this changelog (`git tag -l` and `gh release list` both empty).
- The version badge in the README reads `0.1.0`; `Cargo.toml` workspace version matches.
- The canonical coverage source of truth is `support_matrix.json` (with a snapshot in `tests/conformance/support_matrix_maintenance_report.v1.json`).
- All commits are by a single author (`Dicklesworthstone`); see the [Unreleased] header for the running count.
- The project was originally named `glibc_rust` and renamed to FrankenLibC on 2026-02-12.
- License is MIT with an OpenAI/Anthropic rider, adopted 2026-02-18.
- The project started 2026-02-08; this changelog covers through the [Unreleased] snapshot date.
