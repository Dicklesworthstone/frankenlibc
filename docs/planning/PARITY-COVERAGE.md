# FrankenLibC Parity Coverage Report

**Reconciled:** 2026-10-20. The symbol-presence comparison and session history below originate from 2026-05-25; they are not a fresh workload or parity run.

## Current Scope

The declared replacement level is **L0 interposition over host glibc**. The committed `support_matrix.json` classifies 4,119 exports as 2,419 `Implemented`, 410 `RawSyscall`, 1,272 `WrapsHostLibc`, zero `GlibcCallThrough`, and eighteen `Stub`. The 2,829 native/direct-syscall classifications (68.7%) measure ownership, not complete semantics or a standalone process.

The committed support-maintenance report rejects 1,079 classifications; the live maintenance gate also reports a stale host census. Those mismatches require reviewed source/provider evidence, not blanket promotion. Fixture linkage covers 1,190/4,119 rows (28.9%); linkage is not an executed pass rate. The nine-entry semantic overlay is representative, not exhaustive.

The September 24 committed preload summary records 189 passes, zero failures, four skips and one xfail for its identified artifact. Current-source workload/performance qualification and L1 promotion remain open. See [the bridge plan](REALITY_CHECK_BRIDGE_PLAN.md) and [compatibility guide](COMPATIBILITY.md) for evidence boundaries and active tasks.

## Historical Symbol-Presence Comparison — May 25, 2026

| Metric | Count | Notes |
|--------|-------|-------|
| glibc exported symbols | 2932 | `nm -D /lib/x86_64-linux-gnu/libc.so.6` |
| FrankenLibC symbols | 4119 | `support_matrix.json` |
| Common (present in both) | 2681 | 91.4% of glibc exports |
| Missing from FrankenLibC | 251 | **All internal/private** |
| Extra in FrankenLibC | 1438 | `__*_finite` math, fortify, extensions |

### Symbol Presence Does Not Establish Full API Coverage

The May comparison categorized its 251 missing names as follows. That categorization does not demonstrate that every present public export implements its full contract:

- **GLIBC_*** (42): Version markers, not callable symbols
- **_dl_*** (12): Dynamic linker internals (`_dl_allocate_tls`, `_dl_signal_error`, etc.)
- **_nss_*** (82): NSS plugin implementation symbols (not public API)
- **_rtld_*** (2): Runtime linker globals
- **_thread_db_*** (113): Thread debug interface internals

## Scope and Host-Dependency Boundaries

The full POSIX/GNU objective remains. Historical exclusions must not silently remove required behavior from that objective:

| Subsystem | Reason | Impact |
|-----------|--------|--------|
| NSS plugins (`_nss_*`) | Native files/DNS coexist with installed host-loaded NSS modules | Public lookup behavior and provider independence need separate qualification |
| Thread debug (`_thread_db_*`) | GDB/debugger integration internals | Debuggers use libthread_db.so |
| Dynamic linker globals (`_rtld_*`, `_dl_*`) | Host-loader internals differ from the public symbol surface | Owned startup, TLS and transitive loading remain standalone integration obligations |
| Sun RPC/XDR | Declared legacy ABI remains in scope | Native code exists, but fourteen RPC symbols remain classified as stubs pending implementation/qualification |
| STREAMS (`fattach`, `getmsg`, `putmsg`) | SVR4 legacy, never widely used on Linux | Effectively dead API |

## Support Matrix Breakdown

| Status | Count | Description |
|--------|-------|-------------|
| Implemented | 2419 | Classified native Rust behavior |
| RawSyscall | 410 | Classified direct syscall path |
| WrapsHostLibc | 1272 | Explicit host-backed subset |
| GlibcCallThrough | 0 | Opaque call-through subset |
| Stub | 18 | Explicit unsupported contracts |

**Native-classified:** 2,829 symbols (`Implemented + RawSyscall`). This is not a standalone-capable process claim.

**Host-backed:** 1,272 symbols (`WrapsHostLibc`). Taxonomy/source disagreements are described above.

## Behavioral Parity Verification

### Function Families in the Historical Test Inventory

The May inventory counted 154 test functions across these families. Test presence and that historical count do not establish current compilation, nonzero execution or complete family semantics:

- **string/memory:** memcpy, memmove, memset, memcmp, memchr, strlen, strcmp, strncmp, strchr, strrchr, strstr, strcpy, strncpy, strcat, strncat, strdup, strndup, strerror
- **ctype:** isalpha, isdigit, isalnum, isspace, ispunct, isupper, islower, isprint, isxdigit, iscntrl, isgraph, tolower, toupper
- **math:** sin, cos, tan, asin, acos, atan, sinh, cosh, tanh, exp, log, log10, sqrt, pow, fabs, ceil, floor, round, trunc, fmod, ldexp, frexp, modf
- **stdio:** printf (formats), sprintf, snprintf, sscanf, fopen, fclose, fread, fwrite, fseek, ftell, fgets, fputs
- **stdlib:** atoi, atol, atoll, strtol, strtoll, strtoul, strtoull, strtod, strtof, malloc, calloc, realloc, free, qsort, bsearch, abs, labs, llabs, div, ldiv, lldiv
- **time:** time, localtime, gmtime, mktime, strftime, strptime, clock_gettime, gettimeofday
- **errno:** errno thread-safety, strerror mapping
- **signal:** signal masks, sigaction semantics
- **env:** getenv, setenv, unsetenv, putenv
- **inet:** inet_aton, inet_ntoa, inet_pton, inet_ntop, htons, ntohs, htonl, ntohl
- **regex:** regcomp, regexec, regfree basic and extended patterns
- **glob:** glob, globfree with various flags
- **fnmatch:** FNM_PATHNAME, FNM_PERIOD, FNM_NOESCAPE
- **termios:** tcgetattr, tcsetattr, cfgetispeed, cfsetispeed
- **poll/select:** poll, select, pselect timeout and fd behavior
- **mmap:** mmap, munmap, mprotect
- **socket:** socket, bind, listen, accept, connect, send, recv

### Edge Cases Named by the Historical Inventory

- `strtol` with C23 binary prefix (`0b101`)
- `strftime` trailing `%` handling
- `strptime` minute/second validation (0-59)
- `fnmatch` backslash in bracket expressions
- `glob` GLOB_NOESCAPE flag
- printf width/precision edge cases
- scanf whitespace consumption
- errno preservation across calls
- NULL pointer handling where permitted

## Behavioral Divergence Evidence

The old assertions that `random()` uses Rust's `rand` crate and that `drand48()` necessarily has a different seed sequence are not current verified divergence evidence. Use the native implementation and differential tests for the exact family, state and seed. POSIX permission to differ does not establish GNU/glibc parity, and statistical similarity is not a substitute for the required sequence contract. Record current divergences with a named oracle and executed counterexample.

## Performance Contracts

| Mode | Target | Measured |
|------|--------|----------|
| Strict membrane overhead | <20ns/call for membrane-gated hot paths | Not established for the current artifact |
| Hardened membrane overhead | <200ns/call for membrane-gated hot paths | Not established for the current artifact |
| Hardened vs native glibc | ≤2× for the specified workload contracts | Current allocator/sort and other named budgets remain open |

Targets require deployed-path measurements with the live incumbent in the same invocation. A closed bead, symbol classification or historical self-speedup does not establish these budgets globally.

## Automated Gates

| Gate | Script | Purpose |
|------|--------|---------|
| Zero-host-reference | `scripts/check_host_reference_gate.sh` | Verify standalone has no glibc deps |
| Host-backed burndown | `scripts/host_backed_burndown.sh` | Track WrapsHostLibc symbol reduction |
| NSS overlay | `scripts/check_nss_overlay.sh` | Verify NSS functions implemented |
| Aarch64 toolchain | `scripts/check_aarch64_toolchain.sh` | Preflight cross-compile prerequisites |
| Soak freshness | `scripts/check_soak_artifact_freshness.sh` | Verify artifact matches source |
| Buffer audit | `scripts/audit_unterminated_buffers.sh` | Audit tracked buffer handling |
| Aarch64 smoke | `scripts/run_aarch64_smoke.sh` | Currently runs a static system-libc program; actual library qualification is tracked by `bd-rc0923-epic-eeuy4f.41`–`.42` |

## Historical Session Record (2026-05-25)

The statuses below describe that session, not current closure verification or current proof that its gates exercised FrankenLibC.

Beads closed this session (13 total):
- bd-gq1kz7.10: Zero-host-reference gate (86b348b2)
- bd-gq1kz7.9: Host-backed burndown dashboard (e7a792a0)
- bd-gq1kz7.15: NSS overlay exhaustiveness (d3730f36)
- bd-gq1kz7.11: Aarch64 toolchain preflight (668a31c8)
- bd-gq1kz7.14: Soak artifact freshness (668a31c8)
- bd-gq1kz7.6: Unterminated buffer sweep (e152948c)
- bd-gq1kz7.12: Aarch64 smoke runner (a26c6e04)
- bd-gq1kz7.13: WS8 soak handoff ledger (5d342d1a)
- bd-gq1kz7.7: Native loader phase-2 contract (252f6e01)
- bd-gq1kz7.8: Two-DSO dependency fixture (1fc1b67c)
- bd-gq1kz7.1: Owned unwinder design contract (c64b3532)
- bd-gq1kz7.2: C++ exception fixture (48045a85)

Blocked beads (require implementation):
- bd-gq1kz7.3: Owned unwinder frame registry (blocked by design acceptance)
- bd-gq1kz7.4: Owned unwinder phase-1 path (blocked by .2, .3)

## Audit Trail

- `support_matrix.json`: Authoritative symbol-level classification
- `tests/conformance/`: Behavioral parity test fixtures
- `crates/frankenlibc-abi/src/`: Implementation source
- `.beads/`: Work tracking for parity defects

---

*This is a maintained interpretation of source and dated artifacts. Run the existing support-maintenance, semantic-claim and replacement-level checks, and inspect their predicates and source identities; fresh execution evidence must come from actual tests.*
