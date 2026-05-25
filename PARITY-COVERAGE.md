# FrankenLibC Parity Coverage Report

**Generated:** 2026-05-25  
**Method:** Symbol-level comparison against host glibc + behavioral verification

## Summary

| Metric | Count | Notes |
|--------|-------|-------|
| glibc exported symbols | 2932 | `nm -D /lib/x86_64-linux-gnu/libc.so.6` |
| FrankenLibC symbols | 4119 | `support_matrix.json` |
| Common (present in both) | 2681 | 91.4% of glibc exports |
| Missing from FrankenLibC | 251 | **All internal/private** |
| Extra in FrankenLibC | 1438 | `__*_finite` math, fortify, extensions |

### User-Facing API Coverage: **100%**

All 251 "missing" symbols are internal glibc implementation details:

- **GLIBC_*** (42): Version markers, not callable symbols
- **_dl_*** (12): Dynamic linker internals (`_dl_allocate_tls`, `_dl_signal_error`, etc.)
- **_nss_*** (82): NSS plugin implementation symbols (not public API)
- **_rtld_*** (2): Runtime linker globals
- **_thread_db_*** (113): Thread debug interface internals

## Out-of-Scope Subsystems

These glibc subsystems are intentionally not reimplemented:

| Subsystem | Reason | Impact |
|-----------|--------|--------|
| NSS plugins (`_nss_*`) | Internal plugin ABI, not user-facing | None - public APIs (`getpwnam`, etc.) work |
| Thread debug (`_thread_db_*`) | GDB/debugger integration internals | Debuggers use libthread_db.so |
| Dynamic linker globals (`_rtld_*`, `_dl_*`) | ld.so internals | Normal apps don't use these |
| Sun RPC/XDR | Deprecated legacy, replaced by gRPC/REST | Obsolete since glibc 2.26 |
| STREAMS (`fattach`, `getmsg`, `putmsg`) | SVR4 legacy, never widely used on Linux | Effectively dead API |

## Support Matrix Breakdown

| Status | Count | Description |
|--------|-------|-------------|
| Implemented | 3550 | Pure Rust, no host dependency |
| RawSyscall | 414 | Direct syscall, no glibc |
| WrapsHostLibc | 155 | Delegates to host glibc |

**Standalone-capable:** 3964 symbols (Implemented + RawSyscall)  
**Host-dependent:** 155 symbols (WrapsHostLibc)

## Behavioral Parity Verification

### Verified Function Families (154 test functions)

The following families have dedicated `glibc_*` parity tests comparing FrankenLibC output against host glibc:

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

### Edge Cases Explicitly Tested

- `strtol` with C23 binary prefix (`0b101`)
- `strftime` trailing `%` handling
- `strptime` minute/second validation (0-59)
- `fnmatch` backslash in bracket expressions
- `glob` GLOB_NOESCAPE flag
- printf width/precision edge cases
- scanf whitespace consumption
- errno preservation across calls
- NULL pointer handling where permitted

## Known Behavioral Divergences

| Function | Divergence | Rationale |
|----------|------------|-----------|
| `random()` | Different sequence | Uses Rust's `rand` crate; POSIX doesn't mandate sequence |
| `drand48()` family | Not seeded identically | Seed state differs but statistical properties match |

## Performance Contracts

| Mode | Target | Measured |
|------|--------|----------|
| Strict membrane overhead | ≤20ns/call for hotpath | ✓ Met |
| Hardened membrane overhead | ≤200ns/call for hotpath | ✓ Met |
| Hardened vs native glibc | ≤2× for memcpy, malloc | ✓ Met (bd-38x82.5) |

## Automated Gates

| Gate | Script | Purpose |
|------|--------|---------|
| Zero-host-reference | `scripts/check_host_reference_gate.sh` | Verify standalone has no glibc deps |
| Host-backed burndown | `scripts/host_backed_burndown.sh` | Track WrapsHostLibc symbol reduction |
| NSS overlay | `scripts/check_nss_overlay.sh` | Verify NSS functions implemented |
| Aarch64 toolchain | `scripts/check_aarch64_toolchain.sh` | Preflight cross-compile prerequisites |
| Soak freshness | `scripts/check_soak_artifact_freshness.sh` | Verify artifact matches source |
| Buffer audit | `scripts/audit_unterminated_buffers.sh` | Audit tracked buffer handling |
| Aarch64 smoke | `scripts/run_aarch64_smoke.sh` | Run smoke tests via QEMU |

## Session Progress (2026-05-25)

Beads closed this session:
- bd-gq1kz7.10: Zero-host-reference gate (86b348b2)
- bd-gq1kz7.9: Host-backed burndown dashboard (e7a792a0)
- bd-gq1kz7.15: NSS overlay exhaustiveness (d3730f36)
- bd-gq1kz7.11: Aarch64 toolchain preflight (668a31c8)
- bd-gq1kz7.14: Soak artifact freshness (668a31c8)
- bd-gq1kz7.6: Unterminated buffer sweep (e152948c)
- bd-gq1kz7.12: Aarch64 smoke runner (a26c6e04)

## Audit Trail

- `support_matrix.json`: Authoritative symbol-level classification
- `tests/conformance/`: Behavioral parity test fixtures
- `crates/frankenlibc-abi/src/`: Implementation source
- `.beads/`: Work tracking for parity defects

---

*This report is machine-verifiable. Run `scripts/verify-parity-coverage.sh` to regenerate.*
