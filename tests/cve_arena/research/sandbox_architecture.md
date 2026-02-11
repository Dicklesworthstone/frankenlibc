# R3: Sandbox Architecture and LD_PRELOAD Feasibility Assessment

**Document:** CVE Arena Test Suite -- Sandbox Design
**Date:** 2026-02-10
**Status:** Feasibility Report
**Scope:** glibc_rust Transparent Safety Membrane (TSM) validation against real-world CVEs

---

## 1. LD_PRELOAD Mechanics

### 1.1 Symbol Interposition Overview

The Linux dynamic linker (`ld-linux.so`) resolves symbols in a well-defined order.
When a shared object is specified via the `LD_PRELOAD` environment variable, its
symbols take precedence over all other shared libraries, including the system libc.
This mechanism is the foundation of Mode B testing.

The resolution order for a dynamically linked executable is:

```
1. LD_PRELOAD libraries (left to right)
2. The executable itself (its own symbols)
3. DT_NEEDED dependencies in link order
4. System libc (libc.so.6)
5. ld-linux.so (dynamic linker internals)
```

When our `glibc-rs-abi` crate produces its `cdylib` artifact (hereafter referred to
as `libglibc_rs_abi.so`), setting `LD_PRELOAD=/path/to/libglibc_rs_abi.so` causes
the dynamic linker to bind calls to `malloc`, `memcpy`, `strlen`, etc. to our
implementations rather than the system glibc.

### 1.2 Interceptable Functions

Based on the current `glibc-rs-abi` version script (`version_scripts/libc.map`)
and the ABI modules in `crates/glibc-rs-abi/src/`, the following function families
can be interposed:

| Family | Symbols | ABI Module | CVE Relevance |
|--------|---------|------------|---------------|
| Allocator | `malloc`, `free`, `calloc`, `realloc` | `malloc_abi.rs` | Heap overflow, double-free, UAF |
| String/Memory | `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `strlen`, `strcmp`, `strcpy`, `strncpy`, `strcat`, `strncat`, `strchr`, `strrchr`, `strstr`, `strtok` | `string_abi.rs` | Buffer overflow, off-by-one |
| Math | `sin`, `cos`, `tan`, `exp`, `log`, `pow`, `fabs`, `ceil`, `floor`, `round`, `fmod`, `erf`, `tgamma`, `lgamma` | `math_abi.rs` | NaN injection, precision exploits |
| Wide char | wchar functions | `wchar_abi.rs` | Encoding overflows |
| iconv | (stubs, pending Phase 4) | `iconv_abi.rs` | CVE-2024-2961 |
| stdio | `printf` family, file I/O | `stdio_abi.rs` | Format string attacks |
| Process | `execve`, `fork`, `system` | `process_abi.rs` | Command injection |
| Resolver | DNS functions | `resolv_abi.rs` | DNS-based overflows |
| Socket | `connect`, `bind`, `send`, `recv` | `socket_abi.rs` | Network-facing CVEs |

### 1.3 Limitations

Several scenarios render LD_PRELOAD ineffective:

**Static linking.** If the target binary was compiled with `-static`, all libc
symbols are resolved at compile time and baked into the binary. LD_PRELOAD has no
effect. Mitigation: always build test targets with dynamic linking.

**Direct syscalls.** Programs that invoke syscalls directly via `syscall(2)` or
inline assembly bypass libc entirely. This is common in Go binaries, some Rust
binaries, and hardened security tools. Mitigation: this is out of scope for the
CVE Arena; such programs do not exercise libc at all.

**vDSO functions.** The kernel exposes certain functions (`clock_gettime`,
`gettimeofday`, `time`) via the vDSO (virtual dynamic shared object), which the
dynamic linker maps into every process. These are resolved before LD_PRELOAD in
some configurations. Mitigation: vDSO functions are not security-relevant for
our CVE test cases.

**Internal libc calls.** Within the system glibc itself, internal calls between
functions (e.g., `printf` calling `malloc`) use hidden internal symbols (prefixed
with `__GI_` or accessed via IFUNC resolvers) that are not subject to interposition.
Mitigation: this is only relevant to Mode B, and only when the vulnerability
exists in a call chain internal to libc. For Mode A, we test our own code directly.

**IFUNC resolvers.** glibc uses IFUNC (indirect function) dispatching for
architecture-optimized routines (e.g., AVX2 `memcpy`). The resolver runs at load
time and may bypass the normal symbol lookup path. Mitigation: our version script
exports symbols under `GLIBC_2.2.5`, and the dynamic linker resolves LD_PRELOAD
symbols before IFUNC dispatch.

### 1.4 GLIBC Version Symbol Resolution

The system glibc uses symbol versioning to maintain backward compatibility. Symbols
are tagged with version labels such as `GLIBC_2.2.5`, `GLIBC_2.17`, `GLIBC_2.34`.
When an application is linked against a specific glibc version, the linker records
the expected version tag in the binary's `.gnu.version_r` section.

Our `libc.map` version script currently exports all symbols under `GLIBC_2.2.5`:

```
GLIBC_2.2.5 {
    global:
        memcpy;
        malloc;
        /* ... */
    local:
        *;
};
```

This is the baseline version tag and is compatible with all binaries linked against
glibc 2.2.5 or later. For LD_PRELOAD interposition, version tags are not strictly
required -- the dynamic linker will bind to the unversioned symbol from the preloaded
library. However, for Mode A (direct linking via `-l`), version tags matter:

- Binaries expecting `GLIBC_2.17` symbols (e.g., `memcpy@GLIBC_2.17` with the
  non-overlapping-copy semantic) will resolve to our `GLIBC_2.2.5` export.
- Binaries expecting `GLIBC_2.34` symbols (e.g., `pthread_create@GLIBC_2.34`,
  after the libpthread merge) will fail to resolve unless we add those version
  tags to our map.

**Recommendation:** Extend `libc.map` incrementally. For the CVE Arena, start
with the `GLIBC_2.2.5` baseline. Add higher version tags only when a specific
CVE test target requires them.

---

## 2. Two Testing Modes

### Mode A: glibc-Internal CVEs

These CVEs exist in glibc itself, and we test whether our Rust reimplementation
prevents the vulnerability. No LD_PRELOAD is needed because we are testing our
own code directly.

**Build approach:**

```bash
# Build the glibc_rust cdylib
cargo build -p glibc-rs-abi --release

# Compile a C test harness against our libc.so
gcc -o test_cve_2024_2961 test_cve_2024_2961.c \
    -L target/release \
    -lglibc_rs_abi \
    -Wl,-rpath,target/release

# Or use LD_LIBRARY_PATH at runtime
LD_LIBRARY_PATH=target/release ./test_cve_2024_2961
```

**Test matrix:**

| Phase | libc | Expected Behavior |
|-------|------|-------------------|
| Phase 1 (baseline) | System glibc | Crash, corruption, or exploitable condition |
| Phase 2 (glibc_rust) | `libglibc_rs_abi.so` | Safe handling via TSM healing |

**Applicable CVEs:**

- CVE-2024-2961 (iconv buffer overflow)
- CVE-2024-33599 through CVE-2024-33602 (nscd/netgroup overflows)
- CVE-2023-4911 (Looney Tunables -- GLIBC_TUNABLES overflow)
- CVE-2023-6246 (syslog heap overflow via `__vsyslog_internal`)
- CVE-2023-6779 (off-by-one in `__vsyslog_internal`)
- CVE-2021-3999 (getcwd buffer underflow)
- CVE-2023-25139 (printf overflow with width specifier)

**Advantages of Mode A:**

- Full control over the test environment.
- No concern about symbol interposition edge cases.
- Deterministic: the C test harness calls our functions directly.
- Can test both `strict` and `hardened` membrane modes.

### Mode B: External Software CVEs

These CVEs exist in third-party software that uses libc functions at the
vulnerability site. We test whether our libc's membrane prevents exploitation
when the software runs against our implementation via LD_PRELOAD.

**Execution approach:**

```bash
# Build the vulnerable software version from source
git clone --branch <vulnerable-tag> <repo>
cd <repo> && make

# Run with our libc interposed
LD_PRELOAD=/path/to/libglibc_rs_abi.so ./vulnerable_binary <trigger_input>
```

**Candidate software and feasibility:**

| Software | CVE | Vulnerable Function | Uses libc Allocator? | Feasible? |
|----------|-----|---------------------|---------------------|-----------|
| sudo | CVE-2021-3156 (Baron Samedit) | Heap overflow in `set_cmnd()` via `malloc`/`realloc` | Yes (system malloc) | Yes |
| curl | CVE-2023-38545 (SOCKS5 heap overflow) | `memcpy` into heap buffer | Yes | Yes |
| Perl | CVE-2023-47038 (regex heap overflow) | `realloc` in regex engine | Yes | Yes |
| Redis | CVE-2024-31449 (Lua sandbox escape) | `malloc`/`realloc` | Default jemalloc; compile with `USE_JEMALLOC=no` | Conditional |
| VLC | CVE-2023-47359 (MMS demuxer overflow) | `malloc`/`memcpy` in MMS parser | Yes | Yes |
| glibc-linked Go programs | Various | N/A | No (Go uses direct syscalls) | No |

**When Mode B does NOT work:**

1. **Custom allocators.** Software that ships jemalloc, tcmalloc, or mimalloc
   overrides `malloc`/`free` at link time. Our LD_PRELOAD `malloc` will be
   shadowed by the application's own allocator. Mitigation: compile the software
   without its bundled allocator where possible (e.g., Redis `make USE_JEMALLOC=no`).

2. **Direct syscalls.** Programs that use `mmap`/`brk` directly for memory
   management bypass libc allocation. Mitigation: out of scope.

3. **Static linking.** Fully static binaries. Mitigation: build from source
   with dynamic linking.

4. **dlopen-loaded plugins.** If the vulnerability is in a plugin loaded via
   `dlopen`, LD_PRELOAD still applies (the dynamic linker resolves symbols for
   dlopen'd libraries in the same order). This is a non-issue.

---

## 3. Sandbox Architecture

Running real exploit code requires rigorous isolation. The sandbox uses a layered
defense model to ensure that even if a CVE test achieves code execution, it cannot
escape the test environment.

### Layer 1: Container Isolation (Docker)

Each CVE test executes inside an ephemeral Docker container. This is the primary
isolation boundary.

```dockerfile
# Base image for CVE Arena tests
FROM debian:bookworm-slim AS cve-arena-base

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root user for test execution
RUN useradd -m -s /bin/bash tester
USER tester
WORKDIR /home/tester
```

**Container runtime flags:**

```bash
docker run \
    --rm \
    --network=none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=256m \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --memory=512m \
    --cpus=1 \
    --pids-limit=64 \
    --ulimit nofile=256:256 \
    --timeout 120 \
    cve-arena-${CVE_ID}
```

| Flag | Purpose |
|------|---------|
| `--rm` | Auto-remove container on exit |
| `--network=none` | No network access (prevents data exfiltration) |
| `--read-only` | Root filesystem is read-only |
| `--tmpfs /tmp:rw,noexec,nosuid,size=256m` | Writable scratch space, no exec |
| `--cap-drop=ALL` | Drop all Linux capabilities |
| `--security-opt=no-new-privileges:true` | Prevent privilege escalation via setuid/setgid |
| `--memory=512m` | Hard memory limit |
| `--cpus=1` | Single CPU core |
| `--pids-limit=64` | Prevent fork bombs |
| `--ulimit nofile=256:256` | Limit open file descriptors |

**Exception for network-trigger CVEs:** Some CVEs require a network stimulus (e.g.,
a crafted DNS response, an HTTP request). For these tests, use `--network=bridge`
and a companion container that provides the malicious server:

```bash
docker network create --internal cve-net-${CVE_ID}
docker run --network=cve-net-${CVE_ID} malicious-server-${CVE_ID} &
docker run --network=cve-net-${CVE_ID} cve-arena-${CVE_ID}
docker network rm cve-net-${CVE_ID}
```

The `--internal` flag prevents the network from reaching the host's external
interfaces.

### Layer 2: seccomp Profiles

A custom seccomp profile restricts the system calls available inside the container,
limiting the damage from arbitrary code execution.

**Base profile (`seccomp-cve-arena.json`):**

```json
{
    "defaultAction": "SCMP_ACT_ERRNO",
    "defaultErrnoRet": 1,
    "archMap": [
        { "architecture": "SCMP_ARCH_X86_64", "subArchitectures": ["SCMP_ARCH_X86"] }
    ],
    "syscalls": [
        {
            "names": [
                "read", "write", "close", "fstat", "lseek",
                "mmap", "mprotect", "munmap", "brk",
                "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
                "ioctl", "access", "pipe", "dup", "dup2",
                "getpid", "getuid", "getgid", "geteuid", "getegid",
                "uname", "fcntl", "flock", "fsync",
                "getcwd", "readlink",
                "clock_gettime", "clock_getres",
                "openat", "newfstatat", "getdents64",
                "set_tid_address", "set_robust_list",
                "exit", "exit_group",
                "futex", "sched_yield",
                "getrandom", "rseq",
                "pread64", "pwrite64",
                "writev", "readv",
                "arch_prctl", "prctl",
                "clone3", "wait4", "waitid"
            ],
            "action": "SCMP_ACT_ALLOW"
        },
        {
            "names": ["execve", "execveat"],
            "action": "SCMP_ACT_ALLOW",
            "comment": "Allowed only because the test harness needs to exec the target binary. For tighter control, use a seccomp notifier to allow only the initial exec."
        }
    ]
}
```

**Blocked syscalls (notable):**

| Syscall | Reason for Blocking |
|---------|-------------------|
| `socket`, `connect`, `bind`, `listen`, `accept` | No network (unless network-trigger CVE) |
| `mount`, `umount2` | No filesystem manipulation |
| `ptrace` | No debugging/tracing |
| `personality` | No execution domain changes |
| `init_module`, `finit_module` | No kernel module loading |
| `reboot` | Obvious |
| `keyctl`, `request_key` | No kernel keyring access |
| `bpf` | No BPF program loading |

**Per-CVE overrides:** Some tests need additional syscalls. For example, a
network-trigger CVE test adds:

```json
{
    "names": ["socket", "connect", "sendto", "recvfrom", "setsockopt", "getsockopt"],
    "action": "SCMP_ACT_ALLOW"
}
```

Override profiles are stored alongside the CVE test definition and merged with
the base profile at container build time.

### Layer 3: Process-Level Isolation (Optional)

For CI environments where Docker is unavailable (e.g., some GitHub Actions
runners, restricted build farms), `bubblewrap` (`bwrap`) provides user-namespace
isolation without requiring root:

```bash
bwrap \
    --unshare-all \
    --die-with-parent \
    --ro-bind / / \
    --tmpfs /tmp \
    --dev /dev \
    --proc /proc \
    --clearenv \
    --setenv LD_PRELOAD /path/to/libglibc_rs_abi.so \
    --setenv HOME /tmp \
    -- /path/to/test_harness
```

This layer is optional when Docker is available. It serves as a fallback for
environments with container restrictions.

---

## 4. Test Execution Flow

### 4.1 High-Level Pipeline

```
runner.sh <CVE_ID> [--mode A|B] [--verbose]
    |
    +-- Phase 0: Validate CVE manifest exists
    |     reads: tests/cve_arena/cves/<CVE_ID>/manifest.toml
    |
    +-- Phase 1: Build container (cached via Docker layer caching)
    |     dockerfile: tests/cve_arena/cves/<CVE_ID>/Dockerfile
    |     copies in: trigger binary/script, test input, seccomp profile
    |
    +-- Phase 2: Run under STOCK glibc (baseline)
    |     docker run ... --entrypoint /test/run_baseline.sh
    |     captures: exit code, stdout, stderr, signal, core dump (if any)
    |     timeout: 30 seconds (configurable per CVE)
    |
    +-- Phase 3: Run under glibc_rust (treatment)
    |     docker run ... -e LD_PRELOAD=/test/libglibc_rs_abi.so --entrypoint /test/run_treatment.sh
    |     captures: exit code, stdout, stderr, signal, TSM healing log
    |     timeout: 30 seconds (configurable per CVE)
    |
    +-- Phase 4: Compare and render verdict
    |     reads both result sets
    |     produces: tests/cve_arena/results/<CVE_ID>.json
    |
    +-- Phase 5: (CI only) Upload result as test artifact
```

### 4.2 Manifest Format

Each CVE test is described by a TOML manifest:

```toml
# tests/cve_arena/cves/CVE-2024-2961/manifest.toml

[meta]
cve_id = "CVE-2024-2961"
title = "iconv ISO-2022-CN-EXT buffer overflow"
category = "glibc-internal"          # or "external"
severity = "critical"
published = "2024-04-17"

[build]
mode = "A"                           # A = glibc-internal, B = LD_PRELOAD
base_image = "debian:bookworm-slim"
extra_packages = []
build_script = "build.sh"            # relative to CVE directory

[trigger]
binary = "trigger_2024_2961"         # compiled from trigger.c
args = []
stdin_file = "payload.bin"           # optional: feed to stdin
timeout_seconds = 30
needs_network = false

[expected.stock_glibc]
exit_code = 139                      # SIGSEGV
signal = "SIGSEGV"
exploitable = true

[expected.glibc_rust]
exit_code = 0
signal = "none"
exploitable = false
healing_action = "ClampSize"

[seccomp]
profile = "default"                  # or "network" or "custom.json"
```

### 4.3 Detecting Exploitation vs. Safe Handling

The test runner uses multiple signals to determine the outcome:

1. **Exit code.** A non-zero exit code (especially 128+N indicating signal N)
   suggests a crash. Exit code 139 = SIGSEGV, 134 = SIGABRT, 136 = SIGFPE.

2. **Signal detection.** The runner wraps the target in a signal-catching harness
   that logs which signal terminated the process.

3. **Canary verification.** For heap overflow CVEs, the trigger program writes a
   known canary pattern after the vulnerable buffer. If the canary is intact after
   the operation, no overflow occurred.

4. **TSM healing log.** When running under glibc_rust in hardened mode, the
   membrane logs every healing action to stderr (or a dedicated file descriptor).
   The runner captures this log and parses it for the specific healing action
   applied.

5. **Output comparison.** Some CVEs produce incorrect output when exploited (e.g.,
   a format string attack producing unexpected output). The runner compares stdout
   against expected output.

```bash
#!/usr/bin/env bash
# run_treatment.sh -- executed inside the container

export GLIBC_RS_LOG=healing     # enable TSM healing log
export GLIBC_RS_MODE=hardened   # enable healing (not just detection)

timeout ${TIMEOUT:-30} /test/${TRIGGER_BINARY} ${TRIGGER_ARGS} \
    < "${STDIN_FILE:-/dev/null}" \
    > /tmp/stdout.log \
    2> /tmp/stderr.log

EXIT_CODE=$?
SIGNAL=""

if [ $EXIT_CODE -gt 128 ]; then
    SIGNAL=$(kill -l $(($EXIT_CODE - 128)) 2>/dev/null || echo "unknown")
fi

# Write structured result
cat > /tmp/result.json << RESULT_EOF
{
    "exit_code": ${EXIT_CODE},
    "signal": $([ -n "$SIGNAL" ] && echo "\"$SIGNAL\"" || echo "null"),
    "stdout_path": "/tmp/stdout.log",
    "stderr_path": "/tmp/stderr.log"
}
RESULT_EOF
```

---

## 5. Result Capture Format

### 5.1 JSON Schema

All CVE test results conform to the following JSON schema. The runner produces one
result file per CVE test execution.

```json
{
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "CVE Arena Test Result",
    "type": "object",
    "required": [
        "schema_version",
        "cve_id",
        "test_name",
        "category",
        "timestamp",
        "stock_glibc",
        "glibc_rust",
        "verdict"
    ],
    "properties": {
        "schema_version": {
            "type": "integer",
            "const": 1,
            "description": "Schema version for forward compatibility."
        },
        "cve_id": {
            "type": "string",
            "pattern": "^CVE-\\d{4}-\\d{4,}$",
            "description": "The CVE identifier."
        },
        "test_name": {
            "type": "string",
            "description": "Human-readable short name for the test."
        },
        "category": {
            "type": "string",
            "enum": ["glibc-internal", "external"],
            "description": "Whether this tests our own code or external software."
        },
        "timestamp": {
            "type": "string",
            "format": "date-time",
            "description": "ISO 8601 timestamp of test execution."
        },
        "stock_glibc": { "$ref": "#/$defs/execution_result" },
        "glibc_rust": { "$ref": "#/$defs/execution_result_with_healing" },
        "verdict": {
            "type": "string",
            "enum": ["PREVENTED", "MITIGATED", "NOT_PREVENTED", "INCONCLUSIVE", "SKIPPED"],
            "description": "Overall test verdict."
        },
        "notes": {
            "type": "string",
            "description": "Optional human-readable notes about the result."
        }
    },
    "$defs": {
        "execution_result": {
            "type": "object",
            "required": ["exit_code", "exploitable"],
            "properties": {
                "exit_code": { "type": "integer" },
                "signal": { "type": ["string", "null"] },
                "stdout": { "type": "string", "description": "Truncated to 4096 bytes." },
                "stderr": { "type": "string", "description": "Truncated to 4096 bytes." },
                "exploitable": { "type": "boolean" },
                "duration_ms": { "type": "integer" },
                "canary_intact": { "type": ["boolean", "null"] }
            }
        },
        "execution_result_with_healing": {
            "allOf": [
                { "$ref": "#/$defs/execution_result" },
                {
                    "type": "object",
                    "properties": {
                        "healing_action": {
                            "type": ["string", "null"],
                            "enum": [
                                null,
                                "ClampSize",
                                "TruncateWithNull",
                                "IgnoreDoubleFree",
                                "IgnoreForeignFree",
                                "ReallocAsMalloc",
                                "ReturnSafeDefault",
                                "UpgradeToSafeVariant",
                                "None"
                            ],
                            "description": "The HealingAction variant applied by the TSM."
                        },
                        "tsm_log": {
                            "type": ["string", "null"],
                            "description": "Raw TSM healing log output."
                        },
                        "membrane_mode": {
                            "type": "string",
                            "enum": ["strict", "hardened"],
                            "description": "Which membrane mode was active."
                        }
                    }
                }
            ]
        }
    }
}
```

### 5.2 Example Result

```json
{
    "schema_version": 1,
    "cve_id": "CVE-2024-2961",
    "test_name": "iconv_overflow",
    "category": "glibc-internal",
    "timestamp": "2026-02-10T00:00:00Z",
    "stock_glibc": {
        "exit_code": 139,
        "signal": "SIGSEGV",
        "stdout": "",
        "stderr": "*** buffer overflow detected ***: terminated",
        "exploitable": true,
        "duration_ms": 12,
        "canary_intact": false
    },
    "glibc_rust": {
        "exit_code": 0,
        "signal": null,
        "stdout": "",
        "stderr": "[tsm::heal] ClampSize { requested: 65536, clamped: 4096 }",
        "exploitable": false,
        "healing_action": "ClampSize",
        "tsm_log": "[tsm::heal] ClampSize { requested: 65536, clamped: 4096 }\n[tsm::heal] total_heals=1 size_clamps=1",
        "membrane_mode": "hardened",
        "duration_ms": 8,
        "canary_intact": true
    },
    "verdict": "PREVENTED",
    "notes": "The TSM membrane clamped the iconv output buffer write to the allocated size, preventing the heap overflow."
}
```

### 5.3 Verdict Logic

The verdict is computed from the two execution results:

| stock_glibc.exploitable | glibc_rust.exploitable | glibc_rust.healing_action | Verdict |
|------------------------|----------------------|--------------------------|---------|
| true | false | any healing action | `PREVENTED` |
| true | false | None | `MITIGATED` (safe behavior without explicit healing) |
| true | true | any | `NOT_PREVENTED` |
| false | false | any | `INCONCLUSIVE` (baseline did not trigger vulnerability) |
| (error/timeout) | any | any | `INCONCLUSIVE` |
| any | (error/timeout) | any | `INCONCLUSIVE` |

A `SKIPPED` verdict is set manually when a CVE test is known to be inapplicable
on the current platform (e.g., architecture-specific CVEs on the wrong arch).

---

## 6. Challenges and Mitigations

### 6.1 Custom Allocators in Target Software

**Challenge:** Several high-value targets ship with their own memory allocator,
which overrides `malloc`/`free` at link time. When this happens, our LD_PRELOAD
allocator is shadowed, and heap-related CVEs cannot be tested.

| Software | Bundled Allocator | Workaround |
|----------|-------------------|------------|
| Redis | jemalloc | `make USE_JEMALLOC=no MALLOC=libc` |
| Firefox | mozjemalloc | Not feasible to disable; out of scope |
| Chromium | PartitionAlloc | Not feasible to disable; out of scope |
| Node.js | V8 allocator (partial) | Use `--no-lto` and ensure libc malloc is primary |
| nginx | System malloc by default | No workaround needed |

**Mitigation:** For each Mode B target, verify during CVE manifest creation that
the vulnerability site actually flows through libc allocation. Document the build
flags required to use system malloc.

### 6.2 ASLR and Determinism

**Challenge:** Address Space Layout Randomization (ASLR) makes exploit behavior
non-deterministic. A heap overflow might crash on one run and silently corrupt on
another, depending on memory layout.

**Mitigation:** Disable ASLR inside the container for deterministic results:

```bash
docker run ... --sysctl kernel.randomize_va_space=0 ...
```

Or at the process level:

```bash
setarch $(uname -m) -R /test/trigger_binary
```

Note: disabling ASLR makes exploitation easier, which is desirable for the
baseline (stock glibc) run -- we want to reliably trigger the vulnerability. The
glibc_rust run should prevent exploitation regardless of ASLR state.

### 6.3 Signal Handling and Silent Corruption

**Challenge:** Not all exploits result in a clean crash. Some overflows corrupt
heap metadata silently, leading to delayed crashes or incorrect output without a
signal.

**Mitigation:** Use multiple detection mechanisms:

1. **Heap canaries.** Place a known 8-byte pattern immediately after the vulnerable
   buffer. After the trigger operation, verify the canary is intact.

2. **Output verification.** Compare program output against known-good output. Any
   deviation indicates corruption.

3. **AddressSanitizer (ASan) baseline.** For the stock glibc run, compile the
   trigger with `-fsanitize=address` to get reliable crash-on-overflow behavior.
   This makes the baseline more deterministic.

4. **TSM healing counters.** After the glibc_rust run, query the healing policy
   counters (`total_heals`, `size_clamps`, etc.) to verify that the membrane
   actively intervened, even if the output looks normal.

### 6.4 Race Condition CVEs

**Challenge:** Some CVEs exploit race conditions (TOCTOU, double-fetch, etc.)
that require precise thread scheduling to trigger reliably.

**Mitigation:**

1. **Repeated execution.** Run race-condition tests N times (configurable,
   default 100) and report the exploitation rate.

2. **Thread pinning.** Use `taskset` to pin threads to specific cores, improving
   reproducibility.

3. **Controlled scheduling.** For known race windows, insert a `usleep()` in the
   trigger code at the race point to widen the window.

4. **Probabilistic verdicts.** For race-condition CVEs, the verdict includes an
   exploitation rate: `"exploitation_rate": 0.73` means 73 out of 100 runs were
   exploitable under stock glibc.

### 6.5 Version Script Gaps

**Challenge:** Our current `libc.map` exports symbols only under `GLIBC_2.2.5`.
Some target binaries may require symbols under higher version tags.

**Mitigation:** Inspect each target binary with:

```bash
objdump -T <binary> | grep GLIBC_
readelf -V <binary>
```

If version tags beyond `GLIBC_2.2.5` are required, add them to `libc.map`. For
LD_PRELOAD mode, unversioned symbols generally take precedence, so this is
primarily a concern for Mode A.

### 6.6 Thread-Local Storage and ELF TLS Model

**Challenge:** glibc uses the initial-exec TLS model for performance. Our Rust
cdylib uses the general-dynamic TLS model by default. If the target binary
expects initial-exec TLS layout for libc globals (e.g., `errno`), loading our
library via LD_PRELOAD may cause TLS allocation failures.

**Mitigation:** The `glibc-rs-abi` crate already handles `errno` via
`errno_abi.rs`. For LD_PRELOAD mode, ensure our TLS usage is minimal and uses
`#[thread_local]` (which compiles to initial-exec on Linux). Monitor for
`dlopen` failures that mention TLS.

### 6.7 Container Image Caching and Build Times

**Challenge:** Building vulnerable software from source for each test run is
slow. VLC, for instance, can take 30+ minutes to build.

**Mitigation:**

1. **Docker layer caching.** Use multi-stage Dockerfiles with the vulnerable
   software build in an early stage. The build stage is cached; only the test
   harness layer changes between runs.

2. **Pre-built container registry.** Publish pre-built CVE test containers to a
   private registry. CI pulls the cached image instead of building from source.

3. **Build once, test twice.** The same container image is used for both the
   stock glibc and glibc_rust runs; only the LD_PRELOAD environment variable
   differs.

---

## 7. Recommended Implementation Order

The implementation should proceed from least complex to most complex, building
confidence and infrastructure incrementally.

### Phase 1: glibc-Internal CVEs (Mode A)

**Target:** Weeks 1-2
**Complexity:** Low
**Dependencies:** glibc-rs-abi cdylib builds successfully

| Priority | CVE | Function | Healing Action |
|----------|-----|----------|---------------|
| 1 | CVE-2024-2961 | `iconv` | ClampSize |
| 2 | CVE-2023-6246 | `syslog` / `__vsyslog_internal` | ClampSize |
| 3 | CVE-2023-6779 | `__vsyslog_internal` (off-by-one) | TruncateWithNull |
| 4 | CVE-2021-3999 | `getcwd` | ReturnSafeDefault |
| 5 | CVE-2023-25139 | `printf` (width specifier) | ClampSize |
| 6 | CVE-2023-4911 | Tunable parsing | ClampSize |

Start here because:
- No LD_PRELOAD complexity.
- No external software builds.
- Directly validates our core reimplementation.
- Fastest feedback loop.

### Phase 2: sudo (Simplest External Target)

**Target:** Week 3
**Complexity:** Medium
**Dependencies:** Mode A infrastructure working, Docker sandbox proven

| CVE | Version | Build Complexity |
|-----|---------|-----------------|
| CVE-2021-3156 (Baron Samedit) | sudo < 1.9.5p2 | Low (autoconf, no special deps) |

Start with sudo because:
- Well-understood PoC with public exploit code.
- Small codebase, fast build.
- Uses system malloc (no custom allocator).
- Clear vulnerability site: heap overflow in `set_cmnd()` via `malloc`/`realloc`.
- The trigger is a single command line: `sudoedit -s '\' $(python3 -c 'print("A"*65536)')`.

### Phase 3: curl and Perl

**Target:** Weeks 4-5
**Complexity:** Medium

| CVE | Software | Version | Build Complexity |
|-----|----------|---------|-----------------|
| CVE-2023-38545 | curl | 8.4.0 | Medium (OpenSSL dependency) |
| CVE-2023-47038 | Perl | 5.34.x - 5.36.x | Medium (standard autoconf) |

curl and Perl both:
- Use system malloc.
- Have well-documented PoCs.
- Build in under 10 minutes.
- Exercise `memcpy`/`realloc` at the vulnerability site.

### Phase 4: Redis

**Target:** Week 6
**Complexity:** Medium-High

| CVE | Version | Build Notes |
|-----|---------|-------------|
| CVE-2024-31449 | Redis < 7.2.5 | Must compile with `USE_JEMALLOC=no MALLOC=libc` |

Redis requires the jemalloc workaround, which adds build complexity and may
change behavior. Test carefully that the vulnerability still triggers when using
system malloc.

### Phase 5: VLC

**Target:** Weeks 7-8
**Complexity:** High

| CVE | Version | Build Notes |
|-----|---------|-------------|
| CVE-2023-47359 | VLC < 3.0.20 | Many dependencies (FFmpeg, libav*, etc.) |

VLC is last because:
- Complex build with many dependencies.
- Long build time (30+ minutes).
- Requires multimedia codec libraries.
- The MMS demuxer vulnerability requires crafted network input.

---

## Appendix A: Directory Structure

The proposed CVE Arena directory layout:

```
tests/cve_arena/
    runner.sh                         # Main test runner
    lib/
        verdict.sh                    # Verdict computation logic
        container.sh                  # Docker container management
        capture.sh                    # Result capture and JSON generation
    research/
        sandbox_architecture.md       # This document
    seccomp/
        base.json                     # Base seccomp profile
        network.json                  # Network-enabled seccomp profile
    cves/
        CVE-2024-2961/
            manifest.toml             # Test manifest
            Dockerfile                # Container definition
            trigger.c                 # Trigger/PoC source
            payload.bin               # Optional trigger input
            build.sh                  # Build script
            expected_output.txt       # Optional expected output
        CVE-2021-3156/
            manifest.toml
            Dockerfile
            trigger.sh
            ...
    results/
        CVE-2024-2961.json            # Test result
        CVE-2021-3156.json
        ...
    ci/
        run_all.sh                    # CI entry point
        report.py                     # Generate summary report from results/
```

## Appendix B: Mapping HealingAction to CVE Classes

The `HealingAction` variants defined in `crates/glibc-rs-membrane/src/heal.rs`
map to CVE vulnerability classes as follows:

| HealingAction | Vulnerability Class | Example CVEs |
|---------------|-------------------|--------------|
| `ClampSize` | Heap buffer overflow, integer overflow in size | CVE-2024-2961, CVE-2023-6246, CVE-2023-38545 |
| `TruncateWithNull` | Stack buffer overflow via unterminated strings | CVE-2023-6779 |
| `IgnoreDoubleFree` | Double-free leading to arbitrary write | CVE-2020-1751 |
| `IgnoreForeignFree` | Free of invalid pointer | Various |
| `ReallocAsMalloc` | Use-after-free via realloc of freed pointer | Various |
| `ReturnSafeDefault` | Logic errors from invalid input | CVE-2021-3999 |
| `UpgradeToSafeVariant` | Unbounded copy via `strcpy`/`strcat` | CVE-2021-3156 |

## Appendix C: Quick Reference Commands

```bash
# Build the glibc_rust cdylib
cargo build -p glibc-rs-abi --release

# Verify exported symbols
nm -D target/release/libglibc_rs_abi.so | grep ' T '

# Check symbol versions
objdump -T target/release/libglibc_rs_abi.so | head -40

# Run a simple interposition test
LD_PRELOAD=target/release/libglibc_rs_abi.so /bin/ls

# Inspect a target binary's glibc version requirements
readelf -V /usr/bin/sudo

# Run a CVE test
./tests/cve_arena/runner.sh CVE-2024-2961

# Run all CVE tests in CI
./tests/cve_arena/ci/run_all.sh --parallel 4 --output results/
```
