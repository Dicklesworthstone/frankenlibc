# R4: Synthetic CVE Reproduction Patterns for Proprietary Software

**Document**: R4 -- CVE Arena Synthetic Patterns
**Component**: Transparent Safety Membrane (TSM) validation
**Crate**: `glibc-rs-membrane`
**Status**: Active research artifact

---

## Purpose

This document specifies three minimal, self-contained C programs that reproduce
the exact memory corruption patterns found in high-impact proprietary software
CVEs. Each synthetic program isolates the root CWE class without referencing,
decompiling, or otherwise incorporating any proprietary code. The goal is to
validate that the TSM's healing actions, generational arena, canary detection,
and validation pipeline correctly detect and neutralize each corruption pattern
when glibc_rust is used as the system C library.

### TSM Features Under Test

| Feature | Source |
|---|---|
| `ClampSize` | `heal.rs` -- `HealingAction::ClampSize` |
| `TruncateWithNull` | `heal.rs` -- `HealingAction::TruncateWithNull` |
| `IgnoreDoubleFree` | `heal.rs` -- `HealingAction::IgnoreDoubleFree` |
| `IgnoreForeignFree` | `heal.rs` -- `HealingAction::IgnoreForeignFree` |
| `ReallocAsMalloc` | `heal.rs` -- `HealingAction::ReallocAsMalloc` |
| `ReturnSafeDefault` | `heal.rs` -- `HealingAction::ReturnSafeDefault` |
| `UpgradeToSafeVariant` | `heal.rs` -- `HealingAction::UpgradeToSafeVariant` |
| Generational arena with quarantine | `arena.rs` -- `AllocationArena`, `QuarantineEntry` |
| Allocation fingerprints | `fingerprint.rs` -- `AllocationFingerprint` (SipHash-2-4) |
| Trailing canaries | `fingerprint.rs` -- `Canary` (8-byte XOR-folded pattern) |
| Bloom filter pre-check | `bloom.rs` -- `PointerBloomFilter` |
| Page oracle ownership | `page_oracle.rs` -- `PageOracle` |
| Bounds computation | `ptr_validator.rs` -- `ValidationPipeline::remaining_from` |
| TLS validation cache | `tls_cache.rs` -- thread-local cached validation |

---

## Pattern 1: Format String Vulnerability

### CVE Reference

| Field | Value |
|---|---|
| **CVE** | CVE-2024-23113 |
| **Vendor** | Fortinet |
| **Product** | FortiOS (FGFM daemon) |
| **CVSS** | 9.8 (Critical) |
| **CWE** | CWE-134: Use of Externally-Controlled Format String |
| **Discovered** | 2024 |
| **Impact** | Remote code execution, information disclosure |

### Why We Cannot Use the Proprietary Code

FortiOS is closed-source commercial firmware. The FGFM daemon binary is
distributed only as compiled ARM/x86 images inside Fortinet appliance firmware.
Reverse-engineering it would violate Fortinet's license agreement, the DMCA
(17 U.S.C. 1201), and potentially CFAA provisions. The CVE advisory and
CWE classification are public, but the vulnerable source code is not.

### Memory Corruption Pattern Being Reproduced

The FGFM daemon accepts connections on TCP port 541 and passes
attacker-controlled input directly as the format string argument to a
`printf`-family function (in this case, the pattern maps to `syslog()`). The
attacker sends a string containing format specifiers such as `%x` (read stack
data), `%s` (read arbitrary memory via stack pointer), and `%n` (write to an
address on the stack). The root cause is always the same: a string that should
appear as a *data argument* to a format function instead appears as the *format
argument*.

The synthetic program reproduces the identical code pattern: read a line from a
TCP socket, pass it as the format string to `syslog()`.

### Synthetic Trigger Program

```c
/*
 * synthetic_fmtstr_server.c
 *
 * Reproduces CWE-134 (format string vulnerability) in the same pattern
 * as CVE-2024-23113. A TCP server reads a line from the network and
 * passes it directly as the format string to syslog().
 *
 * Compile:
 *   gcc -Wall -Wextra -o synthetic_fmtstr_server synthetic_fmtstr_server.c
 *
 * WARNING: This program is intentionally vulnerable. Run only in an
 * isolated environment (VM, container with no network exposure).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LISTEN_PORT 9134
#define BUF_SIZE    512

/*
 * Step 1: Accept a TCP connection.
 * Step 2: Read a line of input.
 * Step 3: Pass it as the format string to syslog() -- THIS IS THE BUG.
 *
 * The correct code would be:
 *   syslog(LOG_INFO, "%s", buf);
 *
 * The vulnerable code is:
 *   syslog(LOG_INFO, buf);          <-- attacker controls format string
 */
static void handle_client(int client_fd)
{
    char buf[BUF_SIZE];
    ssize_t n;

    /* Step 2: Read a line of input from the network. */
    n = read(client_fd, buf, BUF_SIZE - 1);
    if (n <= 0) {
        close(client_fd);
        return;
    }
    buf[n] = '\0';

    /* Strip trailing newline. */
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';

    /*
     * Step 3: THE VULNERABILITY.
     *
     * The developer intended to log the user-supplied message. Instead of
     * passing buf as a data argument, buf is passed as the format string.
     * If buf contains "%x", syslog will read the next value from the stack
     * and format it as hex. If buf contains "%n", syslog will WRITE the
     * number of characters output so far to the address found on the stack.
     *
     * This is identical in structure to the FGFM daemon vulnerability:
     * attacker-controlled data used directly as a format string.
     */
    syslog(LOG_INFO, buf);  /* BUG: should be syslog(LOG_INFO, "%s", buf) */

    /*
     * For demonstration: also print to stdout so we can observe the leak
     * without needing to check syslog output.
     */
    printf(buf);            /* BUG: same pattern, easier to observe */
    printf("\n");
    fflush(stdout);

    close(client_fd);
}

int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    openlog("fmtstr_synth", LOG_PID | LOG_NDELAY, LOG_USER);

    /* Step 1: Create a TCP server socket. */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 1) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("[*] Listening on 127.0.0.1:%d\n", LISTEN_PORT);

    /* Accept one connection for demonstration. */
    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        return 1;
    }

    printf("[*] Client connected\n");
    handle_client(client_fd);

    close(server_fd);
    closelog();
    return 0;
}
```

### Attack Payload

```
# Information leak: read 8 values from the stack as hex.
# Each %08x pops and prints one 32-bit value from the stack frame.
echo '%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x' | nc 127.0.0.1 9134

# Stack write: %n writes the count of characters printed so far to the
# address found at the corresponding position on the stack.
# In a real exploit this would be a carefully crafted address, but for
# demonstration the write target is whatever pointer happens to be on
# the stack. This will likely crash the process (SIGSEGV) because the
# stack value is not a valid writable address.
echo 'AAAA%08x.%08x.%08x.%n' | nc 127.0.0.1 9134
```

### Expected Behavior: Stock glibc

| Payload | Observed behavior |
|---|---|
| `%08x.%08x...` | Server prints hex-encoded stack contents. Attacker learns stack layout, pointer values, and potentially canary values from the process. |
| `AAAA...%n` | Server writes a 4-byte integer to whatever address sits at the corresponding stack position. Likely crashes with SIGSEGV; a crafted exploit chains this into arbitrary write and then code execution. |

### Expected Behavior: glibc_rust with TSM

| TSM component | Action |
|---|---|
| **UpgradeToSafeVariant** | The TSM intercepts the `printf`/`syslog` call at the ABI boundary. It detects that the format string argument contains specifiers (`%x`, `%n`, `%s`) but was called with a variable (non-literal) format string and no corresponding variadic arguments on the stack matching the specifier count. The call is upgraded: `syslog(LOG_INFO, buf)` is replaced with `syslog(LOG_INFO, "%s", buf)`, treating the entire input as a literal string. |
| **ReturnSafeDefault** | If the format-string analysis determines that `%n` writes are present, the call is suppressed entirely and a safe default (empty log message) is returned. |
| **Metrics** | `variant_upgrades` counter in `HealingPolicy` increments. The `spectral_monitor` records the event for anomaly detection. |

### Primary Healing Action

**`UpgradeToSafeVariant`** fires because the membrane's format-string
interposition layer detects a mismatch between the specifier count in the
format string and the actual number of variadic arguments passed on the
stack. This is the canonical remediation for CWE-134: ensure user data
never occupies the format-string position.

---

## Pattern 2: DCERPC-style Heap Overflow (Confused Length Field)

### CVE Reference

| Field | Value |
|---|---|
| **CVE** | CVE-2024-38812 |
| **Vendor** | VMware (Broadcom) |
| **Product** | vCenter Server (DCERPC protocol handler) |
| **CVSS** | 9.8 (Critical) |
| **CWE** | CWE-122: Heap-based Buffer Overflow |
| **Discovered** | 2024 |
| **Impact** | Remote code execution via heap corruption |

### Why We Cannot Use the Proprietary Code

VMware vCenter Server is proprietary commercial software. The DCERPC protocol
handler is implemented in a closed-source shared library within the vCenter
appliance. Source code is not publicly available. The vulnerability details
come from VMware's security advisory (VMSA-2024-0019) and independent
security research describing the bug class (confused length fields in a
binary protocol parser). Reproducing the exact source would require
reverse-engineering proprietary binaries, violating VMware's EULA and
applicable intellectual property law.

### Memory Corruption Pattern Being Reproduced

The vCenter DCERPC handler parses a binary protocol packet that contains two
length fields: one used to determine the malloc allocation size, and a
different (larger) one used to determine how many bytes are copied into the
allocated buffer. The attacker crafts a packet where `copy_len > alloc_len`,
causing a classic heap buffer overflow.

The synthetic program reproduces this "confused length field" pattern with a
simplified 4-byte binary protocol header:
- Bytes 0-1: magic number (`0xDC`, `0x3C`)
- Byte 2: `alloc_len` -- determines `malloc()` size
- Byte 3: `copy_len` -- determines `read()` count into the buffer

When `copy_len > alloc_len`, the heap is corrupted.

### Synthetic Trigger Program

```c
/*
 * synthetic_dcerpc_overflow.c
 *
 * Reproduces CWE-122 (heap buffer overflow) in the same "confused length
 * field" pattern as CVE-2024-38812. A server reads a simplified binary
 * protocol header, allocates a buffer based on one length field, and
 * copies data based on a different (larger) length field.
 *
 * Compile:
 *   gcc -Wall -Wextra -o synthetic_dcerpc_overflow synthetic_dcerpc_overflow.c
 *
 * WARNING: This program is intentionally vulnerable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define LISTEN_PORT   9122
#define MAGIC_0       0xDC
#define MAGIC_1       0x3C

/*
 * Simplified DCERPC-like packet header:
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *   0       1     magic[0] = 0xDC
 *   1       1     magic[1] = 0x3C
 *   2       1     alloc_len   (buffer allocation size, 1-255)
 *   3       1     copy_len    (bytes to read into buffer, 1-255)
 *
 * Followed by `copy_len` bytes of payload data.
 *
 * THE BUG: alloc_len and copy_len are independent. The server trusts both
 * without checking that copy_len <= alloc_len. When copy_len > alloc_len,
 * the excess bytes overflow past the end of the heap buffer.
 */
struct dcerpc_header {
    unsigned char magic[2];
    unsigned char alloc_len;
    unsigned char copy_len;
};

/*
 * Read exactly `count` bytes from `fd`, handling partial reads.
 * Returns 0 on success, -1 on failure.
 */
static int read_exact(int fd, void *buf, size_t count)
{
    size_t total = 0;
    while (total < count) {
        ssize_t n = read(fd, (char *)buf + total, count - total);
        if (n <= 0) return -1;
        total += (size_t)n;
    }
    return 0;
}

static void handle_client(int client_fd)
{
    struct dcerpc_header hdr;

    /* Step 1: Read the 4-byte header. */
    if (read_exact(client_fd, &hdr, sizeof(hdr)) < 0) {
        fprintf(stderr, "[!] Failed to read header\n");
        close(client_fd);
        return;
    }

    /* Validate magic bytes. */
    if (hdr.magic[0] != MAGIC_0 || hdr.magic[1] != MAGIC_1) {
        fprintf(stderr, "[!] Bad magic: %02x %02x\n", hdr.magic[0], hdr.magic[1]);
        close(client_fd);
        return;
    }

    printf("[*] Header: alloc_len=%u, copy_len=%u\n", hdr.alloc_len, hdr.copy_len);

    /*
     * Step 2: Allocate a buffer using alloc_len.
     *
     * This is the size the developer *thought* the packet payload would be.
     */
    unsigned char *buf = (unsigned char *)malloc(hdr.alloc_len);
    if (!buf) {
        fprintf(stderr, "[!] malloc(%u) failed\n", hdr.alloc_len);
        close(client_fd);
        return;
    }

    /*
     * Step 3: Read copy_len bytes into the buffer.
     *
     * THE VULNERABILITY: copy_len may be larger than alloc_len. The read
     * will write past the end of the malloc'd buffer, corrupting adjacent
     * heap metadata and objects.
     *
     * In the real CVE-2024-38812, the DCERPC packet has two different length
     * fields (one in the PDU header, one in the stub data), and the code
     * uses the wrong one for the copy operation.
     */
    if (hdr.copy_len > 0) {
        if (read_exact(client_fd, buf, hdr.copy_len) < 0) {  /* BUG: should use alloc_len */
            fprintf(stderr, "[!] Failed to read payload\n");
            free(buf);
            close(client_fd);
            return;
        }
    }

    printf("[*] Received %u bytes into %u-byte buffer\n", hdr.copy_len, hdr.alloc_len);

    /*
     * Process the "message" (in a real server, this would parse DCERPC
     * stub data). For demonstration, just hexdump the buffer contents.
     */
    printf("[*] Buffer contents: ");
    for (int i = 0; i < hdr.alloc_len && i < 32; i++) {
        printf("%02x ", buf[i]);
    }
    printf("\n");

    /* Step 4: Free the buffer. Canary corruption is detected here. */
    free(buf);
    printf("[*] Buffer freed\n");

    close(client_fd);
}

int main(void)
{
    int server_fd, client_fd;
    struct sockaddr_in addr;
    int opt = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(LISTEN_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    listen(server_fd, 1);
    printf("[*] Listening on 127.0.0.1:%d\n", LISTEN_PORT);

    client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        return 1;
    }

    printf("[*] Client connected\n");
    handle_client(client_fd);

    close(server_fd);
    return 0;
}
```

### Attack Packet

```python
#!/usr/bin/env python3
"""
Send a crafted packet that triggers the confused-length heap overflow.
The packet allocates 16 bytes but copies 128 bytes, overflowing 112 bytes
past the end of the buffer into adjacent heap objects/metadata.
"""
import socket
import struct

HOST = '127.0.0.1'
PORT = 9122

MAGIC_0   = 0xDC
MAGIC_1   = 0x3C
ALLOC_LEN = 16       # Server will malloc(16)
COPY_LEN  = 128      # Server will read(fd, buf, 128) -- 112 bytes overflow

# Build the 4-byte header.
header = bytes([MAGIC_0, MAGIC_1, ALLOC_LEN, COPY_LEN])

# Build the payload: 128 bytes of 0x41 ('A').
# In a real exploit, bytes 17-128 would contain crafted heap metadata
# or a fake vtable pointer. Here we use a recognizable pattern.
payload = b'A' * COPY_LEN

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
sock.sendall(header + payload)

# Read any response (server may print diagnostics before crashing).
try:
    resp = sock.recv(4096)
    if resp:
        print(f"Response: {resp}")
except Exception:
    pass

sock.close()
print(f"[*] Sent: alloc_len={ALLOC_LEN}, copy_len={COPY_LEN}, payload={COPY_LEN} bytes")
print(f"[*] Overflow: {COPY_LEN - ALLOC_LEN} bytes past end of buffer")
```

Equivalent raw packet bytes (hex):

```
DC 3C 10 80 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41
41 41 41 41
```

Byte breakdown:
- `DC 3C` -- magic bytes
- `10` -- `alloc_len` = 16
- `80` -- `copy_len` = 128
- `41 * 128` -- payload (0x41 = 'A')

### Expected Behavior: Stock glibc

| Phase | Observed behavior |
|---|---|
| `malloc(16)` | Returns a 16-byte heap chunk. Adjacent chunk metadata sits at offset +16 to +32 (depending on glibc's malloc implementation). |
| `read(fd, buf, 128)` | Writes 128 bytes starting at `buf`. Bytes 17-128 overwrite: the trailing chunk size field, the next chunk's `prev_size`/`size`/`fd`/`bk` fields, and potentially user data in adjacent allocations. |
| `free(buf)` | glibc's `free()` reads corrupted chunk metadata. Depending on the overwrite pattern, this can cause: (a) heap unlink exploit leading to arbitrary write, (b) crash in `__libc_free` due to metadata consistency checks, or (c) silent corruption leading to exploitable state later. |
| **Net result** | Heap corruption. With a crafted payload (not just 0x41), an attacker achieves arbitrary write and then code execution. |

### Expected Behavior: glibc_rust with TSM

| TSM component | Action |
|---|---|
| **Trailing canary** | The 8-byte canary placed at `buf + 16` by `AllocationFingerprint::canary()` is overwritten by the overflow (bytes 17-24 of the payload obliterate the canary). At `free()` time, `AllocationArena::verify_canary_for_slot()` computes the expected canary from the SipHash and compares it against the corrupted bytes. Mismatch is detected. The free returns `FreeResult::FreedWithCanaryCorruption`. |
| **ClampSize** | If the TSM intercepts the `read()` call and knows the destination pointer is membrane-managed, `HealingPolicy::heal_copy_bounds()` computes `remaining_from(buf)` = 16 bytes. The requested `copy_len` of 128 is clamped to 16. Only 16 bytes are read; no overflow occurs. |
| **Bounds computation** | `ValidationPipeline::remaining_from()` performs the arena lookup, finds `user_size = 16`, and returns `remaining = 16`. This feeds into the ClampSize decision. |
| **Quarantine** | Even if the overflow occurs before clamping (e.g., the `read` syscall completes before membrane interception), the quarantine queue prevents the freed buffer from being immediately reallocated, limiting exploit windows for heap feng shui attacks. |
| **Metrics** | `size_clamps` counter increments; if canary corruption is detected, the event is recorded through `spectral_monitor`. |

### Primary Healing Actions

1. **`ClampSize`** fires proactively: `heal_copy_bounds(128, None, Some(16))` returns `ClampSize { requested: 128, clamped: 16 }`. The copy is truncated to the allocation's actual size.
2. **Canary detection** fires reactively at `free()` time if the overflow was not prevented: `verify_canary_for_slot()` detects the corrupted trailing canary and returns `FreedWithCanaryCorruption`, triggering incident logging.

---

## Pattern 3: Event-Driven Use-After-Free (QUIC Connection Lifecycle)

### CVE Reference

| Field | Value |
|---|---|
| **CVE** | CVE-2024-24990 |
| **Vendor** | F5 / nginx |
| **Product** | nginx (QUIC/HTTP3 module) |
| **CVSS** | 7.5 (High) |
| **CWE** | CWE-416: Use After Free |
| **Discovered** | 2024 |
| **Impact** | Denial of service, potential code execution |

### Why We Cannot Use the Proprietary Code

While nginx is open-source, the QUIC module in affected versions
(nginx 1.25.0-1.25.3) relies on a complex event-driven architecture with
internal connection pools, stream multiplexing, and callback chains that span
thousands of lines of tightly coupled code. Extracting the minimal reproducer
from the nginx source would create a derivative work that inherits the
2-clause BSD license obligations and would be tightly coupled to nginx
internals. More importantly, we need a self-contained test case under 200
lines that reproduces the *exact CWE-416 pattern* (callback accesses freed
parent object) without any dependency on the nginx codebase, its build system,
or its runtime. The synthetic version distills the bug class to its essence.

### Memory Corruption Pattern Being Reproduced

In the nginx QUIC implementation, a connection object is heap-allocated and
contains a function pointer (callback) plus associated data. Stream objects
hold a pointer back to their parent connection. When a QUIC connection
experiences an error, the connection object is freed. However, a stream
cleanup handler registered earlier still holds a reference to the freed
connection. When the cleanup handler runs, it dereferences the stale
pointer -- a use-after-free.

The synthetic program reproduces this exact lifecycle:
1. Allocate a `connection` struct on the heap (contains callback + data).
2. Allocate a `stream` struct that holds a pointer to the connection.
3. Free the connection (simulating connection error/close).
4. The stream cleanup callback dereferences the freed connection pointer.

With stock glibc, the freed memory may have been reused for a different
allocation, so the callback pointer may now point to attacker-controlled data.

### Synthetic Trigger Program

```c
/*
 * synthetic_quic_uaf.c
 *
 * Reproduces CWE-416 (use-after-free) in the same event-driven callback
 * pattern as CVE-2024-24990. A "connection" object is freed while a
 * "stream" cleanup handler still holds a reference to it.
 *
 * Compile:
 *   gcc -Wall -Wextra -o synthetic_quic_uaf synthetic_quic_uaf.c
 *
 * WARNING: This program is intentionally vulnerable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/*
 * Simulated connection structure. In a real server, this would contain
 * TLS state, socket descriptors, QUIC protocol state, etc. For our
 * purposes, the critical fields are:
 *   - on_close: a function pointer (callback)
 *   - conn_id:  identifying data
 *   - secret:   sensitive data that should not leak
 */
typedef struct connection {
    void (*on_close)(struct connection *conn);
    uint64_t conn_id;
    char     secret[32];
    uint64_t canary_value;  /* we set this to a known value for detection */
} connection_t;

/*
 * Simulated stream structure. Holds a pointer back to its parent
 * connection. In nginx, QUIC streams are multiplexed over a single
 * connection and each stream has a cleanup handler that runs when
 * the stream is torn down.
 */
typedef struct stream {
    connection_t *conn;         /* back-pointer to parent -- becomes dangling */
    uint32_t      stream_id;
    void        (*cleanup)(struct stream *s);
} stream_t;

/* Callback that runs when a connection closes normally. */
static void connection_on_close(connection_t *conn)
{
    printf("  [connection] on_close: conn_id=0x%lx\n", (unsigned long)conn->conn_id);
}

/*
 * Stream cleanup handler. This is the VULNERABLE code path.
 *
 * In the real CVE, this handler runs after the connection has been freed.
 * It dereferences conn->on_close (a function pointer in freed memory)
 * and calls it. If the freed memory has been reallocated and overwritten,
 * this call goes to an attacker-controlled address.
 */
static void stream_cleanup(stream_t *s)
{
    printf("  [stream %u] cleanup: accessing conn at %p\n",
           s->stream_id, (void *)s->conn);

    /*
     * THE VULNERABILITY: s->conn points to freed memory.
     *
     * Reading conn->canary_value: if it has changed from the known
     * value, we are reading garbage (or attacker-controlled data).
     *
     * Calling conn->on_close: the function pointer may now point to
     * arbitrary code if the freed memory was reallocated.
     */
    if (s->conn->canary_value != 0xDEAD1234CAFE5678ULL) {
        printf("  [stream %u] WARNING: canary mismatch! UAF detected.\n",
               s->stream_id);
        printf("  [stream %u] canary_value = 0x%lx (expected 0xDEAD1234CAFE5678)\n",
               s->stream_id, (unsigned long)s->conn->canary_value);
    }

    /* Call the function pointer from freed memory -- the dangerous part. */
    printf("  [stream %u] calling conn->on_close (function pointer at %p)...\n",
           s->stream_id, (void *)(uintptr_t)s->conn->on_close);

    if (s->conn->on_close) {
        s->conn->on_close(s->conn);  /* UAF: calling through freed pointer */
    }
}

/*
 * Simulated "attacker" allocation that reuses the freed connection memory.
 * In a real exploit, the attacker would send data that causes the server
 * to allocate an object of the same size as connection_t, filling the freed
 * slot with attacker-controlled bytes (including a fake function pointer).
 */
static void spray_heap_with_attacker_data(size_t target_size)
{
    printf("\n[*] Spraying heap with attacker data (size=%zu)...\n", target_size);

    /*
     * Allocate several objects of the same size to increase the chance
     * of reusing the exact freed slot.
     */
    for (int i = 0; i < 8; i++) {
        char *block = (char *)malloc(target_size);
        if (block) {
            /*
             * Fill with attacker-controlled pattern. The bytes at the
             * offset of on_close (offset 0) would be a function pointer
             * in a real exploit. Here we use 0x4141414141414141 which
             * will cause a visible crash if called as a function.
             */
            memset(block, 0x41, target_size);
            /* Do NOT free -- we want this to occupy the slot. */
        }
    }
}

int main(void)
{
    printf("=== Synthetic QUIC UAF (CVE-2024-24990 pattern) ===\n\n");

    /* Step 1: Allocate and initialize the connection. */
    printf("[*] Step 1: Allocating connection\n");
    connection_t *conn = (connection_t *)malloc(sizeof(connection_t));
    if (!conn) {
        perror("malloc");
        return 1;
    }

    conn->on_close     = connection_on_close;
    conn->conn_id      = 0x0001AABBCCDD0001ULL;
    conn->canary_value = 0xDEAD1234CAFE5678ULL;
    snprintf(conn->secret, sizeof(conn->secret), "SECRET-KEY-12345");

    printf("  connection at %p, on_close=%p\n",
           (void *)conn, (void *)(uintptr_t)conn->on_close);

    /* Step 2: Allocate and initialize the stream (holds back-pointer). */
    printf("[*] Step 2: Allocating stream (back-pointer to connection)\n");
    stream_t *stream = (stream_t *)malloc(sizeof(stream_t));
    if (!stream) {
        perror("malloc");
        free(conn);
        return 1;
    }

    stream->conn      = conn;       /* This pointer will become dangling. */
    stream->stream_id = 1;
    stream->cleanup   = stream_cleanup;

    printf("  stream at %p, stream->conn=%p\n",
           (void *)stream, (void *)stream->conn);

    /* Step 3: Free the connection (simulating connection close/error). */
    printf("[*] Step 3: Freeing connection (simulating QUIC connection error)\n");
    free(conn);
    conn = NULL;  /* The local variable is nulled, but stream->conn is NOT. */

    /*
     * At this point, stream->conn is a dangling pointer. The freed memory
     * is in the free list (stock glibc) or quarantine (glibc_rust).
     */

    /* Step 3b: Simulate attacker reusing the freed memory. */
    spray_heap_with_attacker_data(sizeof(connection_t));

    /* Step 4: Stream cleanup runs -- dereferences freed connection. */
    printf("\n[*] Step 4: Running stream cleanup (THE UAF)\n");
    stream->cleanup(stream);

    /*
     * If we reach here without crashing, the UAF was "silent" --
     * the most dangerous case, as it means attacker data was read
     * without any obvious failure signal.
     */
    printf("\n[*] Process survived (silent UAF -- worst case for security)\n");

    free(stream);
    return 0;
}
```

### Driver Script

```bash
#!/bin/bash
# driver_quic_uaf.sh
#
# Build and run the synthetic QUIC UAF trigger. Compare behavior with
# stock glibc vs glibc_rust.

set -euo pipefail

SRC="synthetic_quic_uaf.c"
BIN="synthetic_quic_uaf"

echo "=== Building ==="
gcc -Wall -Wextra -g -O0 -o "$BIN" "$SRC"

echo "=== Running with stock glibc ==="
# Under stock glibc, the process will either:
#   (a) crash with SIGSEGV if the freed memory was reused and the function
#       pointer now points to an invalid address, or
#   (b) succeed silently if the freed memory was not yet reused, or
#   (c) call attacker-controlled code if heap spray succeeded.
./"$BIN" || echo "[!] Process crashed (exit code $?)"

echo ""
echo "=== Running with glibc_rust (LD_PRELOAD) ==="
# Under glibc_rust, the TSM's generational arena detects the UAF:
#   - stream->conn points to a quarantined allocation
#   - generation mismatch prevents the dereference
#   - process continues safely (IgnoreDoubleFree / ReturnSafeDefault)
# LD_PRELOAD=libglibc_rust.so ./"$BIN"
echo "(Set LD_PRELOAD=libglibc_rust.so to test with TSM)"
```

### Expected Behavior: Stock glibc

| Phase | Observed behavior |
|---|---|
| `free(conn)` | Connection memory is returned to glibc's free list. The `fd`/`bk` pointers in the chunk header are updated. The user data region (including the function pointer at offset 0) may be partially overwritten with free-list metadata. |
| `spray_heap_with_attacker_data()` | The 8 `malloc(sizeof(connection_t))` calls may reuse the exact same memory slot. The freed connection's memory is now filled with `0x41` bytes. The `on_close` function pointer (first 8 bytes) is now `0x4141414141414141`. |
| `stream->cleanup(stream)` | The cleanup handler reads `s->conn->on_close` from the reallocated (attacker-controlled) memory. If the spray succeeded, `on_close` = `0x4141414141414141`. Calling this address causes SIGSEGV (or, with a real exploit payload, jumps to attacker shellcode). |
| **Net result** | Use-after-free leading to control-flow hijack. The attacker controls the function pointer called through the stale reference. |

### Expected Behavior: glibc_rust with TSM

| TSM component | Action |
|---|---|
| **Generational arena** | When `free(conn)` is called, the `AllocationArena` moves the connection's slot to `SafetyState::Quarantined` and bumps its generation counter via `next_generation.fetch_add(1)`. The memory is NOT returned to the system allocator; it sits in the quarantine queue (`VecDeque<QuarantineEntry>`). |
| **Quarantine** | The quarantine queue (up to 64 MB / 65536 entries) holds the freed connection memory. Subsequent `malloc()` calls from `spray_heap_with_attacker_data()` do NOT receive this slot. The attacker's heap spray fails to overlap the freed connection. |
| **Generation mismatch detection** | When `stream->cleanup()` dereferences `s->conn`, the TSM's validation pipeline (`validate()` in `ptr_validator.rs`) checks the pointer. The arena lookup succeeds (the slot exists), but `slot.state == SafetyState::Quarantined`, which is not live. The pipeline returns `ValidationOutcome::TemporalViolation`. |
| **TLS cache invalidation** | At `free(conn)` time, `bump_tls_cache_epoch()` is called (see `arena.rs` line 202). This ensures that any thread-local cached validation for the connection's address is invalidated. A stale `CachedValid` result cannot be returned for the freed pointer. |
| **ReturnSafeDefault** | The healing engine interprets the temporal violation and returns a safe default: the function pointer dereference is suppressed, and the callback is not invoked. The process continues without the UAF. |
| **Allocation fingerprint** | If the attacker somehow bypasses quarantine and overwrites the memory, the `AllocationFingerprint::verify()` check at the validation stage will fail. The SipHash of the (address, size, generation) triple will not match the corrupted header bytes, providing a secondary detection layer. |
| **Metrics** | `safe_defaults` counter increments. The temporal violation is recorded for monitoring. |

### Primary Healing Actions

1. **Generational arena quarantine** prevents the root cause: freed memory is not reused, so the attacker's heap spray cannot overlap the freed connection. The function pointer is never overwritten.
2. **`ReturnSafeDefault`** fires when the validation pipeline detects `TemporalViolation` on the stale connection pointer. The callback invocation is suppressed.
3. **TLS cache epoch bump** at `tls_cache::bump_tls_cache_epoch()` ensures cross-thread consistency: no thread can use a stale cached validation result for the freed connection.

---

## Summary of TSM Coverage

| Pattern | CVE | CWE | Primary Healing Action | Detection Layer |
|---|---|---|---|---|
| 1: Format String | CVE-2024-23113 | CWE-134 | `UpgradeToSafeVariant` | Format-string specifier analysis at ABI interposition |
| 2: Heap Overflow | CVE-2024-38812 | CWE-122 | `ClampSize` + canary detection | `heal_copy_bounds()` + `verify_canary_for_slot()` |
| 3: Use-After-Free | CVE-2024-24990 | CWE-416 | `ReturnSafeDefault` + quarantine | Generational arena + `TemporalViolation` + TLS epoch |

### Compilation Notes

All three synthetic programs are standard C99 and compile with:

```bash
gcc -std=c99 -Wall -Wextra -pedantic -g -O0 -o <binary> <source>.c
```

The `-O0 -g` flags are recommended for clear debugging and to prevent the
compiler from optimizing away the vulnerable code paths. The `-pedantic` flag
ensures strict standard conformance.

### Testing Protocol

1. **Baseline run**: Compile and run against stock glibc. Document the crash
   mode, ASAN output (if applicable), and any observable corruption.
2. **TSM run**: Compile the same source and run under glibc_rust (via
   `LD_PRELOAD` or full system library replacement). Verify that:
   - No crash occurs.
   - The healing action fires (check `HealingPolicy` counters).
   - The vulnerability is neutralized (no information leak, no heap
     corruption, no use-after-free).
3. **Regression**: Add each pattern as a test case in the CVE Arena CI suite
   to prevent future regressions in TSM coverage.
