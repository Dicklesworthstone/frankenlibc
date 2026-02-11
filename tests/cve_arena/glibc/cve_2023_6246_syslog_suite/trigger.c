/* CVE-2023-6246 + CVE-2023-6779 + CVE-2023-6780: syslog heap overflow suite
 *
 * Three related vulnerabilities in glibc's __vsyslog_internal(), all
 * involving heap buffer overflow via crafted syslog messages.
 *
 * All three share a common root cause: the internal buffer size calculation
 * in __vsyslog_internal() does not correctly account for the combined
 * length of the ident string, PID, and formatted message. This leads to
 * heap buffer overflows of varying severity.
 *
 * Stock glibc behavior: heap corruption, potential local privilege escalation
 * glibc_rust TSM behavior: canary detection, ClampSize, TruncateWithNull
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Maximum ident length that syslog typically handles */
#define SYSLOG_INTERNAL_BUF_SIZE  1024

/* ===================================================================
 * CVE-2023-6246: Heap buffer overflow via crafted ident string
 * CVSS 8.4 (High) — CWE-787: Out-of-bounds Write
 *
 * Root cause: __vsyslog_internal() computes the required buffer size
 * as: (ident_len + message_len + overhead). However, when openlog()
 * is called with a very long ident string and syslog() is later called
 * with a format string that causes expansion (e.g., %s with a long
 * argument), the actual write exceeds the computed size.
 *
 * The specific bug: the code uses strlen(ident) to compute the buffer,
 * but the formatted output can exceed this because the PID field
 * ("[%d]: ") is not included in the initial size calculation.
 *
 * Exploitation: Qualys demonstrated local root on Fedora 37/38, Ubuntu
 * 22.04/23.04, and Debian 12/13 via su/sudo triggering the overflow.
 * =================================================================== */
static int test_cve_2023_6246(void)
{
    printf("[CVE-2023-6246] Testing heap overflow via crafted ident...\n");

    /* Step 1: Simulate the internal buffer allocation.
     * __vsyslog_internal() allocates based on an UNDERESTIMATED size. */
    size_t alloc_size = SYSLOG_INTERNAL_BUF_SIZE;
    char *internal_buf = (char *)malloc(alloc_size);
    if (!internal_buf) {
        fprintf(stderr, "  ERROR: malloc(%zu) failed\n", alloc_size);
        return 2;
    }
    memset(internal_buf, 0, alloc_size);

    /* Step 2: Construct the ident string.
     * A long ident (say 900 bytes) combined with the PID field and
     * a modest message exceeds the 1024-byte internal buffer. */
    size_t ident_len = 900;
    char *ident = (char *)malloc(ident_len + 1);
    if (!ident) {
        fprintf(stderr, "  ERROR: ident allocation failed\n");
        free(internal_buf);
        return 2;
    }
    memset(ident, 'A', ident_len);
    ident[ident_len] = '\0';

    /* Step 3: Format the syslog message into internal_buf.
     * The real code does: snprintf(buf, bufsize, "<%d>%s%s[%d]: %s", ...)
     * With ident=900 bytes, "[12345]: "=10 bytes, priority header=5 bytes,
     * and message=200 bytes: total = 900+10+5+200 = 1115 > 1024 */
    const char *pid_field = "[12345]: ";
    const char *priority_hdr = "<13>";
    const char *message = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; /* 200 chars */

    size_t total_needed = strlen(priority_hdr) + ident_len +
                          strlen(pid_field) + strlen(message) + 1;
    printf("  Buffer: %zu bytes, needed: %zu bytes, overflow: %zu bytes\n",
           alloc_size, total_needed, total_needed - alloc_size);

    /* Step 4: Perform the overflow write.
     * This simulates what __vsyslog_internal() does internally. */
    size_t offset = 0;

    /* Write priority header */
    memcpy(internal_buf + offset, priority_hdr, strlen(priority_hdr));
    offset += strlen(priority_hdr);

    /* Write ident */
    memcpy(internal_buf + offset, ident, ident_len);
    offset += ident_len;

    /* Write PID field — this is what the size calculation MISSED */
    memcpy(internal_buf + offset, pid_field, strlen(pid_field));
    offset += strlen(pid_field);

    /* Write message — this overflows the buffer */
    memcpy(internal_buf + offset, message, strlen(message));
    offset += strlen(message);

    printf("  Wrote %zu bytes into %zu-byte buffer (overflow: %zu)\n",
           offset, alloc_size, offset > alloc_size ? offset - alloc_size : 0);

    /* Step 5: Free the buffer. Canary check detects corruption. */
    printf("  Freeing buffer (canary check)...\n");
    free(internal_buf);
    free(ident);

    printf("  EXPLOITABLE: heap overflow not detected!\n");
    return 1;
}

/* ===================================================================
 * CVE-2023-6779: Off-by-one in __vsyslog_internal buffer calculation
 * CVSS 8.4 (High) — CWE-131: Incorrect Calculation of Buffer Size
 *
 * Root cause: When the initial buffer is too small, __vsyslog_internal()
 * reallocates. The reallocation size calculation has an off-by-one error
 * in the handling of the trailing newline character: it computes
 * (needed_size) but the format adds a '\n' that requires (needed_size+1).
 *
 * This means the reallocated buffer is exactly 1 byte too small.
 * The subsequent write of '\n' at the end corrupts the first byte
 * past the allocation.
 * =================================================================== */
static int test_cve_2023_6779(void)
{
    printf("[CVE-2023-6779] Testing off-by-one in buffer reallocation...\n");

    /* Simulate the "just right" allocation that's 1 byte too small.
     * __vsyslog_internal() computes the message length but forgets
     * the trailing '\n'. */
    size_t message_len = 256;
    size_t computed_size = message_len;  /* BUG: should be message_len + 1 */

    char *buf = (char *)malloc(computed_size);
    if (!buf) {
        fprintf(stderr, "  ERROR: malloc(%zu) failed\n", computed_size);
        return 2;
    }
    memset(buf, 0, computed_size);

    printf("  Allocated %zu bytes for %zu-byte message + newline\n",
           computed_size, message_len);

    /* Write the message (fills the buffer exactly) */
    memset(buf, 'M', message_len);

    /* Write the trailing newline — OFF-BY-ONE overflow.
     * buf[message_len] is 1 byte past the allocation.
     * This single byte can corrupt heap metadata (tcache next pointer
     * or chunk size field), leading to arbitrary write. */
    buf[computed_size] = '\n';  /* Off-by-one: writes at buf[256] */

    printf("  Wrote newline at offset %zu (1 byte past %zu-byte buffer)\n",
           computed_size, computed_size);

    /* Free — canary detects the 1-byte overflow */
    printf("  Freeing buffer (canary check)...\n");
    free(buf);

    printf("  EXPLOITABLE: off-by-one heap overflow not detected!\n");
    return 1;
}

/* ===================================================================
 * CVE-2023-6780: Integer overflow in __vsyslog_internal size calculation
 * CVSS 5.3 (Medium) — CWE-190: Integer Overflow or Wraparound
 *
 * Root cause: When computing the buffer size for a very long message,
 * the addition of (ident_len + msg_len + overhead) can overflow a
 * 32-bit integer (or a size_t on 32-bit systems). The result wraps
 * around to a small value, causing a small allocation followed by
 * a large write.
 *
 * On 64-bit systems: The overflow in the 32-bit intermediate value
 * used in the calculation can still produce an incorrect (too small)
 * allocation size.
 * =================================================================== */
static int test_cve_2023_6780(void)
{
    printf("[CVE-2023-6780] Testing integer overflow in size calculation...\n");

    /* Simulate the integer overflow in the size computation.
     * On the real bug, the calculation is approximately:
     *   int needed = ident_len + msg_len + sizeof(priority_header);
     * Using 'int' means values > INT_MAX wrap around.
     *
     * We simulate with smaller values for practical reproduction. */

    /* Use values that demonstrate the wrapping concept.
     * Real CVE uses sizes near INT_MAX; we use sizes that show
     * the same pattern: computed < actual. */
    unsigned int ident_len_u32 = 2000000000u;  /* ~2 billion */
    unsigned int msg_len_u32   = 2000000000u;  /* ~2 billion */
    unsigned int overhead_u32  = 300000000u;    /* ~300 million */

    /* Integer overflow: wraps around in 32-bit arithmetic */
    unsigned int computed_u32 = ident_len_u32 + msg_len_u32 + overhead_u32;
    printf("  32-bit size calculation: %u + %u + %u = %u (wrapped!)\n",
           ident_len_u32, msg_len_u32, overhead_u32, computed_u32);
    printf("  True size would be: %llu\n",
           (unsigned long long)ident_len_u32 + msg_len_u32 + overhead_u32);

    /* Simulate the effect: allocate the WRAPPED (small) size,
     * then write the ACTUAL (large) amount.
     * We cap the demo at practical sizes. */
    size_t wrapped_size = 64;    /* What the wrapped calculation gives */
    size_t actual_write = 128;   /* What the code actually writes */

    char *buf = (char *)malloc(wrapped_size);
    if (!buf) {
        fprintf(stderr, "  ERROR: malloc(%zu) failed\n", wrapped_size);
        return 2;
    }
    memset(buf, 0, wrapped_size);

    printf("  Allocated %zu bytes (wrapped), writing %zu bytes (actual)\n",
           wrapped_size, actual_write);

    /* The write overflows by (actual_write - wrapped_size) = 64 bytes */
    memset(buf, 'X', actual_write);

    printf("  Overflow: %zu bytes past end of %zu-byte buffer\n",
           actual_write - wrapped_size, wrapped_size);

    /* Free — canary detects the massive overflow */
    printf("  Freeing buffer (canary check)...\n");
    free(buf);

    printf("  EXPLOITABLE: integer overflow led to undetected heap "
           "corruption!\n");
    return 1;
}

int main(void)
{
    int result = 0;

    printf("=== Syslog Heap Overflow Suite ===\n");
    printf("Three related vulnerabilities in __vsyslog_internal()\n");
    printf("TSM defenses: trailing canary, ClampSize, TruncateWithNull, "
           "bounds computation\n\n");

    printf("--- Test 1/3 ---\n");
    result |= test_cve_2023_6246();
    printf("\n");

    printf("--- Test 2/3 ---\n");
    result |= test_cve_2023_6779();
    printf("\n");

    printf("--- Test 3/3 ---\n");
    result |= test_cve_2023_6780();

    printf("\n=== Summary ===\n");
    if (result == 0) {
        printf("All syslog overflows were DETECTED — TSM protection active.\n");
    } else {
        printf("VULNERABLE: syslog heap overflow(s) completed without "
               "detection.\n");
    }

    return result;
}
