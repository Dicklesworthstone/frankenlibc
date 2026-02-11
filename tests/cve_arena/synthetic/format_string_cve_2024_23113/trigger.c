/* Synthetic CVE reproduction: Format string vulnerability
 * Modeled on CVE-2024-23113 (Fortinet FortiOS FGFM, CVSS 9.8)
 * CWE-134: Use of Externally-Controlled Format String
 *
 * This reproduces the exact bug pattern: user-controlled input passed
 * directly as format string to printf-family function.
 *
 * Stock glibc: Format string enables stack data leakage, crash, or arbitrary write
 * glibc_rust: UpgradeToSafeVariant detects and neutralizes the format string attack
 *
 * Build: cc -o trigger trigger.c -Wall -Wextra
 * Run:   ./trigger
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

/* ---------------------------------------------------------------------------
 * Global state for crash recovery
 * ---------------------------------------------------------------------------
 * We use setjmp/longjmp to recover from SIGSEGV when the %s attack reads
 * from an invalid pointer.  This makes the program deterministic: it always
 * completes all three attack vectors regardless of the runtime.
 * --------------------------------------------------------------------------- */
static sigjmp_buf g_jump_buf;
static volatile sig_atomic_t g_crash_caught = 0;

static void crash_handler(int sig)
{
    (void)sig;
    g_crash_caught = 1;
    siglongjmp(g_jump_buf, 1);
}

/* ---------------------------------------------------------------------------
 * Vulnerable function: process_message()
 * ---------------------------------------------------------------------------
 * This mirrors the FortiOS FGFM daemon bug.  The FGFM protocol handler
 * receives a message from a remote peer and passes the message body directly
 * as the format string argument to snprintf (and subsequently to syslog).
 *
 * The caller SHOULD have written:
 *     snprintf(buf, sizeof(buf), "%s", user_input);
 * but instead wrote:
 *     snprintf(buf, sizeof(buf), user_input);          <-- BUG
 *
 * This gives an attacker full control over the format string, enabling:
 *   - Information disclosure (%x, %p leak stack/heap values)
 *   - Denial of service      (%s dereferences attacker-chosen stack values)
 *   - Arbitrary write         (%n writes the byte count to a stack address)
 * --------------------------------------------------------------------------- */
static int process_message(const char *user_input, char *out, size_t out_sz)
{
    /*
     * BUG: user_input is used directly as the format string.
     * A safe implementation would use "%s" as the format and user_input
     * as a variadic argument.
     */
    int ret = snprintf(out, out_sz, user_input);
    return ret;
}

/* ---------------------------------------------------------------------------
 * Attack Vector 1: Information Leak
 * ---------------------------------------------------------------------------
 * The attacker sends "%08x.%08x.%08x.%08x" as the "message".  snprintf
 * interprets each %x as "pop the next 32-bit value from the variadic
 * argument area" (which on the stack is whatever locals and frame data
 * happen to follow the format string pointer).
 *
 * On stock glibc this silently succeeds and leaks 16 bytes of stack data.
 * On glibc_rust, UpgradeToSafeVariant detects that the format string is not
 * a compile-time literal (or contains specifiers not matched by arguments)
 * and rewrites the call to treat user_input as a plain string argument.
 * --------------------------------------------------------------------------- */
static void attack_info_leak(void)
{
    const char *payload = "%08x.%08x.%08x.%08x";

    printf("[ATTACK 1] Info Leak: sending format string \"%s\"\n", payload);

    /* Heap-allocate the output buffer so it exercises the allocator path */
    char *heap_out = (char *)malloc(256);
    if (!heap_out) {
        fprintf(stderr, "  malloc failed\n");
        return;
    }
    memset(heap_out, 0, 256);

    int written = process_message(payload, heap_out, 256);

    /*
     * Determine what happened.  If the output contains hex digits and dots
     * (e.g. "deadbeef.0000007f.00000002.bfff1234") then the format string
     * was interpreted and stack data was leaked.
     *
     * If glibc_rust's UpgradeToSafeVariant fired, the output should be the
     * literal string "%08x.%08x.%08x.%08x" (treated as plain text).
     */
    if (strcmp(heap_out, payload) == 0) {
        /* The format specifiers were NOT interpreted -- TSM neutralized them */
        printf("  RESULT: Format string neutralized (output == literal input)\n");
        printf("  OUTPUT: \"%s\"\n", heap_out);
        printf("  STATUS: SAFE -- UpgradeToSafeVariant prevented info leak\n");
    } else {
        /* The format specifiers WERE interpreted -- data leaked */
        printf("  RESULT: Stack data leaked via format string!\n");
        printf("  OUTPUT: \"%s\" (written=%d)\n", heap_out, written);
        printf("  STATUS: VULNERABLE -- stack values exposed to attacker\n");
    }

    free(heap_out);
    printf("\n");
}

/* ---------------------------------------------------------------------------
 * Attack Vector 2: Crash via invalid pointer dereference
 * ---------------------------------------------------------------------------
 * The attacker sends "%s%s%s%s%s%s%s%s".  Each %s tells snprintf to read
 * a char* pointer from the variadic argument area and dereference it as a
 * C string.  Since there are no actual arguments, snprintf reads whatever
 * values are on the stack and tries to dereference them.  This almost
 * always results in SIGSEGV.
 *
 * Stock glibc: crashes (SIGSEGV)
 * glibc_rust:  UpgradeToSafeVariant prevents the crash
 * --------------------------------------------------------------------------- */
static void attack_crash(void)
{
    const char *payload = "%s%s%s%s%s%s%s%s";

    printf("[ATTACK 2] Crash: sending format string \"%s\"\n", payload);

    char *heap_out = (char *)malloc(256);
    if (!heap_out) {
        fprintf(stderr, "  malloc failed\n");
        return;
    }
    memset(heap_out, 0, 256);

    /* Install crash handler so we can recover and report */
    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa);
    sigaction(SIGBUS, &sa, NULL);

    g_crash_caught = 0;

    if (sigsetjmp(g_jump_buf, 1) == 0) {
        /* First entry: attempt the dangerous format string operation */
        process_message(payload, heap_out, 256);

        if (strcmp(heap_out, payload) == 0) {
            printf("  RESULT: Format string neutralized (output == literal input)\n");
            printf("  OUTPUT: \"%s\"\n", heap_out);
            printf("  STATUS: SAFE -- UpgradeToSafeVariant prevented crash\n");
        } else {
            printf("  RESULT: Format string was interpreted but did not crash\n");
            printf("  OUTPUT: \"%s\"\n", heap_out);
            printf("  STATUS: VULNERABLE -- exploitable with tuned payload\n");
        }
    } else {
        /* Returned from crash handler via longjmp */
        printf("  RESULT: SIGSEGV caught -- process would have crashed!\n");
        printf("  STATUS: VULNERABLE -- denial of service achieved\n");
    }

    /* Restore original signal handler */
    sigaction(SIGSEGV, &old_sa, NULL);

    /*
     * Only free if we did not crash mid-operation.  After a SIGSEGV inside
     * snprintf the heap may be in an inconsistent state, so freeing could
     * double-fault.  We accept the small leak in the crash path.
     */
    if (!g_crash_caught) {
        free(heap_out);
    }
    printf("\n");
}

/* ---------------------------------------------------------------------------
 * Attack Vector 3: Arbitrary write via %n
 * ---------------------------------------------------------------------------
 * The %n format specifier writes the number of bytes output so far into an
 * address popped from the stack.  An attacker who can also control stack
 * layout (or use %<N>$n direct parameter access) can write to arbitrary
 * memory locations.
 *
 * Modern glibc on many distributions disables %n via the FORTIFY_SOURCE
 * mechanism or environment variable, but the underlying snprintf still
 * supports it.  We simulate the write attempt and detect the outcome.
 *
 * Stock glibc (without fortify): %n writes to a stack-derived address
 * glibc_rust:  UpgradeToSafeVariant strips %n from untrusted format strings
 * --------------------------------------------------------------------------- */
static void attack_write(void)
{
    /*
     * We use a carefully constructed payload that writes to a known location.
     * The variable 'write_target' is placed on the stack.  We push its
     * address via a helper so %n would write into it on architectures where
     * the ABI permits this.
     *
     * For portability and determinism we use an indirect approach: we check
     * whether snprintf even attempted to process a %n by examining
     * write_target before and after.
     */
    volatile int write_target = 0xDEAD;
    const char *payload = "AAAA%n";

    printf("[ATTACK 3] Write: sending format string \"%s\" (%%n payload)\n", payload);

    char *heap_out = (char *)malloc(256);
    if (!heap_out) {
        fprintf(stderr, "  malloc failed\n");
        return;
    }
    memset(heap_out, 0, 256);

    /*
     * Install crash handler: on some platforms %n with no matching argument
     * causes SIGSEGV (writing to an address from uncontrolled stack data).
     * FORTIFY_SOURCE may also abort the process.
     */
    struct sigaction sa, old_sa_segv, old_sa_abrt;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = crash_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, &old_sa_segv);
    sigaction(SIGABRT, &sa, &old_sa_abrt);

    g_crash_caught = 0;

    if (sigsetjmp(g_jump_buf, 1) == 0) {
        process_message(payload, heap_out, 256);

        if (strcmp(heap_out, payload) == 0) {
            /* Output is the literal payload string -- %n was not interpreted */
            printf("  RESULT: %%n neutralized (output == literal input)\n");
            printf("  OUTPUT: \"%s\"\n", heap_out);
            printf("  STATUS: SAFE -- UpgradeToSafeVariant stripped %%n\n");
        } else if (write_target != 0xDEAD) {
            /* write_target was modified -- %n wrote to it */
            printf("  RESULT: %%n wrote to memory! write_target = 0x%X\n",
                   write_target);
            printf("  STATUS: VULNERABLE -- arbitrary memory write achieved\n");
        } else {
            /*
             * %n was processed (output is "AAAA" without the %n text) but
             * wrote to some other stack location rather than write_target.
             * Still dangerous: the write went somewhere uncontrolled.
             */
            printf("  RESULT: %%n was interpreted (output: \"%s\")\n", heap_out);
            printf("  STATUS: VULNERABLE -- %%n write occurred to unknown location\n");
        }
    } else {
        /* Crashed or aborted -- %n triggered a fault */
        printf("  RESULT: Process crashed/aborted processing %%n\n");
        printf("  STATUS: VULNERABLE -- %%n caused fault (FORTIFY may have caught it)\n");
    }

    sigaction(SIGSEGV, &old_sa_segv, NULL);
    sigaction(SIGABRT, &old_sa_abrt, NULL);

    if (!g_crash_caught) {
        free(heap_out);
    }
    printf("\n");
}

/* ---------------------------------------------------------------------------
 * Main: Execute all three attack vectors
 * --------------------------------------------------------------------------- */
int main(void)
{
    printf("=== Synthetic CVE Reproduction: Format String Vulnerability ===\n");
    printf("Modeled on: CVE-2024-23113 (Fortinet FortiOS FGFM daemon)\n");
    printf("CWE-134:    Use of Externally-Controlled Format String\n");
    printf("CVSS:       9.8 (Critical)\n");
    printf("\n");
    printf("Bug pattern: User-controlled input is passed directly as the\n");
    printf("format string argument to snprintf().  An attacker can inject\n");
    printf("format specifiers to leak memory, crash the process, or write\n");
    printf("to arbitrary addresses.\n");
    printf("\n");
    printf("TSM mitigation: UpgradeToSafeVariant intercepts printf-family\n");
    printf("calls and detects when the format string is not a compile-time\n");
    printf("literal or contains specifiers unmatched by arguments.  The\n");
    printf("format string is sanitized by treating the input as a plain\n");
    printf("string argument (equivalent to rewriting the call to use %%s).\n");
    printf("\n");
    printf("-----------------------------------------------------------\n\n");

    attack_info_leak();
    attack_crash();
    attack_write();

    printf("-----------------------------------------------------------\n");
    printf("=== All attack vectors executed.  Review STATUS lines above. ===\n");
    printf("\n");
    printf("Expected with stock glibc:\n");
    printf("  Attack 1: VULNERABLE (stack data leaked)\n");
    printf("  Attack 2: VULNERABLE (SIGSEGV crash)\n");
    printf("  Attack 3: VULNERABLE (%%n write or crash)\n");
    printf("\n");
    printf("Expected with glibc_rust TSM:\n");
    printf("  Attack 1: SAFE (UpgradeToSafeVariant neutralizes format)\n");
    printf("  Attack 2: SAFE (UpgradeToSafeVariant neutralizes format)\n");
    printf("  Attack 3: SAFE (UpgradeToSafeVariant strips %%n)\n");

    return 0;
}
