/* CVE-2025-8058: regcomp() double-free on allocation failure reproduction
 *
 * CVSS Medium — CWE-415: Double Free
 *
 * Root cause: During regex compilation, regcomp() allocates internal buffers
 * for the compiled pattern representation (fastmap, translate tables, and
 * the pattern buffer itself). When a subsequent allocation fails (ENOMEM),
 * the error-cleanup path frees an internal buffer that was already freed
 * by an earlier cleanup step. The bug is in the interaction between
 * re_compile_internal() and re_compile_fastmap_iter() error handling:
 *
 *   1. re_compile_internal() allocates dfa->nodes.
 *   2. A sub-call allocates dfa->sb_char and fails.
 *   3. The error path frees dfa->nodes and returns REG_ESPACE.
 *   4. The caller's cleanup in regcomp() frees dfa->nodes AGAIN because
 *      it was not set to NULL after the first free.
 *
 * This reproduction simulates the exact double-free pattern:
 *   1. Allocate a buffer (simulating dfa->nodes).
 *   2. Free it (simulating the internal error-path cleanup).
 *   3. Free it again (simulating regcomp's outer cleanup).
 *
 * Stock glibc behavior:
 *   - glibc's malloc detects the double-free in most configurations and
 *     calls abort() with "free(): double free detected in tcache 2".
 *   - In older glibc or with tcache disabled, this causes heap corruption
 *     that can be exploited for arbitrary write.
 *
 * glibc_rust TSM behavior:
 *   - The generational arena detects that the pointer's generation has
 *     been incremented (it is in the quarantine queue).
 *   - IgnoreDoubleFree absorbs the second free: logged, not crashed.
 *   - The allocation fingerprint confirms the pointer was legitimately
 *     allocated by us, so it is safe to ignore.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Sizes chosen to match typical regcomp internal allocations */
#define DFA_NODES_SIZE    256   /* dfa->nodes array */
#define DFA_SB_CHAR_SIZE  128   /* dfa->sb_char bitmap */
#define FASTMAP_SIZE       64   /* fastmap table */

/*
 * test_basic_double_free: Minimal reproduction of the double-free.
 *
 * Returns 0 if the double-free was absorbed (TSM behavior).
 * Returns 1 if not reached (stock glibc aborts before returning).
 */
static int test_basic_double_free(void)
{
    printf("[CVE-2025-8058] Test 1: Basic double-free pattern...\n");

    /* Step 1: Allocate dfa->nodes.
     * In regcomp(), this is the first large allocation for the DFA
     * node array used during regex compilation. */
    void *dfa_nodes = malloc(DFA_NODES_SIZE);
    if (!dfa_nodes) {
        fprintf(stderr, "  ERROR: malloc(%d) failed\n", DFA_NODES_SIZE);
        return 2;
    }

    /* Initialize to a known pattern (regcomp zeroes the node array) */
    memset(dfa_nodes, 0, DFA_NODES_SIZE);

    printf("  Allocated dfa->nodes at %p (%d bytes)\n",
           dfa_nodes, DFA_NODES_SIZE);

    /* Step 2: Simulate the internal error path freeing dfa->nodes.
     * This happens in re_compile_internal() when a subsequent allocation
     * (e.g., dfa->sb_char) fails with ENOMEM. */
    printf("  Simulating internal error-path free (first free)...\n");
    free(dfa_nodes);

    /* BUG: The code does NOT set dfa->nodes = NULL after freeing.
     * This is the root cause — a missing NULL assignment. */
    /* dfa_nodes = NULL;  <-- This line is MISSING in the buggy code */

    /* Step 3: Simulate regcomp's outer cleanup path.
     * regcomp() calls regfree() on error, which frees dfa->nodes again
     * because it still holds the now-stale pointer. */
    printf("  Simulating regcomp outer cleanup (second free = DOUBLE FREE)...\n");
    free(dfa_nodes);

    /* If we reach here, the double-free was absorbed. */
    printf("  Double-free was absorbed — IgnoreDoubleFree active.\n");
    return 0;
}

/*
 * test_double_free_with_reuse: A more dangerous variant where another
 * allocation reuses the freed memory before the second free.
 *
 * This demonstrates why double-free is dangerous: the second free()
 * puts an in-use allocation back on the free list, enabling use-after-free
 * and arbitrary write via subsequent allocations.
 */
static int test_double_free_with_reuse(void)
{
    printf("[CVE-2025-8058] Test 2: Double-free with reuse (exploitation "
           "pattern)...\n");

    /* Allocate the buffer that will be double-freed */
    void *dfa_nodes = malloc(DFA_NODES_SIZE);
    if (!dfa_nodes) {
        fprintf(stderr, "  ERROR: malloc(%d) failed\n", DFA_NODES_SIZE);
        return 2;
    }
    memset(dfa_nodes, 'N', DFA_NODES_SIZE);  /* N for Nodes */

    printf("  Allocated dfa->nodes at %p\n", dfa_nodes);

    /* First free (internal error path) */
    printf("  First free (internal error path)...\n");
    free(dfa_nodes);

    /* Between the two frees, another allocation reuses the memory.
     * In a real exploit, the attacker controls this allocation's content.
     * With stock glibc's tcache, same-size allocations often return
     * the most recently freed chunk. */
    void *attacker_controlled = malloc(DFA_NODES_SIZE);
    printf("  Intervening allocation at %p (same size: %d)\n",
           attacker_controlled, DFA_NODES_SIZE);

    if (attacker_controlled) {
        /* Attacker writes controlled data */
        memset(attacker_controlled, 'X', DFA_NODES_SIZE);
    }

    /* Second free (regcomp outer cleanup) — this is the double-free.
     * With stock glibc: this frees attacker_controlled's memory,
     * putting it on the free list WHILE attacker_controlled still
     * references it. This enables use-after-free. */
    printf("  Second free (outer cleanup = DOUBLE FREE)...\n");
    free(dfa_nodes);

    /* If TSM is active, the second free is absorbed because dfa_nodes
     * is already in the quarantine queue. The intervening allocation
     * got a different slot with a different generation. */
    printf("  Double-free absorbed — no heap corruption.\n");

    free(attacker_controlled);
    return 0;
}

/*
 * test_double_free_fastmap: The secondary double-free path in regcomp
 * involving the fastmap allocation.
 */
static int test_double_free_fastmap(void)
{
    printf("[CVE-2025-8058] Test 3: Fastmap double-free variant...\n");

    /* Simulate the compiled regex structure */
    struct {
        void *nodes;
        void *sb_char;
        void *fastmap;
    } dfa;

    dfa.nodes = malloc(DFA_NODES_SIZE);
    dfa.sb_char = malloc(DFA_SB_CHAR_SIZE);
    dfa.fastmap = malloc(FASTMAP_SIZE);

    if (!dfa.nodes || !dfa.sb_char || !dfa.fastmap) {
        fprintf(stderr, "  ERROR: allocation failed\n");
        free(dfa.nodes);
        free(dfa.sb_char);
        free(dfa.fastmap);
        return 2;
    }

    memset(dfa.nodes, 0, DFA_NODES_SIZE);
    memset(dfa.sb_char, 0, DFA_SB_CHAR_SIZE);
    memset(dfa.fastmap, 0, FASTMAP_SIZE);

    printf("  dfa.nodes=%p, dfa.sb_char=%p, dfa.fastmap=%p\n",
           dfa.nodes, dfa.sb_char, dfa.fastmap);

    /* Error path frees nodes and fastmap */
    printf("  Error path: freeing nodes and fastmap...\n");
    free(dfa.nodes);
    free(dfa.fastmap);

    /* Outer cleanup frees ALL fields (double-free on nodes and fastmap) */
    printf("  Outer cleanup: freeing all (double-free on nodes + fastmap)...\n");
    free(dfa.nodes);    /* DOUBLE FREE */
    free(dfa.sb_char);  /* This one is fine — only freed once */
    free(dfa.fastmap);  /* DOUBLE FREE */

    printf("  Both double-frees absorbed — IgnoreDoubleFree active.\n");
    return 0;
}

int main(void)
{
    int result = 0;

    printf("=== CVE-2025-8058: regcomp() Double-Free on Allocation "
           "Failure ===\n");
    printf("Vulnerability: Missing NULL assignment after free in regex "
           "compilation error path\n");
    printf("Impact: Heap corruption, potential arbitrary write "
           "(CVSS medium)\n");
    printf("TSM defenses: generational arena, IgnoreDoubleFree, "
           "allocation fingerprints, quarantine\n\n");

    result |= test_basic_double_free();
    printf("\n");
    result |= test_double_free_with_reuse();
    printf("\n");
    result |= test_double_free_fastmap();

    printf("\n=== Summary ===\n");
    if (result == 0) {
        printf("All double-frees were absorbed — TSM protection active.\n");
    } else {
        printf("VULNERABLE: double-free caused heap corruption.\n");
    }

    return result;
}
