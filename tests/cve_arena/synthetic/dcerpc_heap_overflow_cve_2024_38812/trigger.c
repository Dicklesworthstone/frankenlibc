/* Synthetic CVE reproduction: DCERPC-style heap overflow
 * Modeled on CVE-2024-38812 (VMware vCenter DCERPC, CVSS 9.8)
 * CWE-122: Heap-based Buffer Overflow
 *
 * Pattern: Protocol parser trusts an allocation length field from network
 * input but copies data using a different, larger length field from the
 * same packet. Classic "confused deputy" length mismatch.
 *
 * The VMware bug: The DCERPC protocol handler in vCenter Server reads two
 * length fields from the packet header.  It uses one (frag_length) to
 * allocate a heap buffer and a different one (auth_length, or a computed
 * field from stub data) to determine how many bytes to copy into that
 * buffer.  When the copy length exceeds the allocation length, a heap
 * buffer overflow occurs, leading to remote code execution.
 *
 * Stock glibc: heap metadata is silently corrupted; crash may occur later
 *              at free() or on subsequent allocation, far from the root cause
 * glibc_rust:  trailing canary detects the overflow at free() time;
 *              ClampSize would prevent the oversized copy entirely
 *
 * Build: cc -o trigger trigger.c -Wall -Wextra
 * Run:   ./trigger
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Simulated DCERPC packet header
 * ---------------------------------------------------------------------------
 * In real DCERPC (MS-RPCE), packets carry multiple length fields:
 *   - frag_length:  total fragment length (used for buffer allocation)
 *   - auth_length:  authentication data length
 *   - stub_length:  derived from frag_length minus headers
 *
 * The bug arises when the parser uses frag_length for allocation but a
 * separately controlled field (here: copy_len) for the memcpy size.
 * An attacker crafts a packet where copy_len > alloc_len.
 * --------------------------------------------------------------------------- */
struct packet_header {
    uint16_t magic;      /* Protocol magic: 0xDA7A                           */
    uint16_t alloc_len;  /* Length used for buffer allocation (from header)   */
    uint16_t copy_len;   /* Length used for data copy (BUG: can be > alloc_len) */
    uint16_t padding;    /* Alignment padding                                */
};

/* ---------------------------------------------------------------------------
 * Simulated packet payload
 * ---------------------------------------------------------------------------
 * Follows the header in a real network packet.  We embed a recognizable
 * pattern so we can verify exactly how many bytes were written.
 * --------------------------------------------------------------------------- */
#define MAX_PAYLOAD 512

struct network_packet {
    struct packet_header header;
    uint8_t payload[MAX_PAYLOAD];
};

/* ---------------------------------------------------------------------------
 * build_malicious_packet()
 * ---------------------------------------------------------------------------
 * Constructs a packet that exploits the length mismatch.  The alloc_len is
 * set to a small value (64) while copy_len is set to a much larger value
 * (256).  The payload is filled with a repeating byte pattern (0xCC, which
 * is the INT3 debug breakpoint opcode -- a common shellcode NOP sled byte).
 * --------------------------------------------------------------------------- */
static void build_malicious_packet(struct network_packet *pkt)
{
    memset(pkt, 0, sizeof(*pkt));

    pkt->header.magic     = 0xDA7A;
    pkt->header.alloc_len = 64;   /* Parser allocates this many bytes       */
    pkt->header.copy_len  = 256;  /* But copies this many bytes -- OVERFLOW */
    pkt->header.padding   = 0;

    /* Fill payload with recognizable pattern */
    for (int i = 0; i < MAX_PAYLOAD; i++) {
        pkt->payload[i] = (uint8_t)(0xCC);
    }

    printf("  Packet built: magic=0x%04X alloc_len=%u copy_len=%u\n",
           pkt->header.magic, pkt->header.alloc_len, pkt->header.copy_len);
    printf("  Overflow amount: %u bytes past allocation boundary\n",
           pkt->header.copy_len - pkt->header.alloc_len);
}

/* ---------------------------------------------------------------------------
 * process_dcerpc_packet() -- the vulnerable protocol handler
 * ---------------------------------------------------------------------------
 * This function mirrors the real vCenter DCERPC handler's logic:
 *
 * 1. Read alloc_len from the packet header
 * 2. malloc(alloc_len) to create the processing buffer
 * 3. Read copy_len from the packet header (DIFFERENT field!)
 * 4. memcpy(buffer, payload, copy_len) -- uses the WRONG length
 *
 * Step 4 overflows the buffer when copy_len > alloc_len.
 *
 * Returns:
 *   0 = success (overflow occurred silently -- VULNERABLE)
 *   1 = overflow detected before copy (glibc_rust ClampSize)
 *   2 = overflow detected at free (glibc_rust canary)
 *  -1 = error
 * --------------------------------------------------------------------------- */
static int process_dcerpc_packet(const struct network_packet *pkt)
{
    /* Validate magic (real parsers do this) */
    if (pkt->header.magic != 0xDA7A) {
        fprintf(stderr, "  ERROR: bad magic 0x%04X\n", pkt->header.magic);
        return -1;
    }

    uint16_t alloc_len = pkt->header.alloc_len;
    uint16_t copy_len  = pkt->header.copy_len;

    printf("  Allocating buffer: %u bytes (from header.alloc_len)\n", alloc_len);

    /* Step 1: Allocate based on alloc_len */
    uint8_t *buffer = (uint8_t *)malloc(alloc_len);
    if (!buffer) {
        fprintf(stderr, "  ERROR: malloc(%u) failed\n", alloc_len);
        return -1;
    }
    memset(buffer, 0, alloc_len);

    /*
     * Step 2: Copy using copy_len -- THIS IS THE BUG
     *
     * The real parser reads a different length field from the DCERPC packet
     * to determine how many bytes of stub data or auth data to process.
     * It trusts that field without cross-checking against alloc_len.
     *
     * With stock glibc:
     *   memcpy silently writes past the buffer boundary.  The heap chunk
     *   metadata (fd/bk pointers, size field) of adjacent allocations is
     *   overwritten.  The corruption may not be detected until a later
     *   malloc/free call triggers a heap consistency check -- by which
     *   point the attacker may have gained code execution via corrupted
     *   function pointers or vtable entries.
     *
     * With glibc_rust:
     *   Option A (proactive): If the TSM intercepts memcpy and applies
     *     ClampSize, the copy is reduced to min(copy_len, alloc_len)
     *     = 64 bytes.  No overflow occurs.
     *   Option B (reactive): The trailing canary (8 bytes appended after
     *     the user region by the arena allocator) is overwritten by the
     *     overflow.  At free() time, the canary is verified and the
     *     corruption is detected.
     */
    printf("  Copying %u bytes into %u-byte buffer (from header.copy_len)\n",
           copy_len, alloc_len);

    memcpy(buffer, pkt->payload, copy_len);  /* <-- HEAP OVERFLOW */

    printf("  memcpy completed -- buffer contents:\n");
    printf("    First 8 bytes:  ");
    for (int i = 0; i < 8 && i < alloc_len; i++) {
        printf("%02X ", buffer[i]);
    }
    printf("\n");

    /*
     * Verify overflow by checking bytes beyond the allocation.
     * With stock glibc, the bytes beyond alloc_len were written to heap
     * metadata or adjacent allocations.
     *
     * We allocate a "canary check" buffer immediately after to observe
     * whether the adjacent heap memory was corrupted.
     */
    uint8_t *adjacent = (uint8_t *)malloc(64);
    if (adjacent) {
        /*
         * In a stock glibc heap, the adjacent allocation may land in memory
         * that was just overwritten by our overflow.  Check for our 0xCC
         * pattern in what should be freshly zeroed memory.
         */
        int corruption_detected = 0;
        for (int i = 0; i < 64; i++) {
            if (adjacent[i] == 0xCC) {
                corruption_detected = 1;
                break;
            }
        }
        if (corruption_detected) {
            printf("  Adjacent allocation contains overflow data (0xCC)!\n");
            printf("  HEAP CORRUPTION CONFIRMED\n");
        } else {
            printf("  Adjacent allocation appears clean (heap layout may vary)\n");
        }
        free(adjacent);
    }

    /* Free the overflowed buffer -- canary check happens here in glibc_rust */
    printf("  Freeing overflowed buffer...\n");
    free(buffer);
    printf("  free() returned without error\n");

    return 0;
}

/* ---------------------------------------------------------------------------
 * Scenario 2: Demonstrate ClampSize prevention
 * ---------------------------------------------------------------------------
 * Show what would happen if the copy were clamped to the allocation size.
 * This is a reference "safe" version demonstrating the TSM healing behavior.
 * --------------------------------------------------------------------------- */
static void demonstrate_clamped_copy(const struct network_packet *pkt)
{
    uint16_t alloc_len = pkt->header.alloc_len;
    uint16_t copy_len  = pkt->header.copy_len;

    /* This is what ClampSize would do: min(copy_len, alloc_len) */
    uint16_t safe_len = (copy_len < alloc_len) ? copy_len : alloc_len;

    printf("  ClampSize healing: copy_len=%u clamped to %u (alloc_len=%u)\n",
           copy_len, safe_len, alloc_len);

    uint8_t *buffer = (uint8_t *)malloc(alloc_len);
    if (!buffer) {
        fprintf(stderr, "  ERROR: malloc failed\n");
        return;
    }
    memset(buffer, 0, alloc_len);

    /* Safe copy with clamped length */
    memcpy(buffer, pkt->payload, safe_len);

    printf("  Safe copy completed: %u bytes written to %u-byte buffer\n",
           safe_len, alloc_len);
    printf("  No overflow.  Buffer and heap metadata intact.\n");

    free(buffer);
}

/* ---------------------------------------------------------------------------
 * Main
 * --------------------------------------------------------------------------- */
int main(void)
{
    printf("=== Synthetic CVE Reproduction: DCERPC-style Heap Overflow ===\n");
    printf("Modeled on: CVE-2024-38812 (VMware vCenter Server DCERPC)\n");
    printf("CWE-122:    Heap-based Buffer Overflow\n");
    printf("CVSS:       9.8 (Critical)\n");
    printf("\n");
    printf("Bug pattern: Protocol parser allocates a buffer using one length\n");
    printf("field from the packet header (alloc_len=64) but copies data\n");
    printf("using a different, larger length field (copy_len=256).  The\n");
    printf("192-byte overflow corrupts heap metadata and adjacent allocations.\n");
    printf("\n");
    printf("TSM mitigations:\n");
    printf("  1. ClampSize: Intercepts memcpy and clamps copy length to\n");
    printf("     the known allocation size (remaining_from() bounds check)\n");
    printf("  2. Trailing canary: 8-byte canary after each allocation detects\n");
    printf("     the overflow at free() time if ClampSize did not fire\n");
    printf("\n");
    printf("-----------------------------------------------------------\n\n");

    /* Build the malicious packet */
    struct network_packet pkt;
    printf("[PHASE 1] Constructing malicious DCERPC packet\n");
    build_malicious_packet(&pkt);
    printf("\n");

    /* Execute the vulnerable handler */
    printf("[PHASE 2] Processing packet through vulnerable handler\n");
    int result = process_dcerpc_packet(&pkt);
    printf("  Handler returned: %d\n", result);
    printf("\n");

    /* Demonstrate what ClampSize would do */
    printf("[PHASE 3] Demonstrating ClampSize healing behavior\n");
    demonstrate_clamped_copy(&pkt);
    printf("\n");

    printf("-----------------------------------------------------------\n");
    printf("=== Reproduction complete.  Review output above. ===\n");
    printf("\n");
    printf("Expected with stock glibc:\n");
    printf("  Phase 2: memcpy overflows by 192 bytes; heap metadata corrupted;\n");
    printf("           free() may crash or silently succeed with corrupted heap;\n");
    printf("           subsequent allocations may return attacker-controlled data\n");
    printf("\n");
    printf("Expected with glibc_rust TSM:\n");
    printf("  Phase 2: ClampSize prevents the oversized copy (clamped to 64 bytes)\n");
    printf("           OR trailing canary detects overflow at free() and reports\n");
    printf("           FreedWithCanaryCorruption healing event\n");

    return 0;
}
