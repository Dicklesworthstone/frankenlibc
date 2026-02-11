/* Synthetic CVE reproduction: QUIC-style use-after-free
 * Modeled on CVE-2024-24990 (nginx QUIC, CVSS 7.5)
 * CWE-416: Use After Free
 *
 * Pattern: Event-driven connection handling where stream cleanup handler
 * accesses the parent connection context after it has been freed.
 *
 * The nginx bug: In the QUIC module, when a connection is closed, the
 * connection context is freed.  However, stream objects associated with
 * that connection still hold a pointer to the (now freed) connection
 * context.  When stream cleanup handlers run (either immediately or in
 * a subsequent event loop iteration), they dereference the dangling
 * pointer, reading (and potentially writing) freed memory.
 *
 * If the freed memory has been reallocated for a different purpose, the
 * UAF enables type confusion: the stream cleanup handler interprets
 * the new object's data as a connection context, potentially calling
 * function pointers from attacker-controlled data.
 *
 * Stock glibc: freed memory may be immediately reused; UAF reads stale or
 *              attacker-controlled data; function pointer hijack possible
 * glibc_rust:  generational arena detects generation mismatch on the freed
 *              pointer; quarantine prevents immediate memory reuse; bloom
 *              filter provides fast "is this still valid?" check
 *
 * Build: cc -o trigger trigger.c -Wall -Wextra
 * Run:   ./trigger
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---------------------------------------------------------------------------
 * Simulated connection and stream structures
 * ---------------------------------------------------------------------------
 * These mirror the event-driven server pattern where:
 *   - A "connection" owns resources and has callback function pointers
 *   - Multiple "streams" are multiplexed on a single connection
 *   - Each stream holds a back-pointer to its parent connection
 *   - Stream cleanup must access the connection for logging, stats, etc.
 * --------------------------------------------------------------------------- */

/* Sentinel values written into connection data to verify UAF detection */
#define CONN_MAGIC_ALIVE  0xC044A11E   /* "CONN ALIVE" */
#define CONN_MAGIC_DEAD   0xDEADC044   /* "DEAD CONN"  */
#define CONN_MAGIC_REUSE  0x0BEF0BEF   /* "OBEY OBEY" -- attacker's data */

struct connection {
    uint32_t magic;                        /* Liveness sentinel              */
    int id;                                /* Connection identifier          */
    void (*on_close)(struct connection *);  /* Close callback (function ptr!) */
    char data[64];                         /* Application-specific data      */
    int reference_count;                   /* Number of streams referencing   */
};

struct stream {
    struct connection *conn;               /* Back-pointer to parent (DANGER) */
    int stream_id;                         /* Stream identifier               */
    void (*cleanup)(struct stream *);      /* Cleanup callback                */
};

/* ---------------------------------------------------------------------------
 * Connection callbacks
 * ---------------------------------------------------------------------------
 * In a real server, on_close might flush buffers, update metrics, or send
 * a GOAWAY frame.  The key point is that it is a function pointer stored
 * in heap memory -- the classic target for UAF-based code execution.
 * --------------------------------------------------------------------------- */
static void connection_on_close(struct connection *conn)
{
    printf("    [connection %d] on_close callback invoked\n", conn->id);
}

/* ---------------------------------------------------------------------------
 * Stream cleanup handler -- the VULNERABLE code path
 * ---------------------------------------------------------------------------
 * This runs AFTER the connection has been freed.  It dereferences conn->
 * which is a dangling pointer.
 *
 * In nginx's QUIC module, this corresponds to the stream cleanup handler
 * that accesses c->quic->connection after the QUIC connection object was
 * freed by ngx_quic_close_connection().
 * --------------------------------------------------------------------------- */
static void stream_cleanup(struct stream *s)
{
    printf("    [stream %d] cleanup: accessing parent connection...\n",
           s->stream_id);

    /*
     * UAF: s->conn points to freed memory.
     *
     * Read the magic field to determine the state of the memory:
     *   CONN_MAGIC_ALIVE = connection is still valid (not UAF)
     *   CONN_MAGIC_DEAD  = freed but not yet reused (UAF, stale data)
     *   CONN_MAGIC_REUSE = freed and reallocated by attacker (UAF, hijack)
     *   anything else    = freed and partially overwritten (UAF, corruption)
     */
    uint32_t observed_magic = s->conn->magic;

    if (observed_magic == CONN_MAGIC_ALIVE) {
        printf("    [stream %d] connection %d appears valid (magic=0x%08X)\n",
               s->stream_id, s->conn->id, observed_magic);
        printf("    STATUS: Connection still alive (no UAF in this path)\n");
    } else if (observed_magic == CONN_MAGIC_DEAD) {
        printf("    [stream %d] connection has STALE data (magic=0x%08X)\n",
               s->stream_id, observed_magic);
        printf("    STATUS: USE-AFTER-FREE -- reading freed memory\n");
    } else if (observed_magic == CONN_MAGIC_REUSE) {
        printf("    [stream %d] connection memory REUSED (magic=0x%08X)!\n",
               s->stream_id, observed_magic);
        printf("    STATUS: USE-AFTER-FREE + TYPE CONFUSION -- attacker data!\n");

        /*
         * In a real exploit, the attacker would have placed a controlled
         * function pointer at the offset of conn->on_close.  Calling it
         * would redirect execution to attacker-chosen code.
         *
         * Demonstrate the danger by reading the function pointer field:
         */
        printf("    [stream %d] on_close function pointer = %p\n",
               s->stream_id, (void *)(uintptr_t)s->conn->on_close);
        printf("    WARNING: If attacker controls this, calling on_close\n");
        printf("             redirects execution to arbitrary address!\n");
    } else {
        printf("    [stream %d] connection has UNKNOWN data (magic=0x%08X)\n",
               s->stream_id, observed_magic);
        printf("    STATUS: USE-AFTER-FREE -- heap metadata or other data\n");
    }
}

/* ---------------------------------------------------------------------------
 * create_connection() -- allocate and initialize a connection
 * --------------------------------------------------------------------------- */
static struct connection *create_connection(int id)
{
    struct connection *conn = (struct connection *)malloc(sizeof(struct connection));
    if (!conn) {
        fprintf(stderr, "  ERROR: malloc(connection) failed\n");
        return NULL;
    }

    conn->magic           = CONN_MAGIC_ALIVE;
    conn->id              = id;
    conn->on_close        = connection_on_close;
    conn->reference_count = 0;
    memset(conn->data, 'A', sizeof(conn->data));

    printf("  Created connection %d at %p (magic=0x%08X)\n",
           id, (void *)conn, conn->magic);
    return conn;
}

/* ---------------------------------------------------------------------------
 * create_stream() -- allocate a stream linked to a connection
 * --------------------------------------------------------------------------- */
static struct stream *create_stream(struct connection *conn, int stream_id)
{
    struct stream *s = (struct stream *)malloc(sizeof(struct stream));
    if (!s) {
        fprintf(stderr, "  ERROR: malloc(stream) failed\n");
        return NULL;
    }

    s->conn      = conn;  /* Store back-pointer to parent connection */
    s->stream_id = stream_id;
    s->cleanup   = stream_cleanup;

    conn->reference_count++;

    printf("  Created stream %d -> connection %d (ref_count=%d)\n",
           stream_id, conn->id, conn->reference_count);
    return s;
}

/* ---------------------------------------------------------------------------
 * close_connection() -- free the connection WITHOUT checking streams
 * ---------------------------------------------------------------------------
 * This is the bug: the connection is freed while streams still reference it.
 * In the nginx QUIC code, this happens in ngx_quic_close_connection() which
 * frees the QUIC connection context but does not invalidate stream pointers.
 * --------------------------------------------------------------------------- */
static void close_connection(struct connection *conn)
{
    printf("  Closing connection %d (ref_count=%d still active!)\n",
           conn->id, conn->reference_count);

    /* Mark as dead so we can distinguish stale reads from reuse */
    conn->magic = CONN_MAGIC_DEAD;

    /* In a real server, this might also invoke the on_close callback */
    printf("  Freeing connection %d at %p\n", conn->id, (void *)conn);
    free(conn);  /* STREAMS STILL HOLD POINTERS TO THIS MEMORY */
}

/* ---------------------------------------------------------------------------
 * simulate_attacker_realloc()
 * ---------------------------------------------------------------------------
 * After the connection is freed, an attacker (who controls incoming data)
 * triggers a new allocation of the same size.  The heap allocator returns
 * the recently-freed memory.  The attacker fills it with controlled data,
 * including a crafted function pointer at the on_close offset.
 *
 * With stock glibc: the freed chunk is immediately available for reuse.
 * With glibc_rust: quarantine holds the chunk, preventing immediate reuse.
 * --------------------------------------------------------------------------- */
static void *simulate_attacker_realloc(void)
{
    /*
     * Allocate the exact same size as struct connection.
     * On stock glibc with default malloc, this has a high probability of
     * returning the same address that was just freed.
     */
    void *reused = malloc(sizeof(struct connection));
    if (!reused) {
        return NULL;
    }

    /*
     * Fill with attacker-controlled data.
     * Place CONN_MAGIC_REUSE at offset 0 (where conn->magic lives) and
     * a recognizable fake pointer at the on_close offset.
     */
    memset(reused, 0x41, sizeof(struct connection));

    struct connection *fake = (struct connection *)reused;
    fake->magic    = CONN_MAGIC_REUSE;
    fake->on_close = (void (*)(struct connection *))0xDEADBEEF;

    printf("  Attacker allocation at %p (magic=0x%08X, fake on_close=0xDEADBEEF)\n",
           reused, fake->magic);
    return reused;
}

/* ---------------------------------------------------------------------------
 * Main: demonstrate the UAF sequence
 * --------------------------------------------------------------------------- */
int main(void)
{
    printf("=== Synthetic CVE Reproduction: QUIC-style Use-After-Free ===\n");
    printf("Modeled on: CVE-2024-24990 (nginx QUIC module)\n");
    printf("CWE-416:    Use After Free\n");
    printf("CVSS:       7.5 (High)\n");
    printf("\n");
    printf("Bug pattern: Event-driven server frees connection context while\n");
    printf("stream cleanup handlers still hold pointers to it.  Stream\n");
    printf("cleanup dereferences the dangling pointer, reading freed memory.\n");
    printf("If the memory has been reallocated with attacker data, function\n");
    printf("pointer hijack enables remote code execution.\n");
    printf("\n");
    printf("TSM mitigations:\n");
    printf("  1. Generational arena: freed slot generation increments;\n");
    printf("     subsequent access detects generation mismatch (100%% detection)\n");
    printf("  2. Quarantine queue: freed memory held for 64MB/65536 entries\n");
    printf("     before physical deallocation, preventing immediate reuse\n");
    printf("  3. Bloom filter: O(1) 'is this pointer still valid?' check\n");
    printf("     returns false for freed pointers (zero false negatives)\n");
    printf("\n");
    printf("-----------------------------------------------------------\n\n");

    /* Phase 1: Set up the connection and streams */
    printf("[PHASE 1] Creating connection and multiplexed streams\n");

    struct connection *conn = create_connection(42);
    if (!conn) return 1;

    struct stream *streams[3];
    streams[0] = create_stream(conn, 1);
    streams[1] = create_stream(conn, 2);
    streams[2] = create_stream(conn, 3);

    for (int i = 0; i < 3; i++) {
        if (!streams[i]) return 1;
    }
    printf("  All 3 streams created, each holding back-pointer to connection 42\n");
    printf("\n");

    /* Phase 2: Close the connection (BUG: streams not notified) */
    printf("[PHASE 2] Closing connection (streams still active!)\n");
    void *conn_addr = (void *)conn;
    close_connection(conn);
    conn = NULL;  /* Our local pointer is nulled, but streams still have theirs */
    printf("  Connection freed.  3 streams now hold DANGLING POINTERS to %p\n",
           conn_addr);
    printf("\n");

    /* Phase 3: Attacker triggers reallocation to occupy freed memory */
    printf("[PHASE 3] Attacker triggers reallocation of freed memory\n");
    void *attacker_data = simulate_attacker_realloc();
    if (attacker_data == conn_addr) {
        printf("  CRITICAL: Attacker allocation at SAME ADDRESS as freed connection!\n");
        printf("  Stream pointers now alias attacker-controlled data.\n");
    } else {
        printf("  Attacker allocation at different address (quarantine may be active)\n");
        printf("  Freed memory at %p not yet reused (TSM quarantine working)\n",
               conn_addr);
    }
    printf("\n");

    /* Phase 4: Stream cleanup handlers run -- UAF occurs here */
    printf("[PHASE 4] Running stream cleanup handlers (USE-AFTER-FREE)\n");
    for (int i = 0; i < 3; i++) {
        printf("  --- Stream %d cleanup ---\n", streams[i]->stream_id);
        streams[i]->cleanup(streams[i]);
        printf("\n");
    }

    /* Phase 5: Cleanup */
    printf("[PHASE 5] Cleanup\n");
    for (int i = 0; i < 3; i++) {
        free(streams[i]);
    }
    if (attacker_data) {
        free(attacker_data);
    }
    printf("  All memory freed.\n");
    printf("\n");

    printf("-----------------------------------------------------------\n");
    printf("=== Reproduction complete.  Review PHASE 4 output above. ===\n");
    printf("\n");
    printf("Expected with stock glibc:\n");
    printf("  Phase 3: Attacker allocation returns SAME address as freed\n");
    printf("           connection (immediate reuse from free list)\n");
    printf("  Phase 4: Stream cleanup reads attacker magic (0x%08X);\n",
           CONN_MAGIC_REUSE);
    printf("           on_close function pointer is 0xDEADBEEF;\n");
    printf("           calling on_close would jump to attacker-controlled address\n");
    printf("\n");
    printf("Expected with glibc_rust TSM:\n");
    printf("  Phase 3: Quarantine holds freed connection; attacker allocation\n");
    printf("           returns a DIFFERENT address (no immediate reuse)\n");
    printf("  Phase 4: Generational arena detects generation mismatch when\n");
    printf("           stream cleanup dereferences the freed connection pointer;\n");
    printf("           access is blocked; ReturnSafeDefault provides a null\n");
    printf("           connection context; cleanup completes without crash\n");

    return 0;
}
