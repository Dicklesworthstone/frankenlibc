/* fixture_runtime_ready_arm.cpp — e2e test for RUNTIME_READY arming under LD_PRELOAD (bd-06bxm.1)
 *
 * This fixture has a global constructor that observes the runtime phase.
 * Under LD_PRELOAD, the runtime should arm after all startup initialization
 * completes (after the constructor runs but before main() returns).
 *
 * Exit codes:
 *   0 = PASS: runtime armed by end of main()
 *   1 = FAIL: runtime still in bootstrap/passthrough after main() started
 *   2 = FAIL: FFI symbols not resolved (LD_PRELOAD not working)
 */
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {
    extern int __frankenlibc_is_runtime_ready() __attribute__((weak));
    extern int __frankenlibc_runtime_phase() __attribute__((weak));
}

static int g_constructor_phase = -1;
static int g_constructor_ready = -1;

// Global constructor: runs before main(), should see bootstrap phase
class GlobalStartupObserver {
public:
    GlobalStartupObserver() {
        if (__frankenlibc_runtime_phase && __frankenlibc_is_runtime_ready) {
            g_constructor_phase = __frankenlibc_runtime_phase();
            g_constructor_ready = __frankenlibc_is_runtime_ready();
        }
    }
};

// Another constructor to test multiple constructors don't cause deadlock
class SecondGlobalObserver {
public:
    SecondGlobalObserver() {
        // Just allocate and free to exercise the allocator during startup
        void* ptr = malloc(1024);
        memset(ptr, 0x42, 1024);
        free(ptr);
    }
};

// Use static instances to trigger constructors
static GlobalStartupObserver g_observer1;
static SecondGlobalObserver g_observer2;

int main(int argc, char** argv) {
    // Check FFI symbols are resolved
    if (!__frankenlibc_is_runtime_ready || !__frankenlibc_runtime_phase) {
        fprintf(stderr, "FAIL: FFI symbols not resolved (check LD_PRELOAD)\n");
        return 2;
    }

    int main_phase = __frankenlibc_runtime_phase();
    int main_ready = __frankenlibc_is_runtime_ready();

    // Print diagnostic info
    printf("constructor_phase=%d constructor_ready=%d main_phase=%d main_ready=%d\n",
           g_constructor_phase, g_constructor_ready, main_phase, main_ready);

    // During constructor (before signal_runtime_ready is called in startup wrapper),
    // we expect bootstrap phase (0). After startup completes, we expect active (2).
    // The exact timing depends on when the host __libc_start_main calls our wrapper.

    // Verbose mode: print all details
    if (argc > 1 && strcmp(argv[1], "-v") == 0) {
        fprintf(stderr, "INFO: constructor observed phase=%d ready=%d\n",
                g_constructor_phase, g_constructor_ready);
        fprintf(stderr, "INFO: main() observes phase=%d ready=%d\n",
                main_phase, main_ready);
    }

    // The critical assertion: by the time main() runs, the runtime should be armed.
    // This proves signal_runtime_ready() was called in the startup path.
    if (main_ready != 1) {
        fprintf(stderr, "FAIL: runtime not ready in main() (phase=%d ready=%d)\n",
                main_phase, main_ready);
        fprintf(stderr, "      Expected: armed after startup wrapper completes\n");
        return 1;
    }

    // Note: constructor_ready == 0 is acceptable and expected if the constructor
    // runs before signal_runtime_ready() in the startup sequence.

    printf("PASS: runtime armed by main()\n");
    return 0;
}
