#include <stddef.h>
#ifndef ALIGNMENT
#define ALIGNMENT 4096
#endif
__attribute__((aligned(ALIGNMENT))) volatile unsigned char mapping_data[8192] = { 17 };
__attribute__((aligned(ALIGNMENT))) volatile unsigned char mapping_bss[8192];
void * const mapping_locked = (void *)mapping_data;
static int initialized;
__attribute__((constructor)) static void initialize(void) {
    mapping_data[0] += 1;
    mapping_bss[0] = 23;
    initialized = 1;
}
unsigned char *mapping_data_address(void) { return (unsigned char *)mapping_data; }
unsigned char *mapping_bss_address(void) { return (unsigned char *)mapping_bss; }
void *mapping_locked_address(void) { return (void *)&mapping_locked; }
int mapping_probe(void) {
    if (!initialized || mapping_data[0] != 18 || mapping_bss[0] != 23
        || mapping_data[8191] != 0 || mapping_bss[8191] != 0) return -1;
    mapping_data[8191] = 31; mapping_bss[8191] = 47;
    int ok = mapping_locked == (void *)mapping_data && mapping_data[8191] == 31
        && mapping_bss[8191] == 47;
    mapping_data[8191] = 0; mapping_bss[8191] = 0;
    return ok;
}

#ifdef NONZERO_RUNTIME
/* All addresses below retain their linked ELF virtual values. The loader
   must distinguish those values from offsets in its compact mapping. */
__thread int mapping_tls = 19;
static int legacy_state;
static void (*on_finalize)(int);
void mapping_legacy_init(void) { legacy_state = 1; }
void mapping_legacy_fini(void) {
    if (on_finalize) on_finalize(legacy_state == 2 ? 2 : -2);
}
__attribute__((destructor)) static void finalize(void) {
    if (on_finalize) on_finalize(legacy_state == 1 ? 1 : -1);
    legacy_state = 2;
}
void mapping_set_finalize(void (*callback)(int)) { on_finalize = callback; }
int *mapping_tls_address(void) { return &mapping_tls; }
int mapping_tls_next(void) { return ++mapping_tls; }
static int indirect_result(void) { return 37; }
static int (*select_indirect(void))(void) { return indirect_result; }
int mapping_indirect(void) __attribute__((ifunc("select_indirect")));
int (*mapping_indirect_pointer)(void) = mapping_indirect;
int mapping_runtime_probe(void) {
    return legacy_state == 1 && mapping_indirect_pointer() == 37 && mapping_indirect() == 37;
}
__attribute__((noinline)) int mapping_walk(void (*callback)(void *), void *argument) {
    callback(argument);
    /* Prevent tail calls so a genuine DSO frame must be traversed. */
    return legacy_state;
}
#endif
