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
