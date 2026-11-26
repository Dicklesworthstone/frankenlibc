#define _GNU_SOURCE
#include <inttypes.h>
#include <link.h>
#include <stdio.h>
#include <sys/auxv.h>

static unsigned int trace;

static void preinit(int argc, char **argv, char **envp) {
    if (argc > 0 && argv && argv[0] && envp)
        trace = 1;
}

__attribute__((used, section(".preinit_array")))
static void (*const preinit_entry)(int, char **, char **) = preinit;

__attribute__((constructor))
static void init(void) {
    trace = trace * 10 + 2;
}

static int report(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    uintptr_t phdr = getauxval(AT_PHDR);
    if ((uintptr_t)info->dlpi_phdr != phdr)
        return 0;
    // The running linker supplies the expected displacement independently
    // of the candidate's ELF file and program-header calculations.
    return printf("%" PRIxPTR " %" PRIxPTR " %" PRIxPTR "\n",
                  phdr, (uintptr_t)getauxval(AT_ENTRY),
                  (uintptr_t)info->dlpi_addr) > 0;
}

int main(void) {
    if (trace != 12 || getauxval(AT_BASE) != 0)
        return 1;
    return dl_iterate_phdr(report, NULL) == 1 ? 0 : 2;
}
