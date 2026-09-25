#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stddef.h>

int native_phdr_runtime_probe(void);

static int locate_self(struct dl_phdr_info *info, size_t size, void *data) {
    uintptr_t address = (uintptr_t)&native_phdr_runtime_probe;
    if (size < offsetof(struct dl_phdr_info, dlpi_phnum) + sizeof(info->dlpi_phnum))
        return 0;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        uintptr_t start = info->dlpi_addr + p->p_vaddr;
        if (p->p_type == PT_LOAD && (p->p_flags & PF_X) &&
            address >= start && address - start < p->p_memsz) {
            Dl_info found;
            if (!dladdr((void *)address, &found) ||
                found.dli_fbase != (void *)(uintptr_t)info->dlpi_addr ||
                found.dli_saddr != (void *)address || !found.dli_sname ||
                !info->dlpi_name || !*info->dlpi_name)
                return -1;
            *(int *)data += 1;
            return 19;
        }
    }
    return 0;
}

int native_phdr_runtime_probe(void) {
    int seen = 0;
    int result = dl_iterate_phdr(locate_self, &seen);
    return result == 19 && seen == 1 ? 42 : -1;
}
