#define _GNU_SOURCE
#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct probe { void *base; const char *path; int seen; };
static int visit(struct dl_phdr_info *info, size_t size, void *data) {
    struct probe *probe = data;
    if ((void *)info->dlpi_addr != probe->base) return 0;
    assert(size >= sizeof(*info));
    assert(strcmp(info->dlpi_name, probe->path) == 0);
    int loads = 0, unwind = 0;
    for (int n = 0; n < info->dlpi_phnum; ++n) {
        loads += info->dlpi_phdr[n].p_type == PT_LOAD;
        unwind += info->dlpi_phdr[n].p_type == PT_GNU_EH_FRAME;
    }
    assert(loads > 0 && unwind == 1);
    probe->seen++;
    return 57;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    const char *names[] = {"inspect_answer", "inspect_values", "inspect_protected"};
    Dl_info info;
    for (unsigned n = 0; n < sizeof(names) / sizeof(names[0]); ++n) {
        void *symbol = dlsym(handle, names[n]);
        assert(symbol && dladdr(symbol, &info));
        assert(strcmp(info.dli_fname, argv[1]) == 0);
        assert(strcmp(info.dli_sname, names[n]) == 0);
        assert(info.dli_saddr == symbol);
    }
    char *values = dlsym(handle, "inspect_values");
    assert(dladdr(values + 31, &info) && strcmp(info.dli_sname, "inspect_values") == 0);
    assert(info.dli_saddr == values);
    void *(*hidden)(void) = dlsym(handle, "inspect_hidden_address");
    assert(hidden && dladdr(hidden(), &info));
    assert(info.dli_sname == NULL && info.dli_saddr == NULL);
    assert(dladdr(info.dli_fbase, &info));
    assert(info.dli_sname == NULL && info.dli_saddr == NULL);
    struct probe probe = { info.dli_fbase, argv[1], 0 };
    assert(dl_iterate_phdr(visit, &probe) == 57 && probe.seen == 1);
    assert(dlclose(handle) == 0);
    assert(!dladdr(values, &info));
    puts("PASS: function/data/protected/interior/hidden/object-only/phdr/stop/unload");
    return 0;
}
