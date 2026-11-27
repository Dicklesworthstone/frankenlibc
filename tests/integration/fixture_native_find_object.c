#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>

int find_data = 19;
int find_constructor_result;
static void (*finalizer_report)(int);

int find_answer(void) { return find_data + 23; }

static int find_self(void) {
    struct dl_find_object info;
    if (_dl_find_object(&find_data, &info) != 0)
        return -1;
    return info.dlfo_flags == 0 && info.dlfo_link_map != 0 &&
           (uintptr_t)info.dlfo_map_start <= (uintptr_t)&find_data &&
           (uintptr_t)&find_data < (uintptr_t)info.dlfo_map_end;
}

__attribute__((constructor)) static void find_init(void) {
    find_constructor_result = find_self();
}

__attribute__((destructor)) static void find_fini(void) {
    if (finalizer_report != 0)
        finalizer_report(find_self());
}

void find_set_finalizer_report(void (*report)(int)) {
    finalizer_report = report;
}

int find_direct(void *address, struct dl_find_object *result) {
    return _dl_find_object(address, result);
}

int find_indirect(void *address, struct dl_find_object *result,
                  const char *version) {
    typedef int (*query_fn)(void *, struct dl_find_object *);
    query_fn query = (query_fn)(version == 0
                                  ? dlsym(RTLD_DEFAULT, "_dl_find_object")
                                  : dlvsym(RTLD_DEFAULT, "_dl_find_object", version));
    return query == 0 ? -2 : query(address, result);
}
