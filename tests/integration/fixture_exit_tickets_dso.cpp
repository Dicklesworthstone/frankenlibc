#ifdef EXIT_DSO_BUILD
static void (*observer)(int);
struct Item {
    int id;
    ~Item() { if (observer) observer(id); }
};
static Item first{1}, second{2};
extern "C" void exit_ticket_observer(void (*callback)(int)) { observer = callback; }
#else
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); _Exit(1); } } while(0)
static int calls;
static void observe(int id) { CHECK(id == (calls % 2 ? 1 : 2)); ++calls; }
static void finished() { CHECK(calls == 202); printf("PASS exit-dso\n"); }
int main(int argc, char **argv) {
    CHECK(argc == 3);
    void *host = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL); CHECK(host);
    auto open = reinterpret_cast<void *(*)(const char *, int)>(dlsym(host,"dlopen"));
    auto close = reinterpret_cast<int (*)(void *)>(dlsym(host,"dlclose"));
    auto symbol = reinterpret_cast<void *(*)(void *,const char *)>(dlsym(host,"dlsym"));
    auto quit = reinterpret_cast<void (*)(int)>(dlsym(!strcmp(argv[2],"host") ? host : RTLD_DEFAULT,"exit"));
    CHECK(open && close && symbol && quit);
    const char *path = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (path) {
        Dl_info info; struct stat a,b;
        CHECK(dladdr(dlsym(RTLD_DEFAULT,"__cxa_atexit"), &info));
        CHECK(stat(path,&a) == 0 && stat(info.dli_fname,&b) == 0);
        CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
    }
    CHECK(atexit(finished) == 0);
    for (int i = 0; i <= 100; ++i) {
        void *dso = open(argv[1],RTLD_NOW | RTLD_LOCAL); CHECK(dso);
        auto set = reinterpret_cast<void (*)(void (*)(int))>(symbol(dso,"exit_ticket_observer"));
        CHECK(set); set(observe);
        if (i < 100) { CHECK(close(dso) == 0); CHECK(calls == 2*(i+1)); }
    }
    // The last DSO remains loaded: its destructors precede the main handler.
    // Tickets from the 100 earlier unloads must never access unmapped code or
    // accidentally claim a new registration at a reused DSO/argument address.
    quit(23); CHECK(0);
}
#endif
