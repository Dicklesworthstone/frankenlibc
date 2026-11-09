#ifdef EXIT_DSO_BUILD
#include <pthread.h>
#include <stdlib.h>
static void (*observer)(int);
struct Item {
    int id;
    ~Item() { if (observer) observer(id); }
};
static Item first{1}, second{2};
static void fork_prepare() { if (observer) observer(3); }
static void fork_parent() { if (observer) observer(4); }
static void fork_child() { if (observer) observer(5); }
__attribute__((constructor)) static void register_fork_handlers() {
    if (pthread_atfork(fork_prepare, fork_parent, fork_child) != 0) abort();
}
extern "C" void exit_ticket_observer(void (*callback)(int)) { observer = callback; }
#else
#define _GNU_SOURCE 1
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); _Exit(1); } } while(0)
static int calls;
static void observe(int id) { CHECK(id == (calls % 2 ? 1 : 2)); ++calls; }
static void finished() { CHECK(calls == 202); printf("PASS exit-dso\n"); }
static char fork_events[16];
static unsigned fork_count;
static void *close_during_prepare;
static int (*close_plugin)(void *);
static void fork_observe(int id) {
    if (id < 3) return; // C++ destruction is checked by the existing mode.
    CHECK(fork_count < sizeof(fork_events)-1);
    fork_events[fork_count++] = static_cast<char>('0'+id);
}
static void process_prepare() {
    fork_observe(6);
    if (close_during_prepare) {
        void *dso=close_during_prepare; close_during_prepare=nullptr;
        CHECK(close_plugin(dso)==0);
    }
}
static void process_parent() { fork_observe(7); }
static void process_child() { fork_observe(8); }
static void fork_check(const char *parent, const char *child) {
    memset(fork_events,0,sizeof(fork_events)); fork_count=0;
    pid_t pid=fork(); CHECK(pid >= 0);
    if (pid == 0) _exit(strcmp(fork_events,child) ? 10 : 0);
    int status=0; CHECK(waitpid(pid,&status,0)==pid);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status)==0);
    CHECK(!strcmp(fork_events,parent));
}
int main(int argc, char **argv) {
    CHECK(argc == 3 || (argc == 4 && !strcmp(argv[3],"atfork")));
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
        if (argc == 4) {
            CHECK(dladdr(dlsym(RTLD_DEFAULT,"__register_atfork"), &info));
            CHECK(stat(info.dli_fname,&b) == 0);
            CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
            CHECK(dladdr(dlsym(RTLD_DEFAULT,"fork"), &info));
            CHECK(stat(info.dli_fname,&b) == 0);
            CHECK(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
        }
    }
    if (argc == 4) {
        using register_fn = int (*)(void (*)(void),void (*)(void),void (*)(void),void *);
        auto reg=reinterpret_cast<register_fn>(dlsym(RTLD_DEFAULT,"__register_atfork"));
        CHECK(reg && reg(process_prepare,process_parent,process_child,nullptr)==0);
        close_plugin=close;
        for (int i=0;i<4;++i) {
            void *dso=open(argv[1],RTLD_NOW | RTLD_LOCAL); CHECK(dso);
            auto set=reinterpret_cast<void (*)(void (*)(int))>(symbol(dso,"exit_ticket_observer"));
            CHECK(set); set(fork_observe);
            fork_check("3674","3685");
            if (i & 1) {
                // The plugin's prepare has already run when the older process
                // callback unloads it. Its captured parent/child callbacks
                // must be suppressed within this same fork operation.
                close_during_prepare=dso;
                fork_check("367","368");
                CHECK(close_during_prepare==nullptr);
            } else {
                CHECK(close(dso)==0);
            }
            // The actual DSO has been unloaded. Any retained plugin callback
            // now jumps into unmapped code; surviving NULL-token callbacks
            // must keep their original ordering on both sides of fork.
            fork_check("67","68");
        }
        auto finalize=reinterpret_cast<void (*)(void *)>(dlsym(RTLD_DEFAULT,"__cxa_finalize"));
        CHECK(finalize);
        finalize(nullptr);
        fork_check("67","68");
        printf("PASS atfork-dso\n");
        return 0;
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
