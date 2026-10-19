#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ucontext.h>

#define CHECK(x) do { if (!(x)) { dprintf(2,"FAIL %d: %s\n",__LINE__,#x); _Exit(1); } } while(0)
typedef int (*cxa_fn)(void (*)(void *),void *,void *);
typedef void (*finalize_fn)(void *);
typedef int (*on_fn)(void (*)(int,void *),void *);
static cxa_fn reg;
static finalize_fn fin;
static void (*quit)(int);
static int tag_a,tag_b;
static const char *expected;
static char output[64];
static unsigned count;
static int nested_exit;
static void emit(char c) { CHECK(count < sizeof(output)-1); output[count++] = c; }
static void context_done(void) { emit('X'); }
static void last(void) {
    CHECK(!strcmp(output,expected));
    /* Deliberately buffered: host termination must flush owned stdio. */
    printf("PASS exit-tickets\n");
}
static void letter(void *p) { emit((char)(uintptr_t)p); }
static void with_status(int status,void *p) { CHECK(status==23); letter(p); }
static void insert(void *p) { letter(p); CHECK(reg(letter,(void *)(uintptr_t)'N',&tag_a)==0); }
static void recursive(void *p) { letter(p); fin(&tag_a); }
static void reexit(void *p) { letter(p); if (!nested_exit++) quit(23); }
static void verify_provider(void *symbol) {
    const char *p=getenv("FRANKENLIBC_TEST_LIBRARY"); if(!p) return;
    Dl_info info;struct stat a,b;
    CHECK(dladdr(symbol,&info)&&stat(p,&a)==0&&stat(info.dli_fname,&b)==0);
    CHECK(a.st_dev==b.st_dev&&a.st_ino==b.st_ino);
}
int main(int argc,char **argv) {
    CHECK(argc==3);
    void *host=dlopen("libc.so.6",RTLD_NOW|RTLD_LOCAL);CHECK(host);
    reg=(cxa_fn)dlsym(RTLD_DEFAULT,"__cxa_atexit");
    fin=(finalize_fn)dlsym(RTLD_DEFAULT,"__cxa_finalize");
    on_fn on=(on_fn)dlsym(RTLD_DEFAULT,"on_exit");
    quit=(void (*)(int))dlsym(!strcmp(argv[2],"host")?host:RTLD_DEFAULT,"exit");
    CHECK(reg&&fin&&on&&quit);
    verify_provider((void *)reg);verify_provider((void *)fin);verify_provider((void *)on);
    CHECK(atexit(last)==0);
    const char *kind=argv[1];
    if(!strcmp(kind,"order")) {
        expected="DBCA";
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_a)==0);
        CHECK(on(with_status,(void *)(uintptr_t)'C')==0);
        CHECK(reg(letter,(void *)(uintptr_t)'B',&tag_b)==0);
        CHECK(reg(letter,(void *)(uintptr_t)'D',&tag_a)==0);
    } else if(!strcmp(kind,"reentrant")) {
        expected="BNA";
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_a)==0);
        CHECK(reg(insert,(void *)(uintptr_t)'B',&tag_a)==0);
    } else if(!strcmp(kind,"finalize")) {
        expected="BCDA";
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_b)==0);
        CHECK(reg(letter,(void *)(uintptr_t)'C',&tag_a)==0);
        CHECK(reg(letter,(void *)(uintptr_t)'B',&tag_a)==0);
        fin(&tag_a);fin(&tag_a);
        emit('D');
    } else if(!strcmp(kind,"recursive-finalize")) {
        expected="BAC";
        CHECK(reg(letter,(void *)(uintptr_t)'C',&tag_b)==0);
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_a)==0);
        CHECK(reg(recursive,(void *)(uintptr_t)'B',&tag_a)==0);
        fin(&tag_a);
    } else if(!strcmp(kind,"register-finalize")) {
        expected="BNAC";
        CHECK(reg(letter,(void *)(uintptr_t)'C',&tag_b)==0);
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_a)==0);
        CHECK(reg(insert,(void *)(uintptr_t)'B',&tag_a)==0);
        fin(&tag_a);
    } else if(!strcmp(kind,"recursive-exit")) {
        expected="BA";
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_a)==0);
        CHECK(reg(reexit,(void *)(uintptr_t)'B',&tag_a)==0);
    } else if(!strcmp(kind,"context-null")) {
        CHECK(!strcmp(argv[2],"host"));
        expected="X";
        ucontext_t context;
        int (*get)(ucontext_t *)=(int (*)(ucontext_t *))dlsym(host,"getcontext");
        void (*make)(ucontext_t *,void (*)(void),int,...) =
            (void (*)(ucontext_t *,void (*)(void),int,...))dlsym(host,"makecontext");
        int (*set)(const ucontext_t *)=(int (*)(const ucontext_t *))dlsym(host,"setcontext");
        CHECK(get&&make&&set&&get(&context)==0);
        context.uc_stack.ss_sp=malloc(65536);CHECK(context.uc_stack.ss_sp);
        context.uc_stack.ss_size=65536;context.uc_link=NULL;
        make(&context,context_done,0);
        set(&context);CHECK(0);
    } else if(!strcmp(kind,"mixed-order")) {
        CHECK(!strcmp(argv[2],"host"));
        expected="CBA";
        on_fn hon=(on_fn)dlsym(host,"on_exit");CHECK(hon);
        CHECK(reg(letter,(void *)(uintptr_t)'A',&tag_a)==0);
        CHECK(hon(with_status,(void *)(uintptr_t)'B')==0);
        CHECK(reg(letter,(void *)(uintptr_t)'C',&tag_a)==0);
    } else { CHECK(0); }
    quit(23);CHECK(0);
}
