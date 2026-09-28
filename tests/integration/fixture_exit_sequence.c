/* fixture_exit_sequence.c — the glibc exit sequence, on return from main and
 * on an explicit exit(): every atexit / on_exit / __cxa_atexit handler in one
 * reverse-registration order (atexit is a __cxa_atexit call since glibc 2.34),
 * on_exit handlers receive the status, and destructor functions run AFTER the
 * handlers (_dl_fini is glibc's first-registered exit function). fl used to
 * skip every __cxa_atexit handler and destructor on exit(), drop on_exit
 * handlers when main returned, and run destructors before the handlers.
 * Output must be byte-identical to glibc in strict and hardened modes.
 */
#include <stdio.h>
#include <stdlib.h>

static void a(void) { printf("atexit a\n"); }
static void b(void) { printf("atexit b\n"); }
static void on(int st, void *arg) { printf("on_exit status=%d arg=%s\n", st, (const char *)arg); }
__attribute__((destructor)) static void dtor(void) { printf("destructor\n"); }

int main(int argc, char **argv) {
    (void)argv;
    atexit(a);
    on_exit(on, "x");
    atexit(b);
    printf("main %s\n", argc > 1 ? "calls exit(7)" : "returns 5");
    if (argc > 1) exit(7);
    return 5;
}
