/* realloc inside a signal handler of memory allocated before the signal.
 *
 * Not async-signal-safe by POSIX, but glibc does it whenever the handler did
 * not interrupt malloc itself, and real programs rely on it: perl's
 * POSIX::SigAction handlers (unsafe dispatch) grow arrays from the handler.
 * fl routes every allocation inside a handler through its lock-free bump heap
 * and could not size a hardened-arena block there, so realloc returned NULL
 * and perl died with "Out of memory in perl:util:safesysrealloc"
 * (ext/POSIX/t/sigaction.t, hardened mode). Output matches glibc.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* volatile: the handler changes them behind main's back. */
static char *volatile buf;
static volatile size_t len = 64;
static volatile sig_atomic_t grown;

static void handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig;
    (void)info;
    (void)ctx;
    for (int i = 0; i < 6; i++) {
        size_t next = len * 4;
        char *p = realloc(buf, next);
        if (p == NULL) {
            return;
        }
        memset(p + len, 'a' + i, next - len);
        buf = p;
        len = next;
        grown++;
    }
    char *tmp = malloc(100);
    if (tmp) {
        strcpy(tmp, "handler malloc");
        free(tmp);
    }
}

int main(void) {
    buf = malloc(len);
    if (buf == NULL) {
        return 1;
    }
    memset(buf, 'x', len);
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGHUP, &sa, NULL);
    raise(SIGHUP);
    unsigned long sum = 0;
    for (size_t i = 0; i < len; i++) {
        sum += (unsigned char)buf[i];
    }
    printf("grown=%d len=%zu first=%c last=%c sum=%lu\n", (int)grown, len, buf[0],
           buf[len - 1], sum);
    buf = realloc(buf, len * 2);
    printf("after=%s\n", buf ? "ok" : "null");
    free(buf);
    return 0;
}
