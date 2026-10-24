/* A pthread key destructor that calls string functions on heap memory.
 *
 * fl runs key destructors of host-created threads from a thread-exit callback,
 * after the thread's Rust thread-locals may already be destroyed. OpenSSL's
 * per-thread cleanup does exactly this (OPENSSL_sk_delete -> memmove), and in
 * hardened mode the memmove's pointer validation touched a destroyed
 * thread-local and aborted the process ("cannot access a Thread Local Storage
 * value during or after destruction"). Python's ssl threads hit it.
 *
 * Build with -fno-builtin so memmove is a real call into libc.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_key_t key;

static void key_dtor(void *p) {
    memmove((char *)p + 8, p, 4000);
    free(p);
    char *s = strdup("late");
    free(s);
}

static void *worker(void *arg) {
    (void)arg;
    pthread_setspecific(key, malloc(4096));
    /* Validation after the key value is stored: its thread-local state is
     * created after the key's exit callback is registered, so it is torn
     * down first. */
    char *w = malloc(4096);
    memset(w, 0, 4096);
    memmove(w + 8, w, 4000);
    free(w);
    return NULL;
}

int main(void) {
    if (pthread_key_create(&key, key_dtor) != 0) {
        return 1;
    }
    for (int i = 0; i < 64; i++) {
        pthread_t t;
        if (pthread_create(&t, NULL, worker, NULL) != 0 || pthread_join(t, NULL) != 0) {
            return 1;
        }
    }
    puts("ok");
    return 0;
}
