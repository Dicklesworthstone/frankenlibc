/* Threads doing flockfile(stdout); putc; putc; funlockfile(stdout) while the
 * main thread keeps writing. fl's flockfile blocked on the stream lock while
 * holding its stream-registry lock, and a thread already holding that stream
 * lock needed the registry lock for its next putc: every thread hung, spinning
 * in flockfile. stdout goes to a temporary file and the fixture prints how
 * many of each byte arrived, so the output is deterministic; alarm() turns a
 * hang into a failed run. Must match glibc in strict and hardened. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void *worker(void *arg) {
    int id = (int)(long)arg;
    for (int i = 0; i < 2000; i++) {
        flockfile(stdout);
        putc('A' + id, stdout);
        putc('\n', stdout);
        funlockfile(stdout);
    }
    return NULL;
}

int main(void) {
    alarm(20);
    FILE *tmp = tmpfile();
    if (!tmp)
        return 77;
    fflush(stdout);
    int saved = dup(1);
    dup2(fileno(tmp), 1);
    pthread_t t[4];
    for (long i = 0; i < 4; i++)
        pthread_create(&t[i], NULL, worker, (void *)i);
    for (int i = 0; i < 2000; i++) {
        putc('m', stdout);
        putc('\n', stdout);
    }
    for (int i = 0; i < 4; i++)
        pthread_join(t[i], NULL);
    fflush(stdout);
    dup2(saved, 1);
    close(saved);

    long counts[256] = {0};
    rewind(tmp);
    for (int c; (c = getc(tmp)) != EOF;)
        counts[c]++;
    for (int c = 0; c < 256; c++)
        if (counts[c])
            printf("%d %ld\n", c, counts[c]);
    return 0;
}
