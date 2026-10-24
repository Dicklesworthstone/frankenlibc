#define _GNU_SOURCE
#include <pthread.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* posix_spawn in one thread while another thread fork()s children that stay
   alive for a while. A spawn must not wait for those unrelated children: fl's
   spawn once reported exec failure through an O_CLOEXEC pipe whose write end
   the concurrent fork children inherited, so the parent's EOF waited ~300 ms
   for each of them (bd-vgvlej; glibc and fixed fl: ~1 ms). Also checks that a
   failed exec still reports ENOENT. */
extern char **environ;
static atomic_int stop;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

static void *forker(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        pid_t p = fork();
        if (p == 0) {
            usleep(300000); /* holds every fd the parent had at fork time */
            _exit(0);
        }
        if (p > 0) waitpid(p, NULL, 0);
    }
    return NULL;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, forker, NULL);
    double worst = 0;
    int failed = 0;
    for (int i = 0; i < 200; i++) {
        char *argv[] = {"/bin/true", NULL};
        pid_t pid;
        double t0 = now();
        int rc = posix_spawn(&pid, "/bin/true", NULL, NULL, argv, environ);
        double dt = now() - t0;
        if (rc != 0) failed++;
        else waitpid(pid, NULL, 0);
        if (dt > worst) worst = dt;
    }
    char *argv[] = {"/nonexistent", NULL};
    pid_t pid;
    int enoent = posix_spawn(&pid, "/nonexistent/prog", NULL, NULL, argv, environ);
    atomic_store(&stop, 1);
    pthread_join(t, NULL);
    printf("failed=%d slow_spawns=%s enoent_reported=%d\n", failed, worst > 0.2 ? "yes" : "no",
           enoent == 2);
    return 0;
}
