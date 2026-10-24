#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const size_t sizes[] = {1,16,17,31,64,96,128,192,256,384,512,768,
    1024,1536,2048,3072,4096,6144,8192,12288,16384,24576,32768};
static unsigned long checks;
static void require(int ok, const char *what) {
    if (!ok) { fprintf(stderr, "segment mapping regression: %s\n", what); exit(1); }
    checks++;
}
static unsigned long vmdata(void) {
    char line[256]; unsigned long value = 0;
    FILE *f = fopen("/proc/self/status", "r");
    require(f != NULL, "open status");
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "VmData: %lu kB", &value) == 1) break;
    }
    fclose(f); require(value != 0, "read VmData"); return value;
}
static void *thread_alloc(void *argument) {
    unsigned char **blocks = argument;
    for (size_t i = 0; i < 256; ++i) {
        size_t n = sizes[i % (sizeof sizes / sizeof *sizes)];
        blocks[i] = malloc(n);
        if (!blocks[i]) return (void *)1;
        memset(blocks[i], (int)(i % 251), n);
    }
    return NULL;
}
int main(void) {
    unsigned long before = vmdata();
    for (size_t s = 0; s < sizeof sizes / sizeof *sizes; ++s) {
        const size_t n = sizes[s];
        unsigned char *blocks[96];
        for (size_t i = 0; i < 96; ++i) {
            blocks[i] = calloc(1, n); require(blocks[i] != NULL, "calloc");
            for (size_t j = 0; j < n; ++j) require(blocks[i][j] == 0, "fresh/recycled calloc zero");
            memset(blocks[i], 0x5a, n);
        }
        for (size_t i = 0; i < 96; ++i) {
            unsigned char *grown = realloc(blocks[i], n * 2);
            require(grown != NULL, "realloc growth");
            for (size_t j = 0; j < n; ++j) require(grown[j] == 0x5a, "realloc preserves payload");
            free(grown);
        }
        unsigned char *zero = calloc(1, n); require(zero != NULL, "recycled calloc");
        for (size_t j = 0; j < n; ++j) require(zero[j] == 0, "recycled bytes cleared");
        free(zero);
    }
    pthread_t threads[8]; unsigned char *blocks[8][256] = {{0}};
    for (size_t t = 0; t < 8; ++t) require(pthread_create(&threads[t], NULL, thread_alloc, blocks[t]) == 0, "pthread_create");
    for (size_t t = 0; t < 8; ++t) {
        void *result;
        require(pthread_join(threads[t], &result) == 0 && !result, "thread allocation");
        for (size_t i = 0; i < 256; ++i) {
            size_t n = sizes[i % (sizeof sizes / sizeof *sizes)];
            for (size_t j = 0; j < n; ++j) require(blocks[t][i][j] == i % 251, "cross-thread contents");
            free(blocks[t][i]);
        }
    }
    pid_t child = fork(); require(child >= 0, "fork");
    if (!child) {
        unsigned char *p = calloc(1, 32768);
        if (!p) _exit(2);
        for (size_t j = 0; j < 32768; ++j) if (p[j]) _exit(3);
        memset(p, 0x7c, 32768); free(p); _exit(0);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "child allocator");
    errno = 0;
    volatile size_t impossible = SIZE_MAX;
    require(calloc(impossible, 2) == NULL && errno == ENOMEM, "overflow ENOMEM");
    unsigned long after = vmdata();
    printf("{\"before_kib\":%lu,\"after_kib\":%lu,\"checks\":%lu}\n", before, after, checks);
    return 0;
}
