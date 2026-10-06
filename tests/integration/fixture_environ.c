/* fixture_environ.c — environment semantics programs rely on (2026-09-28):
 * putenv aliasing, setenv overwrite rules and EINVAL, a program-supplied
 * environ array (duplicate keys, setenv into it must COPY not realloc it,
 * exec'd children see the result), in-place entry mutation, and clearenv
 * setting environ to NULL, and env -i's assign-then-putenv-then-exec.
 * Byte-identical to glibc, strict and hardened.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void show(const char *label, const char *name) {
    const char *v = getenv(name);
    printf("%-34s getenv(%s)=%s\n", label, name, v ? v : "(null)");
}

static int count_env(const char *prefix) {
    int n = 0;
    for (char **e = environ; e && *e; e++) if (strncmp(*e, prefix, strlen(prefix)) == 0) n++;
    return n;
}

int main(void) {
    static char pe[] = "FLP_A=one";
    putenv(pe);
    show("putenv", "FLP_A");
    pe[6] = 'X';
    show("putenv string mutated", "FLP_A");
    setenv("FLP_A", "two", 0);
    show("setenv no-overwrite", "FLP_A");
    setenv("FLP_A", "three", 1);
    show("setenv overwrite", "FLP_A");
    printf("pe after overwrite: %s\n", pe);
    int rc;
    errno = 0;
    rc = setenv("A=B", "x", 1);
    printf("setenv bad name '=': %d errno=%d\n", rc, errno);
    errno = 0;
    rc = setenv("", "x", 1);
    printf("setenv empty name: %d errno=%d\n", rc, errno);
    errno = 0;
    rc = unsetenv("A=B");
    printf("unsetenv '=' name: %d errno=%d\n", rc, errno);
    printf("putenv without '=' (unset): %d\n", putenv((char *)"FLP_A"));
    show("after putenv(name)", "FLP_A");

    static char *dup_env[] = {"FLP_D=1", "PATH=/usr/bin:/bin", "FLP_D=2", NULL};
    char **saved = environ;
    environ = dup_env;
    show("environ replaced (dup keys)", "FLP_D");
    unsetenv("FLP_D");
    printf("after unsetenv dups remaining=%d\n", count_env("FLP_D="));
    setenv("FLP_E", "e", 1);
    show("setenv into replaced environ", "FLP_E");
    printf("environ still dup_env: %d\n", environ == dup_env);
    fflush(stdout);
    pid_t c = fork();
    if (c == 0) {
        char *argv[] = {"/bin/sh", "-c", "echo child sees FLP_E=$FLP_E FLP_D=${FLP_D-unset}", NULL};
        execv("/bin/sh", argv);
        _exit(127);
    }
    waitpid(c, NULL, 0);

    environ = saved;
    static char mutable_entry[] = "FLP_M=before";
    static char *arr[] = {mutable_entry, "PATH=/usr/bin:/bin", NULL};
    environ = arr;
    show("direct environ array", "FLP_M");
    mutable_entry[6] = 'B';
    show("entry mutated in place", "FLP_M");
    clearenv();
    printf("clearenv environ==NULL:%d\n", environ == NULL);
    show("after clearenv", "PATH");
    setenv("FLP_Z", "z", 1);
    show("setenv after clearenv", "FLP_Z");
    printf("secure_getenv(FLP_Z)=%s\n", secure_getenv("FLP_Z") ? secure_getenv("FLP_Z") : "(null)");

    /* coreutils `env -i NAME=VALUE cmd`: point environ at an empty array,
     * putenv into it (an inherited name and a new one), exec. fl kept
     * environ and __environ as separate variables, so the child got the old
     * environment plus the new names instead of exactly these two. */
    static char *empty_env[] = {NULL};
    environ = empty_env;
    putenv((char *)"PATH=/usr/bin:/bin");
    putenv((char *)"FLP_N=1");
    printf("after env -i pattern: %d entries\n", count_env(""));
    fflush(stdout);
    c = fork();
    if (c == 0) {
        char *argv[] = {"env", NULL};
        execvp("env", argv);
        _exit(127);
    }
    waitpid(c, NULL, 0);
    return 0;
}
