#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Black-box launch tests. Scripts only use shell builtins. No caller-provided
 * argument is interpreted as a command string. All fixtures are private. */
extern char **environ;
static char root[PATH_MAX], first[PATH_MAX], second[PATH_MAX];
static unsigned passed, failed;
static void die(const char *s) { perror(s); exit(2); }
static void join(char *out, const char *a, const char *b) {
    if (snprintf(out, PATH_MAX, "%s/%s", a, b) >= PATH_MAX) { errno = ENAMETOOLONG; die("join"); }
}
static void make_file(const char *dir, const char *name, const char *text, mode_t mode) {
    char path[PATH_MAX]; join(path, dir, name);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
    if (fd < 0) die("open fixture");
    size_t left = strlen(text); const char *p = text;
    while (left) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) die("write fixture");
        p += n; left -= (size_t)n;
    }
    if (fchmod(fd, mode) || close(fd)) die("finish fixture");
}
enum entry { VP, VPE, LP, VE, V, SPAWNP };
static const char *entry_name(enum entry e) {
    static const char *names[] = {"execvp", "execvpe", "execlp", "execve", "execv", "posix_spawnp"};
    return names[e];
}
static void check(const char *name, enum entry entry, const char *file,
                  const char *path, char *const args[], int empty_env,
                  int expected_status, const char *expected_text) {
    int pipefd[2]; if (pipe2(pipefd, O_CLOEXEC)) die("pipe2");
    fflush(NULL);
    pid_t pid = fork(); if (pid < 0) die("fork");
    if (!pid) {
        alarm(10);
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(120);
        close(pipefd[1]);
        if (chdir(first) || setenv("CHECK_MARKER", "parent", 1)) _exit(121);
        if (path ? setenv("PATH", path, 1) : unsetenv("PATH")) _exit(122);
        char *custom[] = {"CHECK_MARKER=child", "PATH=/not-the-search-path", NULL};
        char *none[] = {NULL};
        char *const *env = empty_env ? none : custom;
        switch (entry) {
        case VP: execvp(file, args); break;
        case VPE: execvpe(file, args, env); break;
        case LP: execlp(file, args[0], args[1], args[2], (char *)NULL); break;
        case VE: execve(file, args, env); break;
        case V: execv(file, args); break;
        case SPAWNP: {
            pid_t child = -1;
            int rc = posix_spawnp(&child, file, NULL, NULL, args, environ);
            if (!rc) { int status; while (waitpid(child, &status, 0) < 0 && errno == EINTR) {} _exit(123); }
            errno = rc; break;
        }
        }
        int error = errno;
        dprintf(STDOUT_FILENO, "error=%d\n", error);
        _exit(111);
    }
    close(pipefd[1]);
    char output[8192]; size_t used = 0;
    while (used < sizeof output - 1) {
        ssize_t n = read(pipefd[0], output + used, sizeof output - 1 - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) die("read output");
        if (!n) break;
        used += (size_t)n;
    }
    output[used] = 0; close(pipefd[0]);
    int status; while (waitpid(pid, &status, 0) < 0) { if (errno != EINTR) die("waitpid"); }
    int okay = WIFEXITED(status) && WEXITSTATUS(status) == expected_status && !strcmp(output, expected_text);
    if (okay) ++passed; else ++failed;
    printf("%s %s/%s\n", okay ? "PASS" : "FAIL", entry_name(entry), name);
    if (!okay) fprintf(stderr, "  status=%d expected=%d; output=[%s] expected=[%s]\n", status, expected_status, output, expected_text);
}
static void error_check(const char *name, enum entry e, const char *file, const char *path,
                        char *const args[], int wanted) {
    char output[64]; snprintf(output, sizeof output, "error=%d\n", wanted);
    check(name, e, file, path, args, 0, 111, output);
}
int main(void) {
    alarm(120);
    strcpy(root, "/tmp/frankenlibc-exec-XXXXXX"); if (!mkdtemp(root)) die("mkdtemp");
    join(first, root, "first"); join(second, root, "second");
    if (mkdir(first, 0700) || mkdir(second, 0700)) die("mkdir");
    const char text[] = "printf 'marker=%s argc=%s a1=<%s> a2=<%s> zero=<%s>\\n' \"${CHECK_MARKER-unset}\" \"$#\" \"$1\" \"$2\" \"$0\"\nexit 37\n";
    make_file(first, "plain", text, 0700);
    make_file(first, "denied", "exit 99\n", 0600);
    make_file(second, "denied", text, 0700);
    make_file(first, "stops", "exit 23\n", 0700);
    make_file(second, "stops", "exit 99\n", 0700);
    make_file(first, "shebang", "#!/bin/sh\nexit 47\n", 0700);
    make_file(first, "many", "[ \"$#\" -eq 4096 ] && exit 29\nexit 99\n", 0700);
    char plain[PATH_MAX], denied[PATH_MAX], nested[PATH_MAX];
    join(plain, first, "plain"); join(denied, first, "denied"); join(nested, plain, "child");
    char path[2 * PATH_MAX + 2]; snprintf(path, sizeof path, "%s:%s", first, second);
    char *args[] = {"caller-argv-zero", "one two", "$(printf INJECTED);*", NULL};
    char expected[PATH_MAX + 256];
    for (enum entry e = VP; e <= LP; ++e) {
        const char *marker = e == VPE ? "child" : "parent";
        snprintf(expected, sizeof expected, "marker=%s argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<%s>\n", marker, plain);
        check("text-via-PATH", e, "plain", first, args, 0, 37, expected);
        check("text-with-slash", e, plain, "/no-such-path", args, 0, 37, expected);
        snprintf(expected, sizeof expected, "marker=%s argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<plain>\n", marker);
        check("empty-PATH", e, "plain", "", args, 0, 37, expected);
        char with_empty[PATH_MAX + 32]; snprintf(with_empty, sizeof with_empty, "/absent:");
        check("trailing-empty-PATH", e, "plain", with_empty, args, 0, 37, expected);
        snprintf(expected, sizeof expected, "marker=%s argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<%s/denied>\n", marker, second);
        check("EACCES-then-script", e, "denied", path, args, 0, 37, expected);
        check("shell-is-terminal", e, "stops", path, args, 0, 23, "");
        check("kernel-shebang", e, "shebang", first, args, 0, 47, "");
        error_check("permission-is-not-shell-fallback", e, denied, first, args, EACCES);
        error_check("missing-name", e, "missing", first, args, ENOENT);
        error_check("empty-name", e, "", first, args, ENOENT);
        error_check("direct-ENOTDIR", e, nested, first, args, ENOTDIR);
    }
    snprintf(expected, sizeof expected, "marker=unset argc=2 a1=<one two> a2=<$(printf INJECTED);*> zero=<%s>\n", plain);
    check("empty-child-environment", VPE, "plain", first, args, 1, 37, expected);
    char *zero[] = {NULL};
    snprintf(expected, sizeof expected, "marker=child argc=0 a1=<> a2=<> zero=<%s>\n", plain);
    check("empty-argv", VPE, "plain", first, zero, 0, 37, expected);
    char *one[] = {"unused", NULL};
    check("argv-zero-only", VPE, "plain", first, one, 0, 37, expected);
    char **many = calloc(4098, sizeof *many); if (!many) die("calloc args");
    for (unsigned i = 0; i < 4097; ++i) many[i] = "value";
    check("large-shell-argument-vector", VPE, "many", first, many, 0, 29, "");
    free(many);
    error_check("raw-execve-no-fallback", VE, plain, first, args, ENOEXEC);
    error_check("raw-execv-no-fallback", V, plain, first, args, ENOEXEC);
    error_check("spawnp-no-fallback", SPAWNP, "plain", first, args, ENOEXEC);
    check("unset-PATH-default", VP, "true", NULL, one, 0, 0, "");
    check("unset-PATH-custom-env", VPE, "true", NULL, one, 0, 0, "");
    error_check("last-PATH-error", VP, "missing", plain, args, ENOTDIR);
    int busy = open(plain, O_WRONLY); if (busy < 0) die("busy fixture");
    error_check("ETXTBSY-no-shell", VP, "plain", first, args, ETXTBSY);
    close(busy);
    const char *names[] = {"plain", "denied", "stops", "shebang", "many"};
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; ++i) { char p[PATH_MAX]; join(p, first, names[i]); unlink(p); }
    const char *other[] = {"denied", "stops"};
    for (unsigned i = 0; i < 2; ++i) { char p[PATH_MAX]; join(p, second, other[i]); unlink(p); }
    rmdir(first); rmdir(second); rmdir(root);
    printf("SUMMARY passed=%u failed=%u\n", passed, failed);
    return failed ? 1 : 0;
}
