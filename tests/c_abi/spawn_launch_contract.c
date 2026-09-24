#define _GNU_SOURCE
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/* Original black-box regression tests; no libc implementation source copied.
 * Run as an ordinary executable for a reference, then under LD_PRELOAD.
 * A child is always reaped even when the implementation unexpectedly succeeds.
 */
extern char **environ;
static char self[PATH_MAX], scratch[PATH_MAX];
static int tests, failures, skips;

static int wait_child(pid_t pid) {
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) return 255;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : 254;
}
static void record(const char *name, int okay) {
    ++tests;
    if (!okay) ++failures;
    printf("%s %s\n", okay ? "PASS" : "FAIL", name);
    fflush(stdout);
}
static void skip(const char *name) {
    ++skips;
    printf("SKIP %s\n", name);
    fflush(stdout);
}
static void fatal(const char *what) {
    perror(what);
    exit(2);
}
static void join(char *out, size_t capacity, const char *dir, const char *name) {
    int n = snprintf(out, capacity, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= capacity) { errno = ENAMETOOLONG; fatal("join"); }
}
static int spawn_expect(const char *path, int search, posix_spawn_file_actions_t *fa,
                        posix_spawnattr_t *attr, char *const argv[], char *const envp[],
                        int wanted_error, int wanted_exit) {
    pid_t pid = -4242;
    int rc = search ? posix_spawnp(&pid, path, fa, attr, argv, envp)
                    : posix_spawn(&pid, path, fa, attr, argv, envp);
    if (rc == 0) {
        int status = wait_child(pid);
        return wanted_error == 0 && status == wanted_exit;
    }
    return rc == wanted_error && pid == -4242;
}
static void init_actions(posix_spawn_file_actions_t *fa) {
    int rc = posix_spawn_file_actions_init(fa);
    if (rc) { errno = rc; fatal("file_actions_init"); }
}
static void init_attrs(posix_spawnattr_t *attr) {
    int rc = posix_spawnattr_init(attr);
    if (rc) { errno = rc; fatal("spawnattr_init"); }
}
static int child_mode(int argc, char **argv) {
    if (argc < 3) return 90;
    if (!strcmp(argv[2], "fd") && argc == 4) {
        int flags = fcntl(atoi(argv[3]), F_GETFD);
        return flags >= 0 && !(flags & FD_CLOEXEC) ? 0 : 91;
    }
    if (!strcmp(argv[2], "mask") && argc == 5) {
        sigset_t set;
        if (sigprocmask(SIG_SETMASK, NULL, &set) != 0) return 92;
        return sigismember(&set, atoi(argv[3])) == atoi(argv[4]) ? 0 : 93;
    }
    if (!strcmp(argv[2], "default") && argc == 4) {
        struct sigaction action;
        if (sigaction(atoi(argv[3]), NULL, &action) != 0) return 94;
        return action.sa_handler == SIG_DFL ? 0 : 95;
    }
    if (!strcmp(argv[2], "ids") && argc == 5) {
        uid_t uid = (uid_t)strtoul(argv[3], NULL, 10);
        gid_t gid = (gid_t)strtoul(argv[4], NULL, 10);
        return getuid() == uid && geteuid() == uid && getgid() == gid && getegid() == gid ? 0 : 96;
    }
    if (!strcmp(argv[2], "environment")) {
        const char *value = getenv("SPAWN_LAUNCH_MARKER");
        const char *path = getenv("PATH");
        return value && !strcmp(value, "child-only") && path && !strcmp(path, "/no-child-search-path") ? 0 : 97;
    }
    if (!strcmp(argv[2], "okay")) return 0;
    return 98;
}
static void descriptors(void) {
    char missing[PATH_MAX];
    join(missing, sizeof missing, scratch, "missing-program");
    char *okay[] = {self, "--child", "okay", NULL};
    posix_spawn_file_actions_t fa;
    init_actions(&fa);
    if (posix_spawn_file_actions_addclosefrom_np(&fa, 0)) fatal("addclosefrom");
    record("closefrom(0) preserves exec failure reporting",
           spawn_expect(missing, 0, &fa, NULL, okay, environ, ENOENT, 0));
    posix_spawn_file_actions_destroy(&fa);

    init_actions(&fa);
    if (posix_spawn_file_actions_addclosefrom_np(&fa, 3) ||
        posix_spawn_file_actions_addchdir_np(&fa, missing)) fatal("addchdir");
    record("closefrom preserves subsequent action errors",
           spawn_expect(self, 0, &fa, NULL, okay, environ, ENOENT, 0));
    posix_spawn_file_actions_destroy(&fa);

    /* Determine holes immediately before spawning. Allocating an actions
     * object must not create fds. Native spawn used to reuse these holes as
     * the error pipe, exposing them as if the caller had opened them. */
    int hole[2];
    init_actions(&fa);
    if (pipe2(hole, O_CLOEXEC)) fatal("pipe2");
    close(hole[0]); close(hole[1]);
    if (posix_spawn_file_actions_addopen(&fa, hole[1], "/dev/null", O_WRONLY, 0)) fatal("addopen");
    record("open cannot overwrite the private error channel",
           spawn_expect(missing, 0, &fa, NULL, okay, environ, ENOENT, 0));
    posix_spawn_file_actions_destroy(&fa);

    init_actions(&fa);
    if (pipe2(hole, O_CLOEXEC)) fatal("pipe2");
    close(hole[0]); close(hole[1]);
    if (posix_spawn_file_actions_adddup2(&fa, hole[1], STDOUT_FILENO)) fatal("adddup2");
    record("private pipe cannot validate an invalid dup2 source",
           spawn_expect(self, 0, &fa, NULL, okay, environ, EBADF, 0));
    posix_spawn_file_actions_destroy(&fa);

    init_actions(&fa);
    if (pipe2(hole, O_CLOEXEC)) fatal("pipe2");
    close(hole[0]); close(hole[1]);
    if (posix_spawn_file_actions_addclose(&fa, hole[1])) fatal("addclose");
    record("close cannot suppress a later exec error",
           spawn_expect(missing, 0, &fa, NULL, okay, environ, ENOENT, 0));
    record("closing an already-closed in-range fd is harmless",
           spawn_expect(self, 0, &fa, NULL, okay, environ, 0, 0));
    posix_spawn_file_actions_destroy(&fa);

    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fatal("open /dev/null");
    char number[32];
    snprintf(number, sizeof number, "%d", fd);
    char *fd_argv[] = {self, "--child", "fd", number, NULL};
    init_actions(&fa);
    if (posix_spawn_file_actions_adddup2(&fa, fd, fd)) fatal("adddup2 self");
    record("dup2(fd, fd) explicitly clears CLOEXEC",
           spawn_expect(self, 0, &fa, NULL, fd_argv, environ, 0, 0));
    record("spawn does not clear CLOEXEC in the parent", (fcntl(fd, F_GETFD) & FD_CLOEXEC) != 0);
    posix_spawn_file_actions_destroy(&fa);
    close(fd);

    int no_zombies = 1;
    for (int i = 0; i < 32; ++i)
        if (!spawn_expect(missing, 0, NULL, NULL, okay, environ, ENOENT, 0)) no_zombies = 0;
    int status;
    errno = 0;
    pid_t leftover = waitpid(-1, &status, WNOHANG);
    record("failed spawns are reaped and leave no zombies", no_zombies && leftover == -1 && errno == ECHILD);
}
static void write_file(const char *path, mode_t mode) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
    if (fd < 0) fatal("create fixture");
    const char text[] = "exit 0\n"; /* Deliberately no shebang: ENOEXEC, not a script fallback. */
    if (write(fd, text, sizeof text - 1) != (ssize_t)(sizeof text - 1) || fchmod(fd, mode)) fatal("write fixture");
    close(fd);
}
static void search_contract(void) {
    char *saved_path = getenv("PATH") ? strdup(getenv("PATH")) : NULL;
    char executable[PATH_MAX];
    join(executable, sizeof executable, scratch, "spawn-contract-program");
    if (symlink(self, executable) || setenv("PATH", scratch, 1)) fatal("search fixture");
    char *envp[] = {"PATH=/no-child-search-path", "SPAWN_LAUNCH_MARKER=child-only", NULL};
    char *args[] = {"spawn-contract-program", "--child", "environment", NULL};
    record("spawnp searches parent PATH but installs child envp",
           spawn_expect("spawn-contract-program", 1, NULL, NULL, args, envp, 0, 0));
    record("empty spawnp file name returns ENOENT",
           spawn_expect("", 1, NULL, NULL, args, environ, ENOENT, 0));
    unlink(executable);

    char non_directory[PATH_MAX], nested[PATH_MAX];
    join(non_directory, sizeof non_directory, scratch, "ordinary-file");
    write_file(non_directory, 0600);
    join(nested, sizeof nested, non_directory, "program");
    record("direct spawn preserves ENOTDIR",
           spawn_expect(nested, 0, NULL, NULL, args, environ, ENOTDIR, 0));
    record("spawnp with slash preserves ENOTDIR",
           spawn_expect(nested, 1, NULL, NULL, args, environ, ENOTDIR, 0));
    unlink(non_directory);

    char first[PATH_MAX], second[PATH_MAX], first_file[PATH_MAX], second_file[PATH_MAX];
    join(first, sizeof first, scratch, "first");
    join(second, sizeof second, scratch, "second");
    if (mkdir(first, 0700) || mkdir(second, 0700)) fatal("mkdir search fixture");
    join(first_file, sizeof first_file, first, "candidate");
    join(second_file, sizeof second_file, second, "candidate");
    write_file(first_file, 0600);
    write_file(second_file, 0700);
    char path[2 * PATH_MAX + 2];
    snprintf(path, sizeof path, "%s:%s", first, second);
    if (setenv("PATH", path, 1)) fatal("setenv PATH");
    char *bad_args[] = {"candidate", NULL};
    record("terminal ENOEXEC outranks earlier PATH EACCES",
           spawn_expect("candidate", 1, NULL, NULL, bad_args, environ, ENOEXEC, 0));
    unlink(second_file);
    record("exhausted PATH retains EACCES over ENOENT",
           spawn_expect("candidate", 1, NULL, NULL, bad_args, environ, EACCES, 0));
    unlink(first_file); rmdir(first); rmdir(second);
    if (saved_path) { setenv("PATH", saved_path, 1); free(saved_path); }
    else unsetenv("PATH");
}
static void signal_contract(void) {
    posix_spawnattr_t attr;
    init_attrs(&attr);
    sigset_t mask, readback;
    sigemptyset(&mask); sigaddset(&mask, SIGRTMAX);
    if (posix_spawnattr_setsigmask(&attr, &mask) || posix_spawnattr_getsigmask(&attr, &readback)) fatal("sigmask attribute");
    record("spawn signal mask round-trips SIGRTMAX", sigismember(&readback, SIGRTMAX) == 1);
    if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK)) fatal("setflags");
    char rt[32]; snprintf(rt, sizeof rt, "%d", SIGRTMAX);
    char *args[] = {self, "--child", "mask", rt, "1", NULL};
    record("spawn child receives blocked SIGRTMAX", spawn_expect(self, 0, NULL, &attr, args, environ, 0, 0));

    struct sigaction ignored = {0}, saved;
    ignored.sa_handler = SIG_IGN; sigemptyset(&ignored.sa_mask);
    if (sigaction(SIGRTMAX, &ignored, &saved)) fatal("sigaction ignore");
    if (posix_spawnattr_setsigdefault(&attr, &mask) || posix_spawnattr_getsigdefault(&attr, &readback)) fatal("sigdefault attribute");
    record("spawn default set round-trips SIGRTMAX", sigismember(&readback, SIGRTMAX) == 1);
    if (posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF)) fatal("setflags default");
    char *defaults[] = {self, "--child", "default", rt, NULL};
    record("SETSIGDEF resets ignored SIGRTMAX", spawn_expect(self, 0, NULL, &attr, defaults, environ, 0, 0));
    if (sigaction(SIGRTMAX, &saved, NULL)) fatal("restore sigaction");

    sigfillset(&mask);
    if (posix_spawnattr_setsigdefault(&attr, &mask)) fatal("sigfillset attribute");
    char *okay[] = {self, "--child", "okay", NULL};
    record("SETSIGDEF tolerates SIGKILL and SIGSTOP in set",
           spawn_expect(self, 0, NULL, &attr, okay, environ, 0, 0));

    sigset_t original, blocked, after;
    sigemptyset(&blocked); sigaddset(&blocked, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &blocked, &original)) fatal("parent sigprocmask");
    sigemptyset(&mask); sigaddset(&mask, SIGUSR1);
    posix_spawnattr_setsigmask(&attr, &mask);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK);
    int good = spawn_expect(self, 0, NULL, &attr, okay, environ, 0, 0);
    char missing[PATH_MAX]; join(missing, sizeof missing, scratch, "missing-program");
    good &= spawn_expect(missing, 0, NULL, &attr, okay, environ, ENOENT, 0);
    if (sigprocmask(SIG_SETMASK, NULL, &after)) fatal("read parent sigprocmask");
    for (int s = 1; s <= SIGRTMAX; ++s) {
        int wanted = s == SIGUSR2 ? 1 : sigismember(&original, s);
        if (sigismember(&after, s) != wanted) good = 0;
    }
    record("spawn restores parent mask on success and exec failure", good);
    if (sigprocmask(SIG_SETMASK, &original, NULL)) fatal("restore parent sigprocmask");
    posix_spawnattr_destroy(&attr);
}
static void resetids_contract(void) {
    if (getuid() != 0 || geteuid() != 0) { skip("RESETIDS differing real/effective IDs (requires root)"); return; }
    /* The checkout may live below a 0700 home directory. Copy this test's
     * executable into our own public-traversable temporary directory so an
     * EACCES from directory traversal is not mistaken for a RESETIDS defect. */
    char helper[PATH_MAX];
    join(helper, sizeof helper, scratch, "credential-probe");
    int input = open(self, O_RDONLY | O_CLOEXEC);
    int output = open(helper, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0755);
    if (input < 0 || output < 0) fatal("copy credential helper");
    char buffer[4096];
    for (;;) {
        ssize_t n = read(input, buffer, sizeof buffer);
        if (n == 0) break;
        if (n < 0) { if (errno == EINTR) continue; fatal("read helper"); }
        ssize_t written = 0;
        while (written < n) {
            ssize_t count = write(output, buffer + written, (size_t)(n - written));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) fatal("write helper");
            written += count;
        }
    }
    close(input);
    if (fchmod(output, 0755)) fatal("chmod helper");
    close(output);
    if (chmod(scratch, 0755)) fatal("chmod credential directory");
    char *sanity[] = {helper, "--child", "okay", NULL};
    if (!spawn_expect(helper, 0, NULL, NULL, sanity, environ, 0, 0)) {
        skip("RESETIDS credential helper cannot execute in temporary filesystem");
        unlink(helper); chmod(scratch, 0700); return;
    }
    fflush(NULL);
    pid_t isolated = fork();
    if (isolated < 0) fatal("fork credential fixture");
    if (isolated == 0) {
        if (setresgid(12345, 0, 0) || setresuid(12345, 0, 0)) _exit(77);
        posix_spawnattr_t attr;
        if (posix_spawnattr_init(&attr) || posix_spawnattr_setflags(&attr, POSIX_SPAWN_RESETIDS)) _exit(2);
        char *args[] = {helper, "--child", "ids", "12345", "12345", NULL};
        int good = spawn_expect(helper, 0, NULL, &attr, args, environ, 0, 0);
        posix_spawnattr_destroy(&attr);
        _exit(good ? 0 : 1);
    }
    int result = wait_child(isolated);
    unlink(helper);
    chmod(scratch, 0700);
    if (result == 77) skip("RESETIDS differing real/effective IDs (namespace lacks capabilities)");
    else record("RESETIDS drops effective IDs to real IDs before exec", result == 0);
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--child")) return child_mode(argc, argv);
    int only_descriptors = argc == 2 && !strcmp(argv[1], "--descriptors");
    if (argc > 1 && !only_descriptors) { fprintf(stderr, "usage: %s [--descriptors]\n", argv[0]); return 2; }
    ssize_t n = readlink("/proc/self/exe", self, sizeof self - 1);
    if (n < 0 || (size_t)n >= sizeof self - 1) fatal("readlink self");
    self[n] = 0;
    strcpy(scratch, "/tmp/frankenlibc-spawn-contract-XXXXXX");
    if (!mkdtemp(scratch)) fatal("mkdtemp");
    alarm(40); /* A broken error channel must fail, not hang the test lane. */
    descriptors();
    if (!only_descriptors) { search_contract(); signal_contract(); resetids_contract(); }
    alarm(0);
    if (rmdir(scratch)) fatal("rmdir fixture");
    printf("SUMMARY tests=%d failed=%d skipped=%d\n", tests, failures, skips);
    return failures ? 1 : 0;
}
