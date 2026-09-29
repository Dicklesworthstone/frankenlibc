// realpath/canonicalize_file_name of /proc/self/fd links whose target is not a
// path: a pipe or socket ("pipe:[N]", "socket:[N]") or an unlinked file
// ("/x (deleted)"). glibc walks the components, reads that text as a relative
// link under /proc/<pid>/fd, and fails with ENOENT.
//
// fl resolved through readlink(/proc/self/fd/N) and returned "pipe:[N]" as the
// canonical name of /dev/stdin; coreutils tail, which canonicalizes its input,
// then failed with "cannot open 'standard input'" -- every `... | tail -1`.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char dir[64];

// Report success paths relative to the fixture directory, so the output is stable.
static void show(const char *label, const char *path) {
    char buf[PATH_MAX];
    errno = 0;
    char *r = realpath(path, buf);
    int e = errno;
    char *c = canonicalize_file_name(path);
    const char *shown = r;
    if (r && strncmp(r, dir, strlen(dir)) == 0) shown = r + strlen(dir);
    printf("%-22s realpath=%s%s canonicalize=%s\n", label, r ? "" : "NULL ", r ? shown : strerrorname_np(e),
           c ? "match" : "NULL");
    if (c && r && strcmp(c, r) != 0) printf("  canonicalize differs: %s\n", c);
    free(c);
}

static void fd_case(const char *label, int fd) {
    char p[64];
    snprintf(p, sizeof p, "/proc/self/fd/%d", fd);
    show(label, p);
}

int main(void) {
    snprintf(dir, sizeof dir, "/tmp/fl_realpath_%d", (int)getpid());
    mkdir(dir, 0755);
    char path[128];
    snprintf(path, sizeof path, "%s/file", dir);
    int f = open(path, O_CREAT | O_RDWR, 0644);
    char link[128];
    snprintf(link, sizeof link, "%s/link", dir);
    symlink(path, link);

    fd_case("regular file fd", f);
    show("symlink", link);
    unlink(path);
    fd_case("unlinked file fd", f);
    show("dangling symlink", link);
    unlink(link);

    int p[2];
    pipe(p);
    fd_case("pipe read end", p[0]);
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
    fd_case("socket", sv[0]);

    // stdin as a pipe, then the pipeline pattern that broke: `... | tail -1`.
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        dup2(p[0], 0);
        close(p[1]);
        show("/dev/stdin (pipe)", "/dev/stdin");
        show("/dev/fd/0 (pipe)", "/dev/fd/0");
        fflush(stdout);
        execlp("tail", "tail", "-n", "1", (char *)NULL);
        _exit(127);
    }
    close(p[0]);
    write(p[1], "one\ntwo\nthree\n", 14);
    close(p[1]);
    int st;
    waitpid(pid, &st, 0);
    printf("tail exit %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    close(f);
    rmdir(dir);
    return 0;
}
