// fork and spawn from a multithreaded parent while other threads are inside
// malloc/free and stdio (bd-rc0923-epic-eeuy4f.5). A lock another thread holds
// at the instant of the clone must not stay held in the child. Output must be
// byte-identical under host glibc and FrankenLibC.
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;
static volatile int stop;

static void *malloc_storm(void *arg) {
  (void)arg;
  while (!stop) {
    void *p[64];
    for (int i = 0; i < 64; i++) p[i] = malloc(16 + i * 37);
    for (int i = 0; i < 64; i++) free(p[i]);
  }
  return NULL;
}

static void *stdio_storm(void *arg) {
  (void)arg;
  while (!stop) {
    FILE *f = fopen("/dev/null", "w");
    if (f) {
      fprintf(f, "%d %s %f\n", 42, "abc", 3.5);
      fclose(f);
    }
  }
  return NULL;
}

static int child_ok(pid_t p) {
  int st = 0;
  waitpid(p, &st, 0);
  return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

int main(void) {
  pthread_t t[4];
  pthread_create(&t[0], NULL, malloc_storm, NULL);
  pthread_create(&t[1], NULL, malloc_storm, NULL);
  pthread_create(&t[2], NULL, stdio_storm, NULL);
  pthread_create(&t[3], NULL, stdio_storm, NULL);

  const int n = 100;
  int ok = 0;
  for (int i = 0; i < n; i++) {
    pid_t p = fork();
    if (p == 0) {
      alarm(10);
      char *b = malloc(1000);
      memset(b, 1, 1000);
      char buf[64];
      snprintf(buf, sizeof buf, "%d %s", i, "child");
      FILE *f = fopen("/dev/null", "w");
      if (!f) _exit(2);
      fprintf(f, "%s\n", buf);
      fclose(f);
      free(b);
      _exit(0);
    }
    ok += child_ok(p);
  }
  printf("fork: child malloc+snprintf+stdio ok %d/%d\n", ok, n);

  ok = 0;
  for (int i = 0; i < n; i++) {
    int fds[2];
    if (pipe2(fds, O_CLOEXEC) != 0) break;
    pid_t p = fork();
    if (p == 0) {
      alarm(10);
      dup2(fds[1], 1);
      execl("/bin/echo", "echo", "exec", (char *)NULL);
      _exit(127);
    }
    close(fds[1]);
    char out[16] = {0};
    ssize_t r = read(fds[0], out, sizeof out - 1);
    close(fds[0]);
    ok += child_ok(p) && r == 5 && strcmp(out, "exec\n") == 0;
  }
  printf("fork+pipe2+exec ok %d/%d\n", ok, n);

  ok = 0;
  for (int i = 0; i < 20; i++) {
    FILE *pp = popen("echo popen", "r");
    char out[16] = {0};
    if (pp && fgets(out, sizeof out, pp) && strcmp(out, "popen\n") == 0 && pclose(pp) == 0) ok++;
  }
  printf("popen ok %d/20\n", ok);

  ok = 0;
  for (int i = 0; i < 20; i++) ok += system("exit 0") == 0;
  printf("system ok %d/20\n", ok);

  ok = 0;
  for (int i = 0; i < 20; i++) {
    pid_t p;
    char *argv[] = {"true", NULL};
    if (posix_spawn(&p, "/bin/true", NULL, NULL, argv, environ) == 0) ok += child_ok(p);
  }
  printf("posix_spawn ok %d/20\n", ok);

  stop = 1;
  for (int i = 0; i < 4; i++) pthread_join(t[i], NULL);
  return 0;
}
