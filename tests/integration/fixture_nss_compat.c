/* Execute real compat directives through independently pinned providers.
 * The runner supplies private /etc files and an NSS account module. No file
 * in the host identity database is changed by this fixture. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stddef.h>
#include <pwd.h>
#include <shadow.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int same_object(const char *path, void *symbol) {
  Dl_info info;
  struct stat expected, actual;
  return dladdr(symbol, &info) && info.dli_fname && !stat(path, &expected) &&
         !stat(info.dli_fname, &actual) && expected.st_dev == actual.st_dev &&
         expected.st_ino == actual.st_ino;
}

static void *symbol(void *handle, const char *path, const char *name) {
  void *address = dlsym(handle, name);
  if (!address || !same_object(path, address)) {
    fprintf(stderr, "wrong provider for %s\n", name);
    exit(91);
  }
  return address;
}

/* These GLIBC_PRIVATE imports are part of the real installed compat module's
 * dependency chain. A component exporting only _nss_compat_* can accidentally
 * pass while every private callback still comes from GNU libc. Require the
 * candidate definitions, then check global ownership in a preload subject.
 * The runner separately records the dynamic loader's actual module bindings. */
static const char *private_imports[] = {
  "__nss_files_fopen", "__nss_database_get", "__nss_lookup_function",
  "__internal_setnetgrent", "__internal_getnetgrent_r", "__internal_endnetgrent"
};

static void check_private_provider(void *provider, const char *path) {
  for (size_t i = 0; i < sizeof private_imports / sizeof *private_imports; ++i) {
    (void)symbol(provider, path, private_imports[i]);
    if (getenv("FLTEST_COMPAT_REQUIRE_INTERPOSITION") &&
        !same_object(path, dlsym(RTLD_DEFAULT, private_imports[i]))) {
      fprintf(stderr, "private import was not interposed: %s\n", private_imports[i]);
      exit(91);
    }
  }
}

static const char *string(const char *text) { return text ? text : "(null)"; }
static void passwd_value(const struct passwd *entry) {
  if (!entry) { puts("NULL"); return; }
  printf("%s:%s:%u:%u:%s:%s:%s\n", string(entry->pw_name), string(entry->pw_passwd),
         (unsigned)entry->pw_uid, (unsigned)entry->pw_gid, string(entry->pw_gecos),
         string(entry->pw_dir), string(entry->pw_shell));
}
static void group_value(const struct group *entry) {
  if (!entry) { puts("NULL"); return; }
  printf("%s:%s:%u:", string(entry->gr_name), string(entry->gr_passwd),
         (unsigned)entry->gr_gid);
  for (char **member = entry->gr_mem; member && *member; ++member)
    printf("%s%s", member == entry->gr_mem ? "" : ",", *member);
  putchar('\n');
}
static void shadow_value(const struct spwd *entry) {
  if (!entry) { puts("NULL"); return; }
  printf("%s:%s:%ld:%ld:%ld:%ld:%ld:%ld:%lu\n", string(entry->sp_namp),
         string(entry->sp_pwdp), entry->sp_lstchg, entry->sp_min, entry->sp_max,
         entry->sp_warn, entry->sp_inact, entry->sp_expire, entry->sp_flag);
}

#define LOAD(field, name) *(void **)(&api.field) = symbol(provider, path, name)
static struct {
  int *(*error)(void);
  struct passwd *(*pwname)(const char *);
  struct passwd *(*pwuid)(uid_t);
  struct group *(*grname)(const char *);
  struct group *(*grgid)(gid_t);
  struct spwd *(*spname)(const char *);
  int (*pwname_r)(const char *, struct passwd *, char *, size_t, struct passwd **);
  int (*grname_r)(const char *, struct group *, char *, size_t, struct group **);
  int (*spname_r)(const char *, struct spwd *, char *, size_t, struct spwd **);
  void (*pwset)(void), (*pwend)(void), (*grset)(void), (*grend)(void);
  void (*spset)(void), (*spend)(void);
  struct passwd *(*pwent)(void);
  struct group *(*grent)(void);
  struct spwd *(*spent)(void);
  int (*pwent_r)(struct passwd *, char *, size_t, struct passwd **);
  int (*grent_r)(struct group *, char *, size_t, struct group **);
  int (*spent_r)(struct spwd *, char *, size_t, struct spwd **);
  int (*groups)(const char *, gid_t, gid_t *, int *);
} api;

static void load_public(void *provider, const char *path) {
  LOAD(error, "__errno_location");
  LOAD(pwname, "getpwnam"); LOAD(pwuid, "getpwuid");
  LOAD(grname, "getgrnam"); LOAD(grgid, "getgrgid"); LOAD(spname, "getspnam");
  LOAD(pwname_r, "getpwnam_r"); LOAD(grname_r, "getgrnam_r"); LOAD(spname_r, "getspnam_r");
  LOAD(pwset, "setpwent"); LOAD(pwend, "endpwent"); LOAD(pwent, "getpwent");
  LOAD(grset, "setgrent"); LOAD(grend, "endgrent"); LOAD(grent, "getgrent");
  LOAD(spset, "setspent"); LOAD(spend, "endspent"); LOAD(spent, "getspent");
  LOAD(pwent_r, "getpwent_r"); LOAD(grent_r, "getgrent_r"); LOAD(spent_r, "getspent_r");
  LOAD(groups, "getgrouplist");
}

static void lookups(void) {
  const char *names[] = {"root", "local", "fltest1", "fltest2", "+", "-fltest2", "absent", "after"};
  const char *groups[] = {"root", "local", "fltestgrp", "fltestgrp2", "fltestmany", "+", "absent", "after"};
  for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
    *api.error() = 731;
    struct passwd *pw = api.pwname(names[i]);
    printf("pw %s errno=%d ", names[i], *api.error()); passwd_value(pw);
    *api.error() = 731;
    struct spwd *sp = api.spname(names[i]);
    printf("sp %s errno=%d ", names[i], *api.error()); shadow_value(sp);
    *api.error() = 731;
    struct group *gr = api.grname(groups[i]);
    printf("gr %s errno=%d ", groups[i], *api.error()); group_value(gr);
  }
  const unsigned ids[] = {0, 4201, 4202, 4301, 4302, 4303, 9001, 9002, 9999};
  for (size_t i = 0; i < sizeof ids / sizeof *ids; ++i) {
    *api.error() = 731;
    struct passwd *pw = api.pwuid(ids[i]);
    printf("uid %u errno=%d ", ids[i], *api.error()); passwd_value(pw);
    *api.error() = 731;
    struct group *gr = api.grgid(ids[i]);
    printf("gid %u errno=%d ", ids[i], *api.error()); group_value(gr);
  }
  const size_t capacities[] = {0, 1, 8, 64, 4096};
  for (size_t i = 0; i < sizeof capacities / sizeof *capacities; ++i) {
    size_t capacity = capacities[i];
    char buffer[4098];
    struct passwd pw, *pwr = (void *)1;
    struct group gr, *grr = (void *)1;
    struct spwd sp, *spr = (void *)1;
#define CHECKED_LOOKUP(tag, call, result, display) do { \
    memset(buffer, 0x5a, sizeof buffer); *api.error() = 731; \
    int rc = (call); \
    if (buffer[0] != 0x5a || buffer[capacity + 1] != 0x5a) exit(92); \
    if ((result) && (result) != &(tag)) exit(92); \
    printf(#tag "_r capacity=%zu rc=%d errno=%d ", capacity, rc, *api.error()); \
    display(result); \
  } while (0)
    CHECKED_LOOKUP(pw, api.pwname_r("fltest1", &pw, buffer + 1, capacity, &pwr), pwr, passwd_value);
    CHECKED_LOOKUP(gr, api.grname_r("fltestgrp", &gr, buffer + 1, capacity, &grr), grr, group_value);
    CHECKED_LOOKUP(sp, api.spname_r("fltest1", &sp, buffer + 1, capacity, &spr), spr, shadow_value);
#undef CHECKED_LOOKUP
  }
}

static void enumeration(void) {
  char buffer[4098];
#define ENUMERATE(tag, type, display) do { \
    api.tag##set(); \
    for (unsigned count = 0;; ++count) { \
      if (count == 32) exit(93); \
      struct type value, *result = (void *)1; \
      *api.error() = 731; \
      int rc = api.tag##ent_r(&value, buffer + 1, 1, &result); \
      printf(#tag " small rc=%d errno=%d result=%d\n", rc, *api.error(), result != NULL); \
      if (rc == ERANGE) { \
        *api.error() = 731; \
        rc = api.tag##ent_r(&value, buffer + 1, sizeof buffer - 2, &result); \
        printf(#tag " retry rc=%d errno=%d ", rc, *api.error()); display(result); \
      } \
      if (rc || !result) break; \
    } \
    api.tag##end(); api.tag##set(); \
    printf(#tag " rewind "); display(api.tag##ent()); \
    struct type value, *result = NULL; \
    int rc = api.tag##ent_r(&value, buffer + 1, sizeof buffer - 2, &result); \
    printf(#tag " mixed rc=%d ", rc); display(result); \
    api.tag##end(); \
  } while (0)
  ENUMERATE(pw, passwd, passwd_value);
  ENUMERATE(gr, group, group_value);
  ENUMERATE(sp, spwd, shadow_value);
#undef ENUMERATE
}

static void supplementary_groups(void) {
  const char *users[] = {"fltest1", "fltest2", "local", "absent"};
  for (unsigned user = 0; user < 4; ++user) {
    for (int capacity = 1; capacity <= 16; capacity *= 4) {
      gid_t groups[16];
      for (int i = 0; i < 16; ++i) groups[i] = 0x5a5a5a5a;
      int count = capacity;
      *api.error() = 731;
      int rc = api.groups(users[user], 4301, groups, &count);
      printf("groups %s capacity=%d rc=%d count=%d errno=%d:", users[user], capacity,
             rc, count, *api.error());
      for (int i = 0; i < count && i < capacity; ++i) printf(" %u", (unsigned)groups[i]);
      putchar('\n');
      for (int i = capacity; i < 16; ++i) if (groups[i] != 0x5a5a5a5a) exit(92);
    }
  }
}

static void module_calls(void *provider, const char *path, int unavailable) {
  char buffer[4096];
  int error;
#define MODULE_DB(tag, type, display, key) do { \
    int (*begin)(int); int (*end)(void); \
    int (*next)(struct type *, char *, size_t, int *); \
    int (*lookup)(const char *, struct type *, char *, size_t, int *); \
    *(void **)(&begin) = symbol(provider, path, "_nss_compat_set" #tag "ent"); \
    *(void **)(&end) = symbol(provider, path, "_nss_compat_end" #tag "ent"); \
    *(void **)(&next) = symbol(provider, path, "_nss_compat_get" #tag "ent_r"); \
    *(void **)(&lookup) = symbol(provider, path, "_nss_compat_get" #tag "nam_r"); \
    int rc = begin(0); \
    if (unavailable && rc != -1) exit(94); \
    printf("module " #tag " set=%d\n", rc); \
    for (unsigned count = 0;; ++count) { \
      if (count == 32) exit(93); \
      struct type entry; error = 731; \
      rc = next(&entry, buffer, sizeof buffer, &error); \
      if (unavailable && (rc != -1 || error != ENOSYS)) exit(94); \
      printf("module " #tag " next=%d error=%d ", rc, error); \
      display(rc == 1 ? &entry : NULL); \
      if (rc != 1) break; \
    } \
    rc = end(); \
    if (unavailable && rc != -1) exit(94); \
    printf("module " #tag " end=%d\n", rc); \
    for (size_t capacity = 1; capacity <= sizeof buffer; capacity *= 64) { \
      struct type entry; error = 731; \
      rc = lookup(key, &entry, buffer, capacity, &error); \
      if (unavailable && (rc != -1 || error != ENOSYS)) exit(94); \
      printf("module " #tag " name capacity=%zu rc=%d error=%d ", capacity, rc, error); \
      display(rc == 1 ? &entry : NULL); \
    } \
  } while (0)
  MODULE_DB(pw, passwd, passwd_value, "fltest1");
  MODULE_DB(gr, group, group_value, "fltestgrp");
  MODULE_DB(sp, spwd, shadow_value, "fltest1");
#undef MODULE_DB
  int (*byuid)(uid_t, struct passwd *, char *, size_t, int *);
  int (*bygid)(gid_t, struct group *, char *, size_t, int *);
  int (*groups)(const char *, gid_t, long *, long *, gid_t **, long, int *);
  *(void **)(&byuid) = symbol(provider, path, "_nss_compat_getpwuid_r");
  *(void **)(&bygid) = symbol(provider, path, "_nss_compat_getgrgid_r");
  *(void **)(&groups) = symbol(provider, path, "_nss_compat_initgroups_dyn");
  struct passwd pw; struct group gr;
  error = 731;
  int rc = byuid(4201, &pw, buffer, sizeof buffer, &error);
  if (unavailable && (rc != -1 || error != ENOSYS)) exit(94);
  printf("module uid=%d error=%d ", rc, error); passwd_value(rc == 1 ? &pw : NULL);
  error = 731;
  rc = bygid(4301, &gr, buffer, sizeof buffer, &error);
  if (unavailable && (rc != -1 || error != ENOSYS)) exit(94);
  printf("module gid=%d error=%d ", rc, error); group_value(rc == 1 ? &gr : NULL);
  long count = 1, size = 1;
  gid_t *gids = malloc(sizeof *gids);
  if (!gids) exit(95);
  gids[0] = 4301; error = 731;
  rc = groups("fltest1", 4301, &count, &size, &gids, 16, &error);
  if (unavailable && (rc != -1 || error != ENOSYS || count != 1 || size != 1)) exit(94);
  if (count < 0 || count > size || count > 16) exit(92);
  printf("module groups=%d error=%d count=%ld:", rc, error, count);
  for (long i = 0; i < count; ++i) printf(" %u", (unsigned)gids[i]);
  putchar('\n'); free(gids);
}

/* Native compat must preserve a record across repeated ERANGE responses, and
 * keyed calls must not disturb a live enumeration. The caller deliberately
 * supplies misaligned storage with canaries on both sides. GNU is executed in
 * a separate process with identical files and the same account backend. */
static void module_state(void *provider, const char *path) {
  char buffer[4098];
  const char *users[] = {"root", "local", "fltest1", "fltest2", "absent", "after"};
  const char *groups[] = {"root", "local", "fltestgrp", "fltestgrp2", "absent", "after"};
#define STATE_DB(tag, type, display, names) do { \
    int (*begin)(int); int (*end)(void); \
    int (*next)(struct type *, char *, size_t, int *); \
    int (*lookup)(const char *, struct type *, char *, size_t, int *); \
    *(void **)(&begin) = symbol(provider, path, "_nss_compat_set" #tag "ent"); \
    *(void **)(&end) = symbol(provider, path, "_nss_compat_end" #tag "ent"); \
    *(void **)(&next) = symbol(provider, path, "_nss_compat_get" #tag "ent_r"); \
    *(void **)(&lookup) = symbol(provider, path, "_nss_compat_get" #tag "nam_r"); \
    struct type entry; int error, rc; \
    for (size_t i = 0; i < sizeof(names) / sizeof *(names); ++i) { \
      memset(buffer, 0x5a, sizeof buffer); error = 619; \
      rc = lookup((names)[i], &entry, buffer + 1, 4096, &error); \
      if (buffer[0] != 0x5a || buffer[4097] != 0x5a) exit(92); \
      printf("state " #tag " name=%s rc=%d error=%d ", (names)[i], rc, error); \
      display(rc == 1 ? &entry : NULL); \
    } \
    printf("state " #tag " set=%d\n", begin(0)); \
    for (unsigned index = 0;; ++index) { \
      if (index == 32) exit(93); \
      for (unsigned attempt = 0; attempt < 2; ++attempt) { \
        memset(buffer, 0x5a, sizeof buffer); error = 619; \
        rc = next(&entry, buffer + 1, 1, &error); \
        if (buffer[0] != 0x5a || buffer[2] != 0x5a) exit(92); \
        printf("state " #tag " small=%u rc=%d error=%d\n", attempt, rc, error); \
        if (rc == 1) exit(92); \
      } \
      memset(buffer, 0x5a, sizeof buffer); error = 619; \
      rc = next(&entry, buffer + 1, 4096, &error); \
      if (buffer[0] != 0x5a || buffer[4097] != 0x5a) exit(92); \
      printf("state " #tag " next=%d error=%d ", rc, error); \
      display(rc == 1 ? &entry : NULL); \
      if (rc != 1) break; \
      if (index == 0) { \
        error = 619; rc = lookup((names)[3], &entry, buffer + 1, 4096, &error); \
        printf("state " #tag " interleaved=%d error=%d ", rc, error); \
        display(rc == 1 ? &entry : NULL); \
      } \
    } \
    rc = end(); \
    printf("state " #tag " end=%d reset=%d\n", rc, begin(0)); \
    error = 619; rc = next(&entry, buffer + 1, 4096, &error); \
    printf("state " #tag " restarted=%d error=%d ", rc, error); \
    display(rc == 1 ? &entry : NULL); \
    (void)end(); \
  } while (0)
  STATE_DB(pw, passwd, passwd_value, users);
  STATE_DB(gr, group, group_value, groups);
  STATE_DB(sp, spwd, shadow_value, users);
#undef STATE_DB

  /* Numeric compat lookups do not share the by-name directive algorithm.
   * Exercise unrelated later locals, selected-name mismatches, and exclusions
   * through the actual provider entry points even in a component proof. */
  int (*byuid)(uid_t, struct passwd *, char *, size_t, int *);
  int (*bygid)(gid_t, struct group *, char *, size_t, int *);
  *(void **)(&byuid) = symbol(provider, path, "_nss_compat_getpwuid_r");
  *(void **)(&bygid) = symbol(provider, path, "_nss_compat_getgrgid_r");
  const unsigned ids[] = {0, 4201, 4202, 4301, 4302, 4303, 9001, 9002, 9999};
  for (size_t index = 0; index < sizeof ids / sizeof *ids; ++index) {
    struct passwd pw; struct group gr;
    memset(buffer, 0x5a, sizeof buffer);
    int error = 619;
    int rc = byuid(ids[index], &pw, buffer + 1, 4096, &error);
    if (buffer[0] != 0x5a || buffer[4097] != 0x5a) exit(92);
    printf("state uid=%u rc=%d error=%d ", ids[index], rc, error);
    passwd_value(rc == 1 ? &pw : NULL);
    memset(buffer, 0x5a, sizeof buffer); error = 619;
    rc = bygid(ids[index], &gr, buffer + 1, 4096, &error);
    if (buffer[0] != 0x5a || buffer[4097] != 0x5a) exit(92);
    printf("state gid=%u rc=%d error=%d ", ids[index], rc, error);
    group_value(rc == 1 ? &gr : NULL);
  }

  int (*initgroups)(const char *, gid_t, long *, long *, gid_t **, long, int *);
  *(void **)(&initgroups) = symbol(provider, path, "_nss_compat_initgroups_dyn");
  const char *members[] = {"fltest1", "fltest2", "local", "absent"};
  const long limits[] = {1, 3, 16};
  for (size_t user = 0; user < sizeof members / sizeof *members; ++user) {
    for (size_t limit = 0; limit < sizeof limits / sizeof *limits; ++limit) {
      long count = 1, size = 1;
      gid_t *values = malloc(sizeof *values);
      if (!values) exit(95);
      values[0] = 4301;
      int error = 619;
      int rc = initgroups(members[user], 4301, &count, &size, &values, limits[limit], &error);
      if (count < 1 || count > size || count > limits[limit] || values[0] != 4301) exit(92);
      printf("state groups user=%s limit=%ld rc=%d error=%d count=%ld:",
             members[user], limits[limit], rc, error, count);
      for (long index = 0; index < count; ++index) printf(" %u", (unsigned)values[index]);
      putchar('\n'); free(values);
    }
  }
}

static void require_native_compat(void) {
  if (!getenv("FLTEST_COMPAT_REQUIRE_NATIVE")) return;
  FILE *maps = fopen("/proc/self/maps", "r");
  if (!maps) exit(98);
  char line[4096];
  while (fgets(line, sizeof line, maps)) {
    if (strstr(line, "libnss_compat.so")) {
      fputs("native compat loaded the GNU compat provider\n", stderr);
      fclose(maps); exit(98);
    }
  }
  if (ferror(maps) || fclose(maps)) exit(98);
}

/* The backend can require 4096 bytes of scratch even when its result is much
 * smaller. A compat provider must pass the real remaining caller capacity,
 * including bytes reserved for overrides; privately growing then squeezing
 * the result into a shorter caller buffer violates this NSS contract. */
static void module_budget(void *provider, const char *path, int retry) {
  char buffer[8194];
  const size_t capacities[] = {4095, 4096, 4104, 4105, 4124, 4125, 8192};
#define BUDGET_DB(tag, type, key, display) do { \
    int (*begin)(int); int (*end)(void); \
    int (*next)(struct type *, char *, size_t, int *); \
    int (*lookup)(const char *, struct type *, char *, size_t, int *); \
    *(void **)(&begin) = symbol(provider, path, "_nss_compat_set" #tag "ent"); \
    *(void **)(&end) = symbol(provider, path, "_nss_compat_end" #tag "ent"); \
    *(void **)(&next) = symbol(provider, path, "_nss_compat_get" #tag "ent_r"); \
    *(void **)(&lookup) = symbol(provider, path, "_nss_compat_get" #tag "nam_r"); \
    struct type entry; int rc, error; \
    if (!retry) { \
      for (size_t index = 0; index < sizeof capacities / sizeof *capacities; ++index) { \
      size_t capacity = capacities[index]; memset(buffer, 0x5a, sizeof buffer); error = 619; \
      rc = lookup(key, &entry, buffer + 1, capacity, &error); \
      if (buffer[0] != 0x5a || buffer[capacity + 1] != 0x5a) exit(92); \
      printf("budget " #tag " name capacity=%zu rc=%d error=%d ", capacity, rc, error); \
        display(rc == 1 ? &entry : NULL); \
      } \
      break; \
    } \
    if (begin(0) != 1) exit(96); \
    for (unsigned local = 0; local < 2; ++local) { \
      error = 619; rc = next(&entry, buffer + 1, 8192, &error); \
      printf("budget " #tag " local=%u rc=%d error=%d ", local, rc, error); \
      display(rc == 1 ? &entry : NULL); \
      if (rc != 1) exit(96); \
    } \
    for (size_t index = 0; index < sizeof capacities / sizeof *capacities; ++index) { \
      size_t capacity = capacities[index]; memset(buffer, 0x5a, sizeof buffer); error = 619; \
      rc = next(&entry, buffer + 1, capacity, &error); \
      if (buffer[0] != 0x5a || buffer[capacity + 1] != 0x5a) exit(92); \
      printf("budget " #tag " next capacity=%zu rc=%d error=%d ", capacity, rc, error); \
      display(rc == 1 ? &entry : NULL); \
      if (rc == 1) break; \
      if (rc != -2 || error != ERANGE) exit(96); \
    } \
    error = 619; rc = next(&entry, buffer + 1, 8192, &error); \
    printf("budget " #tag " following=%d error=%d ", rc, error); \
    display(rc == 1 ? &entry : NULL); \
    (void)end(); \
  } while (0)
  BUDGET_DB(pw, passwd, "fltest1", passwd_value);
  BUDGET_DB(gr, group, "fltestgrp", group_value);
  BUDGET_DB(sp, spwd, "fltest1", shadow_value);
#undef BUDGET_DB
  if (!retry) {
    /* GNU's passwd UID provider preserves preflight ERANGE but turns an
     * actual remote callback's non-success into NOTFOUND, retaining errnop.
     * The missing-provider case is independently covered by module-state. */
    int (*byuid)(uid_t, struct passwd *, char *, size_t, int *);
    *(void **)(&byuid) = symbol(provider, path, "_nss_compat_getpwuid_r");
    const size_t uid_capacities[] = {32, 64, 4095, 4096, 8192};
    for (size_t index = 0; index < sizeof uid_capacities / sizeof *uid_capacities; ++index) {
      size_t capacity = uid_capacities[index];
      struct passwd entry; int error = 619;
      memset(buffer, 0x5a, sizeof buffer);
      int rc = byuid(4201, &entry, buffer + 1, capacity, &error);
      if (buffer[0] != 0x5a || buffer[capacity + 1] != 0x5a) exit(92);
      printf("budget uid capacity=%zu rc=%d error=%d ", capacity, rc, error);
      passwd_value(rc == 1 ? &entry : NULL);
    }
  }
}

/* Attribution control for GNU compat's selected-account loss on ERANGE. The
 * same backend is called directly: a short lookup must not modify the result,
 * and a short enumeration must not consume its first remote record. */
static void backend_retry_control(void) {
  void *backend = dlopen("libnss_fltest.so.2", RTLD_NOW | RTLD_LOCAL);
  if (!backend) exit(91);
  char buffer[8192];
#define BACKEND_DB(tag, type, member, first, second, display) do { \
    int (*begin)(int); int (*end)(void); \
    int (*next)(struct type *, char *, size_t, int *); \
    int (*lookup)(const char *, struct type *, char *, size_t, int *); \
    *(void **)(&begin) = dlsym(backend, "_nss_fltest_set" #tag "ent"); \
    *(void **)(&end) = dlsym(backend, "_nss_fltest_end" #tag "ent"); \
    *(void **)(&next) = dlsym(backend, "_nss_fltest_get" #tag "ent_r"); \
    *(void **)(&lookup) = dlsym(backend, "_nss_fltest_get" #tag "nam_r"); \
    if (!begin || !end || !next || !lookup || begin(0) != 1) exit(91); \
    struct type entry, unchanged; memset(&unchanged, 0x5a, sizeof unchanged); \
    for (unsigned attempt = 0; attempt < 2; ++attempt) { \
      memcpy(&entry, &unchanged, sizeof entry); int error = 619; \
      int rc = lookup(first, &entry, buffer, 4095, &error); \
      if (rc != -2 || error != ERANGE || memcmp(&entry, &unchanged, sizeof entry)) exit(96); \
      printf("backend " #tag " keyed-short=%u rc=%d error=%d unchanged=1\n", attempt, rc, error); \
      error = 619; rc = next(&entry, buffer, 4095, &error); \
      if (rc != -2 || error != ERANGE || memcmp(&entry, &unchanged, sizeof entry)) exit(96); \
      printf("backend " #tag " enum-short=%u rc=%d error=%d unchanged=1\n", attempt, rc, error); \
    } \
    const char *expected[] = {first, second}; \
    for (unsigned index = 0; index < 2; ++index) { \
      int error = 619; int rc = next(&entry, buffer, sizeof buffer, &error); \
      if (rc != 1 || strcmp(entry.member, expected[index])) exit(96); \
      printf("backend " #tag " retained=%u ", index); display(&entry); \
    } \
    (void)end(); \
  } while (0)
  BACKEND_DB(pw, passwd, pw_name, "fltest1", "fltest2", passwd_value);
  BACKEND_DB(gr, group, gr_name, "fltestgrp", "fltestgrp2", group_value);
  BACKEND_DB(sp, spwd, sp_namp, "fltest1", "fltest2", shadow_value);
#undef BACKEND_DB
}

/* <nss.h> forward-declares GNU's private cursor. This independent declaration
 * is the same caller-owned module ABI already exercised by
 * fixture_nss_module_lib.c; no opaque list or cursor contents are interpreted.
 * Keeping two real objects alive catches wrappers that wrongly substitute the
 * public process-global netgroup iterator for these private operations. */
struct compat_netgroup_cursor {
  int type;
  union {
    struct { const char *host, *user, *domain; } triple;
    const char *group;
  } val;
  char *data;
  size_t data_size;
  union { char *cursor; unsigned long position; };
  int first;
  void *known_groups, *needed_groups, *nip;
};
#if UINTPTR_MAX == UINT64_MAX
_Static_assert(sizeof(struct compat_netgroup_cursor) == 88, "GNU netgroup cursor size");
_Static_assert(offsetof(struct compat_netgroup_cursor, data) == 32, "GNU netgroup data offset");
_Static_assert(offsetof(struct compat_netgroup_cursor, nip) == 80, "GNU netgroup service offset");
#endif

static void private_calls(void *provider, const char *path, void *gnu, const char *gnu_path) {
  FILE *(*files_open)(const char *);
  int (*netgroup_set)(const char *, struct compat_netgroup_cursor *);
  int (*netgroup_get)(char **, char **, char **, struct compat_netgroup_cursor *,
                      char *, size_t, int *);
  void (*netgroup_end)(struct compat_netgroup_cursor *);
  int *(*host_error)(void);
  int (*host_close)(FILE *), (*host_fileno)(FILE *);
  char *(*host_gets)(char *, int, FILE *);
  int (*host_getpos)(FILE *, fpos_t *), (*host_setpos)(FILE *, const fpos_t *);
#define PRIVATE_LOAD(field, name) *(void **)(&field) = symbol(provider, path, name)
#define HOST_LOAD(field, name) *(void **)(&field) = symbol(gnu, gnu_path, name)
  PRIVATE_LOAD(files_open, "__nss_files_fopen");
  PRIVATE_LOAD(netgroup_set, "__internal_setnetgrent");
  PRIVATE_LOAD(netgroup_get, "__internal_getnetgrent_r");
  PRIVATE_LOAD(netgroup_end, "__internal_endnetgrent");
  HOST_LOAD(host_error, "__errno_location");
  HOST_LOAD(host_close, "fclose"); HOST_LOAD(host_fileno, "fileno");
  HOST_LOAD(host_gets, "fgets_unlocked");
  HOST_LOAD(host_getpos, "fgetpos"); HOST_LOAD(host_setpos, "fsetpos");
#undef PRIVATE_LOAD
#undef HOST_LOAD

  /* The private opener must return a GNU-owned FILE. Consume it through
   * explicitly pinned GNU functions, as the real module does with its opaque
   * provider state; a native FILE masquerading as a host FILE is not accepted. */
  *host_error() = 731;
  FILE *file = files_open("/etc/passwd");
  printf("private fopen success=%d errno=%d\n", file != NULL, *host_error());
  if (!file) exit(96);
  int fd = host_fileno(file);
  int descriptor_flags = fcntl(fd, F_GETFD);
  int status_flags = fcntl(fd, F_GETFL);
  printf("private fopen cloexec=%d access=%d nonblock=%d\n",
         !!(descriptor_flags & FD_CLOEXEC), status_flags & O_ACCMODE,
         !!(status_flags & O_NONBLOCK));
  char line[512], repeated[512];
  if (!host_gets(line, sizeof line, file)) exit(96);
  printf("private fopen first=%s", line);
  fpos_t position;
  if (host_getpos(file, &position) || !host_gets(line, sizeof line, file) ||
      host_setpos(file, &position) || !host_gets(repeated, sizeof repeated, file) ||
      strcmp(line, repeated)) exit(96);
  printf("private fopen repeated=%s", repeated);
  printf("private fclose rc=%d\n", host_close(file));
  *host_error() = 731;
  file = files_open("/etc/no-such-compat-file");
  printf("private fopen missing=%d errno=%d\n", file == NULL, *host_error());
  if (file) { host_close(file); exit(96); }

  struct compat_netgroup_cursor first = {0}, second = {0};
  *host_error() = 731;
  int rc = netgroup_set("allow-parent", &first);
  printf("private netgroup set first=%d errno=%d\n", rc, *host_error());
  if (!rc) exit(96);
  *host_error() = 731;
  rc = netgroup_set("block", &second);
  printf("private netgroup set second=%d errno=%d\n", rc, *host_error());
  if (!rc) exit(96);
  char buffer[4098];
  char *host, *user, *domain;
  int error;
#define PRIVATE_NEXT(label, cursor, capacity) do { \
    memset(buffer, 0x5a, sizeof buffer); \
    host = user = domain = NULL; error = 619; *host_error() = 731; \
    rc = netgroup_get(&host, &user, &domain, cursor, buffer + 1, capacity, &error); \
    if (buffer[0] != 0x5a || buffer[(capacity) + 1] != 0x5a) exit(92); \
    printf("private netgroup " label " rc=%d errno=%d error=%d", rc, *host_error(), error); \
    if (rc) printf(" (%s,%s,%s)", string(host), string(user), string(domain)); \
    putchar('\n'); \
  } while (0)
  PRIVATE_NEXT("small", &first, 1);
  PRIVATE_NEXT("retry", &first, 4096);
  PRIVATE_NEXT("independent", &second, 4096);
  for (unsigned count = 0; count < 8; ++count) {
    PRIVATE_NEXT("nested", &first, 4096);
    if (!rc) break;
    if (count == 7) exit(93);
  }
  netgroup_end(&first);
  netgroup_end(&second);
  memset(&first, 0, sizeof first);
  *host_error() = 731;
  rc = netgroup_set("allow-parent", &first);
  printf("private netgroup reset=%d errno=%d\n", rc, *host_error());
  PRIVATE_NEXT("reset-first", &first, 4096);
  netgroup_end(&first);
  memset(&first, 0, sizeof first);
  *host_error() = 731;
  rc = netgroup_set("missing-compat-netgroup", &first);
  printf("private netgroup missing=%d errno=%d\n", rc, *host_error());
  netgroup_end(&first);
#undef PRIVATE_NEXT
}

int main(int argc, char **argv) {
  if (argc != 3) return 90;
  int host = !strcmp(argv[1], "host");
  void *gnu = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  Dl_info gnu_info;
  if (!gnu || !dladdr(dlsym(gnu, "getpwnam"), &gnu_info)) return 91;
  int host_module = !strcmp(argv[2], "host-module");
  int state = !strcmp(argv[2], "module-state");
  int retry_budget = !strcmp(argv[2], "module-retry-budget");
  int budget = !strcmp(argv[2], "module-budget") || retry_budget;
  int module = !strcmp(argv[2], "module") || !strcmp(argv[2], "unavailable") ||
               host_module || state || budget;
  void *provider = host ? gnu : dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!provider || (!host && same_object(argv[1], dlsym(gnu, "getpwnam")))) return 91;
  const char *path = host ? gnu_info.dli_fname : argv[1];
  if (!host) check_private_provider(provider, path);
  if ((host && module) || host_module) {
    provider = dlopen("libnss_compat.so.2", RTLD_NOW | RTLD_LOCAL);
    Dl_info compat_info;
    if (!provider || !dladdr(dlsym(provider, "_nss_compat_getpwnam_r"), &compat_info)) return 91;
    path = compat_info.dli_fname;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (!strcmp(argv[2], "backend-retry")) backend_retry_control();
  else if (budget) module_budget(provider, path, retry_budget);
  else if (state) module_state(provider, path);
  else if (module) module_calls(provider, path, !strcmp(argv[2], "unavailable"));
  else if (!strcmp(argv[2], "private")) private_calls(provider, path, gnu, gnu_info.dli_fname);
  else {
    load_public(provider, path);
    if (!strcmp(argv[2], "lookup")) lookups();
    else if (!strcmp(argv[2], "enumeration")) enumeration();
    else if (!strcmp(argv[2], "groups")) supplementary_groups();
    else if (!strcmp(argv[2], "provider")) puts(path);
    else return 90;
  }
  require_native_compat();
  return 0;
}
