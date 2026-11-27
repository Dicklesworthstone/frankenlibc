/* Execute real compat directives through independently pinned providers.
 * The runner supplies private /etc files and an NSS account module. No file
 * in the host identity database is changed by this fixture. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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
  const char *names[] = {"root", "local", "fltest1", "fltest2", "+", "-fltest2", "absent"};
  const char *groups[] = {"root", "local", "fltestgrp", "fltestgrp2", "fltestmany", "+", "absent"};
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
  const unsigned ids[] = {0, 4201, 4202, 4301, 4302, 4303, 9001, 9999};
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

int main(int argc, char **argv) {
  if (argc != 3) return 90;
  int host = !strcmp(argv[1], "host");
  void *gnu = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  Dl_info gnu_info;
  if (!gnu || !dladdr(dlsym(gnu, "getpwnam"), &gnu_info)) return 91;
  int module = !strcmp(argv[2], "module") || !strcmp(argv[2], "unavailable");
  void *provider = host ? gnu : dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!provider || (!host && same_object(argv[1], dlsym(gnu, "getpwnam")))) return 91;
  const char *path = host ? gnu_info.dli_fname : argv[1];
  if (host && module) {
    provider = dlopen("libnss_compat.so.2", RTLD_NOW | RTLD_LOCAL);
    Dl_info compat_info;
    if (!provider || !dladdr(dlsym(provider, "_nss_compat_getpwnam_r"), &compat_info)) return 91;
    path = compat_info.dli_fname;
  }
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (module) module_calls(provider, path, !strcmp(argv[2], "unavailable"));
  else {
    load_public(provider, path);
    if (!strcmp(argv[2], "lookup")) lookups();
    else if (!strcmp(argv[2], "enumeration")) enumeration();
    else if (!strcmp(argv[2], "groups")) supplementary_groups();
    else if (!strcmp(argv[2], "provider")) puts(path);
    else return 90;
  }
  return 0;
}
