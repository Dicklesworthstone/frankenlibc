/* A minimal third-party NSS service module, built twice:
 *   -DSERVICE=fltest           libnss_fltest.so.2      (with initgroups_dyn)
 *   -DSERVICE=fltestnoig -DNO_INITGROUPS
 *                              libnss_fltestnoig.so.2  (group-enumeration fallback)
 *
 * It uses only the public NSS module ABI (the <nss.h> status codes and the
 * _nss_<service>_<function> entry points), the same way libnss_sss,
 * libnss_systemd or libnss_ldap do, so it exercises a libc's module loader
 * rather than its files backend.
 *
 * Environment:
 *   FLTEST_STATUS=unavail|notfound|tryagain   force every lookup's status
 *   FLTEST_TRACE=1                            log each call to fd 2
 */
#include <errno.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <shadow.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SERVICE
#define SERVICE fltest
#endif
#define CAT2(a, b, c) a##b##c
#define CAT(a, b, c) CAT2(a, b, c)
#define FN(name) CAT(_nss_, SERVICE, _##name)
#define STR2(x) #x
#define STR(x) STR2(x)

struct user {
  const char *name, *passwd, *gecos, *dir, *shell;
  uid_t uid;
  gid_t gid;
};
struct grp {
  const char *name, *passwd;
  gid_t gid;
  const char *mem[4];
};

static const struct user users[] = {
    {"fltest1", "x", "FL Test One", "/home/fltest1", "/bin/sh", 4201, 4301},
    {"fltest2", "*", "FL Test Two", "/home/fltest2", "/bin/false", 4202, 4302},
    /* Shadows the files entry: which one a lookup sees shows source order. */
    {"root", "m", "module root", "/nonexistent", "/bin/false", 0, 0},
};
static const struct grp groups[] = {
    {"fltestgrp", "x", 4301, {"fltest1", "fltest2", NULL}},
    {"fltestgrp2", "", 4302, {"fltest1", NULL}},
    {"fltestmany", "x", 4303, {"fltest2", "nobody", "fltest1", NULL}},
    /* Shares the files group's name and gid: exercises [SUCCESS=merge]. */
    {"root", "y", 0, {"fltest1", NULL}},
};
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static void trace(const char *what, const char *arg) {
  const char *t = getenv("FLTEST_TRACE");
  if (t == NULL || *t != '1') return;
  char line[256];
  size_t n = 0;
  const char *parts[] = {STR(SERVICE), ":", what, arg ? "(" : "", arg ? arg : "", arg ? ")" : "", "\n"};
  for (size_t i = 0; i < COUNT(parts); i++) {
    size_t l = strlen(parts[i]);
    if (n + l >= sizeof line) break;
    memcpy(line + n, parts[i], l);
    n += l;
  }
  (void)!write(2, line, n);
}

/* Returns 1 and sets *st when FLTEST_STATUS forces a status. */
static int forced(enum nss_status *st, int *errnop) {
  const char *s = getenv("FLTEST_STATUS");
  if (s == NULL || *s == 0) return 0;
  if (strcmp(s, "unavail") == 0) {
    *st = NSS_STATUS_UNAVAIL;
    *errnop = ENOENT;
  } else if (strcmp(s, "tryagain") == 0) {
    *st = NSS_STATUS_TRYAGAIN;
    *errnop = EAGAIN;
  } else {
    *st = NSS_STATUS_NOTFOUND;
    *errnop = ENOENT;
  }
  return 1;
}

static char *put(char **cur, char *end, const char *s) {
  size_t l = strlen(s) + 1;
  if (*cur == NULL || (size_t)(end - *cur) < l) {
    *cur = NULL;
    return NULL;
  }
  char *dst = *cur;
  memcpy(dst, s, l);
  *cur += l;
  return dst;
}

static enum nss_status fill_user(const struct user *u, struct passwd *pw, char *buf, size_t len,
                                 int *errnop) {
  char *cur = buf, *end = buf + len;
  pw->pw_name = put(&cur, end, u->name);
  pw->pw_passwd = put(&cur, end, u->passwd);
  pw->pw_gecos = put(&cur, end, u->gecos);
  pw->pw_dir = put(&cur, end, u->dir);
  pw->pw_shell = put(&cur, end, u->shell);
  if (cur == NULL) {
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  pw->pw_uid = u->uid;
  pw->pw_gid = u->gid;
  return NSS_STATUS_SUCCESS;
}

static enum nss_status fill_group(const struct grp *g, struct group *gr, char *buf, size_t len,
                                  int *errnop) {
  size_t nmem = 0;
  while (g->mem[nmem]) nmem++;
  /* Member pointer array first, pointer-aligned, as real modules lay it out. */
  size_t pad = (sizeof(char *) - ((uintptr_t)buf % sizeof(char *))) % sizeof(char *);
  size_t vec = pad + (nmem + 1) * sizeof(char *);
  if (len < vec) {
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  char **mem = (char **)(buf + pad);
  char *cur = buf + vec, *end = buf + len;
  gr->gr_name = put(&cur, end, g->name);
  gr->gr_passwd = put(&cur, end, g->passwd);
  for (size_t i = 0; i < nmem; i++) mem[i] = put(&cur, end, g->mem[i]);
  if (cur == NULL) {
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  mem[nmem] = NULL;
  gr->gr_mem = mem;
  gr->gr_gid = g->gid;
  return NSS_STATUS_SUCCESS;
}

enum nss_status FN(getpwnam_r)(const char *name, struct passwd *pw, char *buf, size_t len,
                               int *errnop) {
  enum nss_status st;
  trace("getpwnam_r", name);
  if (forced(&st, errnop)) return st;
  for (size_t i = 0; i < COUNT(users); i++)
    if (strcmp(users[i].name, name) == 0) return fill_user(&users[i], pw, buf, len, errnop);
  *errnop = ENOENT;
  return NSS_STATUS_NOTFOUND;
}

enum nss_status FN(getpwuid_r)(uid_t uid, struct passwd *pw, char *buf, size_t len, int *errnop) {
  enum nss_status st;
  trace("getpwuid_r", NULL);
  if (forced(&st, errnop)) return st;
  for (size_t i = 0; i < COUNT(users); i++)
    if (users[i].uid == uid) return fill_user(&users[i], pw, buf, len, errnop);
  *errnop = ENOENT;
  return NSS_STATUS_NOTFOUND;
}

static size_t pw_cursor, gr_cursor, sp_cursor;

enum nss_status FN(setpwent)(int stayopen) {
  (void)stayopen;
  trace("setpwent", NULL);
  pw_cursor = 0;
  return NSS_STATUS_SUCCESS;
}
enum nss_status FN(endpwent)(void) {
  trace("endpwent", NULL);
  pw_cursor = 0;
  return NSS_STATUS_SUCCESS;
}
enum nss_status FN(getpwent_r)(struct passwd *pw, char *buf, size_t len, int *errnop) {
  enum nss_status st;
  trace("getpwent_r", NULL);
  if (forced(&st, errnop)) return st;
  if (pw_cursor >= COUNT(users)) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
  st = fill_user(&users[pw_cursor], pw, buf, len, errnop);
  if (st == NSS_STATUS_SUCCESS) pw_cursor++;
  return st;
}

enum nss_status FN(getgrnam_r)(const char *name, struct group *gr, char *buf, size_t len,
                               int *errnop) {
  enum nss_status st;
  trace("getgrnam_r", name);
  if (forced(&st, errnop)) return st;
  for (size_t i = 0; i < COUNT(groups); i++)
    if (strcmp(groups[i].name, name) == 0) return fill_group(&groups[i], gr, buf, len, errnop);
  *errnop = ENOENT;
  return NSS_STATUS_NOTFOUND;
}

enum nss_status FN(getgrgid_r)(gid_t gid, struct group *gr, char *buf, size_t len, int *errnop) {
  enum nss_status st;
  trace("getgrgid_r", NULL);
  if (forced(&st, errnop)) return st;
  for (size_t i = 0; i < COUNT(groups); i++)
    if (groups[i].gid == gid) return fill_group(&groups[i], gr, buf, len, errnop);
  *errnop = ENOENT;
  return NSS_STATUS_NOTFOUND;
}

enum nss_status FN(setgrent)(int stayopen) {
  (void)stayopen;
  trace("setgrent", NULL);
  gr_cursor = 0;
  return NSS_STATUS_SUCCESS;
}
enum nss_status FN(endgrent)(void) {
  trace("endgrent", NULL);
  gr_cursor = 0;
  return NSS_STATUS_SUCCESS;
}
enum nss_status FN(getgrent_r)(struct group *gr, char *buf, size_t len, int *errnop) {
  enum nss_status st;
  trace("getgrent_r", NULL);
  if (forced(&st, errnop)) return st;
  if (gr_cursor >= COUNT(groups)) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
  st = fill_group(&groups[gr_cursor], gr, buf, len, errnop);
  if (st == NSS_STATUS_SUCCESS) gr_cursor++;
  return st;
}

static enum nss_status fill_spwd(const struct user *u, struct spwd *sp, char *buf, size_t len,
                                 int *errnop) {
  char *cur = buf, *end = buf + len;
  sp->sp_namp = put(&cur, end, u->name);
  sp->sp_pwdp = put(&cur, end, "$6$fltest$hash");
  if (cur == NULL) {
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  sp->sp_lstchg = 19000 + (long)u->uid % 100;
  sp->sp_min = 0;
  sp->sp_max = 99999;
  sp->sp_warn = 7;
  sp->sp_inact = -1;
  sp->sp_expire = -1;
  sp->sp_flag = ~0UL;
  return NSS_STATUS_SUCCESS;
}

enum nss_status FN(getspnam_r)(const char *name, struct spwd *sp, char *buf, size_t len,
                               int *errnop) {
  enum nss_status st;
  trace("getspnam_r", name);
  if (forced(&st, errnop)) return st;
  for (size_t i = 0; i < COUNT(users); i++)
    if (strcmp(users[i].name, name) == 0 && users[i].uid != 0)
      return fill_spwd(&users[i], sp, buf, len, errnop);
  *errnop = ENOENT;
  return NSS_STATUS_NOTFOUND;
}
enum nss_status FN(setspent)(int stayopen) {
  (void)stayopen;
  trace("setspent", NULL);
  sp_cursor = 0;
  return NSS_STATUS_SUCCESS;
}
enum nss_status FN(endspent)(void) {
  trace("endspent", NULL);
  sp_cursor = 0;
  return NSS_STATUS_SUCCESS;
}
enum nss_status FN(getspent_r)(struct spwd *sp, char *buf, size_t len, int *errnop) {
  enum nss_status st;
  trace("getspent_r", NULL);
  if (forced(&st, errnop)) return st;
  while (sp_cursor < COUNT(users) && users[sp_cursor].uid == 0) sp_cursor++;
  if (sp_cursor >= COUNT(users)) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
  st = fill_spwd(&users[sp_cursor], sp, buf, len, errnop);
  if (st == NSS_STATUS_SUCCESS) sp_cursor++;
  return st;
}

#ifndef NO_INITGROUPS
enum nss_status FN(initgroups_dyn)(const char *user, gid_t group, long int *start, long int *size,
                                   gid_t **groupsp, long int limit, int *errnop) {
  enum nss_status st;
  trace("initgroups_dyn", user);
  if (forced(&st, errnop)) return st;
  int found = 0;
  for (size_t i = 0; i < COUNT(groups); i++) {
    if (groups[i].gid == group) continue;
    int member = 0;
    for (size_t m = 0; groups[i].mem[m]; m++)
      if (strcmp(groups[i].mem[m], user) == 0) member = 1;
    if (!member) continue;
    found = 1;
    if (*start == *size) {
      if (limit > 0 && *size >= limit) return NSS_STATUS_SUCCESS;
      long int newsize = *size ? 2 * *size : 8;
      if (limit > 0 && newsize > limit) newsize = limit;
      gid_t *ng = realloc(*groupsp, (size_t)newsize * sizeof(gid_t));
      if (ng == NULL) {
        *errnop = ENOMEM;
        return NSS_STATUS_TRYAGAIN;
      }
      *groupsp = ng;
      *size = newsize;
    }
    (*groupsp)[(*start)++] = groups[i].gid;
  }
  if (!found) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
  return NSS_STATUS_SUCCESS;
}
#endif
