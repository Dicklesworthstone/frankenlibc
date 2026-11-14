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
#include <netdb.h>
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

static void trace(const char *what, const char *arg);
static int forced(enum nss_status *st, int *errnop);
static char *put(char **cur, char *end, const char *s);

/* Service lookups deliberately overlap /etc/services at http, return
 * different TCP/UDP ports, and require more than the usual 1 KiB scratch for
 * fltest-large-service. A libc must query the selected NSS source for each
 * protocol; scanning /etc/services cannot satisfy these cases. */
static unsigned service_calls;
static int (*service_reentry)(void);

unsigned FN(service_calls)(void) { return service_calls; }
void FN(set_service_reentry)(int (*callback)(void)) { service_reentry = callback; }

static enum nss_status fill_service(const char *name, const char *proto,
                                   unsigned port, int large,
                                   struct servent *out, char *buf, size_t len,
                                   int *errnop) {
  size_t pad = (sizeof(char *) - (uintptr_t)buf % sizeof(char *)) % sizeof(char *);
  size_t count = large ? 3 : 2;
  size_t need = pad + (count + 1) * sizeof(char *) + strlen(name) + 1 +
                strlen(proto) + 1 + sizeof "fltest-svc" + sizeof "shared-service" +
                (large ? 3073 : 0);
  if (len < need) {
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  char **aliases = (char **)(buf + pad);
  char *cur = (char *)(aliases + count + 1), *end = buf + len;
  out->s_name = put(&cur, end, name);
  out->s_proto = put(&cur, end, proto);
  out->s_port = htons((uint16_t)port);
  out->s_aliases = aliases;
  aliases[0] = put(&cur, end, "fltest-svc");
  aliases[1] = put(&cur, end, "shared-service");
  if (large) {
    aliases[2] = cur;
    memset(cur, 's', 3072);
    cur[3072] = '\0';
  }
  aliases[count] = NULL;
  *errnop = 0;
  return NSS_STATUS_SUCCESS;
}

enum nss_status FN(getservbyname_r)(const char *name, const char *proto,
                                   struct servent *out, char *buf, size_t len,
                                   int *errnop) {
  ++service_calls;
  trace("getservbyname_r", name);
  enum nss_status status;
  if (forced(&status, errnop)) return status;
  /* These modules intentionally leave errnop untouched, as successful NSS
   * providers are allowed to do. Keep misses and transient failures separate. */
  if (!strcmp(name, "fltest-errno-none")) return NSS_STATUS_NOTFOUND;
  if (!strcmp(name, "fltest-errno-again")) return NSS_STATUS_TRYAGAIN;
  if (!strcmp(name, "fltest-errno-unavail")) return NSS_STATUS_UNAVAIL;
  if (!strcmp(name, "fltest-errno-success") || !strcmp(name, "fltest-errno-written")) {
    int saved = *errnop;
    status = fill_service("errno-unchanged", "tcp", 4346, 0, out, buf, len, errnop);
    if (status == NSS_STATUS_SUCCESS)
      *errnop = !strcmp(name, "fltest-errno-written") ? EIO : saved;
    return status;
  }
  if (!strcmp(name, "fltest-reentry")) {
    if (!service_reentry || service_reentry() != 0) {
      *errnop = EIO;
      return NSS_STATUS_UNAVAIL;
    }
    return fill_service("fltest-reentry", "tcp", 4347, 1, out, buf, len, errnop);
  }
  if (!strcmp(name, "fltest-again")) {
    *errnop = EAGAIN;
    return NSS_STATUS_TRYAGAIN;
  }
  if (!strcmp(name, "fltest-unavail")) {
    *errnop = ENOSYS;
    return NSS_STATUS_UNAVAIL;
  }
  int large = !strcmp(name, "fltest-large-service");
  int http = !strcmp(name, "http");
  if ((!large && !http && strcmp(name, "fltest-service") &&
       strcmp(name, "fltest-svc") && strcmp(name, "shared-service")) ||
      (proto && strcmp(proto, "tcp") && strcmp(proto, "udp"))) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
  if (!proto) proto = "tcp";
  if (http && !strcmp(proto, "udp")) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
#ifndef FLTEST_NATIVE_MODULE
  if (getenv("FLTEST_SERVICE_REENTER")) {
    struct passwd scratch, *found;
    char storage[1024];
    if (getpwnam_r("root", &scratch, storage, sizeof storage, &found) != 0 || !found) {
      *errnop = EIO;
      return NSS_STATUS_UNAVAIL;
    }
  }
#endif
  return fill_service(http ? "module-http" : "fltest-service", proto,
                      http ? 42480 : large ? 4345 : !strcmp(proto, "tcp") ? 4343 : 4344,
                      large, out, buf, len, errnop);
}

enum nss_status FN(getservbyport_r)(int port, const char *proto,
                                   struct servent *out, char *buf, size_t len,
                                   int *errnop) {
  ++service_calls;
  trace("getservbyport_r", proto);
  enum nss_status status;
  if (forced(&status, errnop)) return status;
  const char *selected = port == htons(4344) ? "udp" : "tcp";
  if ((port != htons(4343) && port != htons(4344) && port != htons(4345) &&
       port != htons(80)) || (proto && strcmp(proto, selected))) {
    *errnop = ENOENT;
    return NSS_STATUS_NOTFOUND;
  }
  return fill_service(port == htons(80) ? "module-http" : "fltest-service", selected,
                      ntohs((uint16_t)port), port == htons(4345), out, buf, len, errnop);
}

static const unsigned char host_v4[2][4] = {
    {192, 0, 2, 41}, {192, 0, 2, 42},
};
static const unsigned char host_v6[2][16] = {
    {[0] = 0x20, [1] = 0x01, [2] = 0x0d, [3] = 0xb8, [15] = 0x41},
    {[0] = 0x20, [1] = 0x01, [2] = 0x0d, [3] = 0xb8, [15] = 0x42},
};

static enum nss_status host_failure(enum nss_status status, int error,
                                    int *errnop, int *h_errnop) {
  *errnop = error;
  *h_errnop = status == NSS_STATUS_TRYAGAIN ? TRY_AGAIN
             : status == NSS_STATUS_NOTFOUND ? HOST_NOT_FOUND : NO_RECOVERY;
  return status;
}

static enum nss_status fill_host(int family, int large, struct hostent *host,
                                 char *buf, size_t len, int *errnop, int *h_errnop) {
  if (family != AF_INET && family != AF_INET6)
    return host_failure(NSS_STATUS_UNAVAIL, EAFNOSUPPORT, errnop, h_errnop);
  size_t addrlen = family == AF_INET ? 4 : 16;
  size_t alias_count = large ? 3 : 2;
  size_t pad = (sizeof(char *) - (uintptr_t)buf % sizeof(char *)) % sizeof(char *);
  size_t vector_bytes = (alias_count + 1 + 3) * sizeof(char *);
  if (len < pad + vector_bytes + 2 * addrlen + 128 + (large ? 3073 : 0))
    return host_failure(NSS_STATUS_TRYAGAIN, ERANGE, errnop, h_errnop);
  char **aliases = (char **)(buf + pad);
  char **addresses = aliases + alias_count + 1;
  char *cur = (char *)(addresses + 3), *end = buf + len;
  host->h_name = put(&cur, end, "fltest-host.example");
  aliases[0] = put(&cur, end, "fltest-alias");
  aliases[1] = put(&cur, end, "fltest-short");
  if (large) {
    aliases[2] = cur;
    memset(cur, 'a', 3072);
    cur[3072] = '\0';
    cur += 3073;
  }
  aliases[alias_count] = NULL;
  for (size_t i = 0; i < 2; ++i) {
    addresses[i] = cur;
    memcpy(cur, family == AF_INET ? host_v4[i] : host_v6[i], addrlen);
    cur += addrlen;
  }
  addresses[2] = NULL;
  host->h_aliases = aliases;
  host->h_addrtype = family;
  host->h_length = (int)addrlen;
  host->h_addr_list = addresses;
  *errnop = 0;
  *h_errnop = NETDB_SUCCESS;
  return NSS_STATUS_SUCCESS;
}

#if !defined(NO_HOST1) || !defined(NO_HOST2) || !defined(NO_HOST3)
static enum nss_status host_by_name(const char *name, int family, struct hostent *host,
                                    char *buf, size_t len, int *errnop, int *h_errnop) {
  enum nss_status status;
  if (forced(&status, errnop))
    return host_failure(status, *errnop, errnop, h_errnop);
  int large = strcmp(name, "fltest-large") == 0;
  if (!large && strcmp(name, "fltest-host") != 0 &&
      strcmp(name, "fltest-host.example") != 0 &&
      strcmp(name, "fltest-alias") != 0 && strcmp(name, "shared-host") != 0 &&
      strcmp(name, "fltest-canonical") != 0)
    return host_failure(NSS_STATUS_NOTFOUND, ENOENT, errnop, h_errnop);
  return fill_host(family, large, host, buf, len, errnop, h_errnop);
}
#endif

#ifdef WITH_HOST4
enum nss_status FN(gethostbyname4_r)(const char *name, struct gaih_addrtuple **pat,
                                    char *buf, size_t len, int *errnop,
                                    int *h_errnop, int32_t *ttlp) {
  static _Thread_local int partial_head_outstanding;
  trace("gethostbyname4_r", name);
  if (partial_head_outstanding) {
    const char *require_reset = getenv("FLTEST_REQUIRE_TUPLE_HEAD_RESET");
    partial_head_outstanding = 0;
    if (require_reset != NULL && *require_reset == '1' && *pat != NULL)
      return host_failure(NSS_STATUS_UNAVAIL, EINVAL, errnop, h_errnop);
  }
  enum nss_status status;
  if (forced(&status, errnop))
    return host_failure(status, *errnop, errnop, h_errnop);
  int large = strcmp(name, "fltest-tuple-large") == 0;
  if (!large && strcmp(name, "fltest-tuple") != 0)
    return host_failure(NSS_STATUS_NOTFOUND, ENOENT, errnop, h_errnop);

  const char canonical[] = "fltest-tuple.example";
  size_t alignment = _Alignof(struct gaih_addrtuple);
  size_t pad = (alignment - (uintptr_t)buf % alignment) % alignment;
  size_t tuples_size = 4 * sizeof(struct gaih_addrtuple);
  size_t required = pad + tuples_size + sizeof canonical + (large ? 8192 : 0);
  if (len < required) {
    /* A failed module call may publish a partial list into the old scratch.
       Candidate retries must discard that pointer before replacing storage. */
    if (len >= pad + sizeof(struct gaih_addrtuple)) {
      struct gaih_addrtuple *partial = (struct gaih_addrtuple *)(buf + pad);
      memset(partial, 0, sizeof *partial);
      partial->family = AF_INET;
      memcpy(partial->addr, host_v4[0], 4);
      *pat = partial;
      partial_head_outstanding = 1;
    }
    trace("gethostbyname4_r_ERANGE", name);
    *errnop = ERANGE;
    *h_errnop = NETDB_INTERNAL;
    return NSS_STATUS_TRYAGAIN;
  }

  struct gaih_addrtuple *tuples = (struct gaih_addrtuple *)(buf + pad);
  char *owner = buf + pad + tuples_size;
  memcpy(owner, canonical, sizeof canonical);
  memset(tuples, 0, tuples_size);
  for (size_t i = 0; i < 4; ++i) {
    tuples[i].next = i == 3 ? NULL : &tuples[i + 1];
    tuples[i].name = owner;
    tuples[i].family = i == 0 ? AF_INET : AF_INET6;
  }
  memcpy(tuples[0].addr, host_v4[0], 4);
  memcpy(tuples[1].addr, host_v6[0], 16);
  const unsigned char scoped[16] = {[0] = 0xfe, [1] = 0x80, [15] = 0x41};
  memcpy(tuples[2].addr, scoped, 16);
  memcpy(tuples[3].addr, scoped, 16);
  tuples[2].scopeid = 7;
  tuples[3].scopeid = 9;
  *pat = tuples;
  const char *shape = getenv("FLTEST_TUPLE_SHAPE");
  if (shape != NULL && *shape != '\0') {
    trace("gethostbyname4_r_shape", shape);
    if (strcmp(shape, "nameless") == 0) {
      for (size_t i = 0; i < 4; ++i) tuples[i].name = NULL;
    } else if (strcmp(shape, "empty") == 0) {
      *pat = NULL;
    } else if (strcmp(shape, "badfamily") == 0) {
      tuples[1].family = AF_UNIX;
    } else if (strcmp(shape, "cycle") == 0) {
      tuples[3].next = &tuples[1];
    }
  }
  *errnop = 0;
  *h_errnop = NETDB_SUCCESS;
  if (ttlp != NULL) *ttlp = 60;
  return NSS_STATUS_SUCCESS;
}
#endif

#ifndef NO_HOST3
enum nss_status FN(gethostbyname3_r)(const char *name, int family, struct hostent *host,
                                    char *buf, size_t len, int *errnop, int *h_errnop,
                                    int32_t *ttlp, char **canonp) {
  trace("gethostbyname3_r", name);
  enum nss_status status = host_by_name(name, family, host, buf, len, errnop, h_errnop);
  if (status == NSS_STATUS_SUCCESS) {
    if (ttlp != NULL) *ttlp = 60;
    if (canonp != NULL)
      *canonp = strcmp(name, "fltest-canonical") == 0
                    ? (char *)"fltest-official.example" : host->h_name;
  }
  return status;
}
#endif

#ifndef NO_HOST2
enum nss_status FN(gethostbyname2_r)(const char *name, int family, struct hostent *host,
                                    char *buf, size_t len, int *errnop, int *h_errnop) {
  trace("gethostbyname2_r", name);
  return host_by_name(name, family, host, buf, len, errnop, h_errnop);
}
#endif

#ifndef NO_HOST1
enum nss_status FN(gethostbyname_r)(const char *name, struct hostent *host,
                                   char *buf, size_t len, int *errnop, int *h_errnop) {
  trace("gethostbyname_r", name);
  return host_by_name(name, AF_INET, host, buf, len, errnop, h_errnop);
}
#endif

static enum nss_status host_by_address(const void *address, socklen_t address_len,
                                       int family, struct hostent *host, char *buf,
                                       size_t len, int *errnop, int *h_errnop) {
  enum nss_status status;
  if (forced(&status, errnop))
    return host_failure(status, *errnop, errnop, h_errnop);
  if ((family != AF_INET && family != AF_INET6) ||
      address_len != (socklen_t)(family == AF_INET ? 4 : 16))
    return host_failure(NSS_STATUS_UNAVAIL, EAFNOSUPPORT, errnop, h_errnop);
  for (size_t i = 0; i < 2; ++i) {
    const unsigned char *expected = family == AF_INET ? host_v4[i] : host_v6[i];
    if (memcmp(address, expected, address_len) == 0)
      return fill_host(family, i == 1, host, buf, len, errnop, h_errnop);
  }
  return host_failure(NSS_STATUS_NOTFOUND, ENOENT, errnop, h_errnop);
}

#ifndef NO_HOSTADDR2
enum nss_status FN(gethostbyaddr2_r)(const void *address, socklen_t address_len,
                                    int family, struct hostent *host, char *buf,
                                    size_t len, int *errnop, int *h_errnop,
                                    int32_t *ttlp) {
  trace("gethostbyaddr2_r", NULL);
  enum nss_status status = host_by_address(address, address_len, family, host,
                                          buf, len, errnop, h_errnop);
  if (status == NSS_STATUS_SUCCESS && ttlp != NULL) *ttlp = 60;
  return status;
}
#endif

enum nss_status FN(gethostbyaddr_r)(const void *address, socklen_t address_len,
                                   int family, struct hostent *host, char *buf,
                                   size_t len, int *errnop, int *h_errnop) {
  trace("gethostbyaddr_r", NULL);
  return host_by_address(address, address_len, family, host, buf, len, errnop, h_errnop);
}

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
#ifdef FLTEST_NATIVE_MODULE
/* Force the loader-selected realloc to consume and resize the caller's
   initial group array, even when the fixture contributes only three gids. */
static unsigned initgroups_reallocations;
unsigned FN(initgroups_reallocations)(void) { return initgroups_reallocations; }
uintptr_t FN(allocator_address)(unsigned which) {
  return which == 0 ? (uintptr_t)malloc : which == 1 ? (uintptr_t)realloc : (uintptr_t)free;
}
#endif
enum nss_status FN(initgroups_dyn)(const char *user, gid_t group, long int *start, long int *size,
                                   gid_t **groupsp, long int limit, int *errnop) {
  enum nss_status st;
  trace("initgroups_dyn", user);
  if (forced(&st, errnop)) return st;
#ifdef FLTEST_NATIVE_MODULE
  long int grown = *size + 64;
  gid_t *resized = realloc(*groupsp, (size_t)grown * sizeof(gid_t));
  if (resized == NULL) {
    *errnop = ENOMEM;
    return NSS_STATUS_TRYAGAIN;
  }
  *groupsp = resized;
  *size = grown;
  ++initgroups_reallocations;
#endif
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


/* GNU's netgroup module ABI. <nss.h> intentionally only forward-declares
 * this cursor; keep the layout here independent of libc implementation code.
 * Each SET owns its data until END, and GET must not consume on ERANGE. */
struct __netgrent {
  enum { flnet_triple, flnet_group } type;
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
_Static_assert(sizeof(struct __netgrent) == 88, "GNU netgroup cursor size");
#endif

struct flnet_cursor {
  char name[64];
  size_t position;
  int retried;
};
static int (*netgroup_reentry)(void);
void FN(set_netgroup_reentry)(int (*callback)(void)) {
  netgroup_reentry = callback;
}

enum nss_status FN(setnetgrent)(const char *name, struct __netgrent *out) {
  trace("setnetgrent", name);
  if (!strcmp(STR(SERVICE), "fltest")) {
    if (!strcmp(name, "flnet-set-notfound") || !strcmp(name, "flnet-remote"))
      return NSS_STATUS_NOTFOUND;
    if (!strcmp(name, "flnet-set-unavail")) return NSS_STATUS_UNAVAIL;
    if (!strcmp(name, "flnet-set-again")) return NSS_STATUS_TRYAGAIN;
    if (!strcmp(name, "flnet-set-return")) return NSS_STATUS_RETURN;
  }
  if (strncmp(name, "flnet-", 6) || !strcmp(name, "flnet-missing"))
    return NSS_STATUS_NOTFOUND;
  struct flnet_cursor *state = calloc(1, sizeof *state);
  if (!state) return NSS_STATUS_TRYAGAIN;
  if (strlen(name) >= sizeof state->name) {
    free(state);
    return NSS_STATUS_NOTFOUND;
  }
  strcpy(state->name, name);
  out->data = (char *)state;
  out->data_size = sizeof *state;
  return NSS_STATUS_SUCCESS;
}

enum nss_status FN(endnetgrent)(struct __netgrent *out) {
  struct flnet_cursor *state = (struct flnet_cursor *)out->data;
  trace("endnetgrent", state ? state->name : NULL);
  free(state);
  out->data = NULL;
  out->data_size = 0;
  return NSS_STATUS_SUCCESS;
}

enum nss_status FN(getnetgrent_r)(struct __netgrent *out, char *buf, size_t len,
                                  int *errnop) {
  struct flnet_cursor *state = (struct flnet_cursor *)out->data;
  if (!state) {
    *errnop = EINVAL;
    return NSS_STATUS_UNAVAIL;
  }
  trace("getnetgrent_r", state->name);
  size_t index = state->position;
  const char *host = NULL, *user = NULL, *domain = NULL, *group = NULL;
  int large = 0;

  if (!strcmp(state->name, "flnet-reentry") && !index && netgroup_reentry) {
    int (*callback)(void) = netgroup_reentry;
    netgroup_reentry = NULL;
    int rc = callback();
    netgroup_reentry = callback;
    if (rc) {
      *errnop = EIO;
      return NSS_STATUS_UNAVAIL;
    }
  }
  if (!strcmp(state->name, "flnet-empty")) return NSS_STATUS_RETURN;
  if (!strcmp(state->name, "flnet-cross")) {
    if (index) return NSS_STATUS_RETURN;
    group = "flnet-remote";
  } else if (!strcmp(state->name, "flnet-nested")) {
    if (!index) { host = "root"; user = "root-user"; domain = "root-domain"; }
    else if (index == 1 || index == 3) group = "flnet-alpha";
    else if (index == 2) group = "flnet-beta";
    else if (index == 4) group = "flnet-missing";
    else return NSS_STATUS_RETURN;
  } else if (!strcmp(state->name, "flnet-alpha")) {
    if (!index) { host = "alpha"; user = "a"; domain = "d"; }
    else if (index == 1) group = "flnet-nested";
    else return NSS_STATUS_RETURN;
  } else if (!strcmp(state->name, "flnet-beta")) {
    if (!index) { host = "beta"; user = "b"; domain = "d"; }
    else if (index == 1) group = "flnet-alpha";
    else return NSS_STATUS_RETURN;
  } else if (!strcmp(state->name, "flnet-null")) {
    if (index) return NSS_STATUS_RETURN;
    host = NULL; user = ""; domain = "-";
  } else if (!strcmp(state->name, "flnet-large")) {
    if (index) return NSS_STATUS_RETURN;
    large = 1; user = "large-user"; domain = "large-domain";
  } else if (!strcmp(state->name, "flnet-scratch")) {
    if (index) return NSS_STATUS_RETURN;
    /* Scratch requirements are a module contract, even when its final
     * tuple would fit a much smaller buffer. Public GET may not auto-grow. */
    if (len < 4096) {
      trace("getnetgrent_r_ERANGE", state->name);
      *errnop = ERANGE;
      return NSS_STATUS_TRYAGAIN;
    }
    host = "scratch"; user = "scratch-user"; domain = "scratch-domain";
  } else if (!strcmp(state->name, "flnet-retry")) {
    if (index == 1 && !state->retried) {
      state->retried = 1;
      *errnop = EAGAIN;
      return NSS_STATUS_TRYAGAIN;
    }
    if (index > 1) return NSS_STATUS_RETURN;
    host = index ? "after-retry" : "before-retry";
    user = "retry-user"; domain = "retry-domain";
  } else if (!strncmp(state->name, "flnet-get-", 10)) {
    if (!index) { host = "before-status"; user = "u"; domain = "d"; }
    else if (index == 1) group = "flnet-leaf";
    else if (!strcmp(state->name, "flnet-get-notfound")) {
      *errnop = ENOENT;
      return NSS_STATUS_NOTFOUND;
    } else if (!strcmp(state->name, "flnet-get-unavail")) {
      *errnop = ENOSYS;
      return NSS_STATUS_UNAVAIL;
    } else if (!strcmp(state->name, "flnet-get-quiet")) {
      return NSS_STATUS_UNAVAIL;
    } else if (!strcmp(state->name, "flnet-get-again-quiet")) {
      return NSS_STATUS_TRYAGAIN;
    } else return NSS_STATUS_RETURN;
  } else if (!strcmp(state->name, "flnet-leaf")) {
    if (index) return NSS_STATUS_RETURN;
    host = "leaf"; user = "leaf-user"; domain = "leaf-domain";
  } else {
    if (index > 1) return NSS_STATUS_RETURN;
    host = index ? STR(SERVICE) "-two" : STR(SERVICE) "-one";
    user = index ? "two" : "one";
    domain = "example.test";
  }

  size_t need = group ? strlen(group) + 1 :
      (large ? 3073 : host ? strlen(host) + 1 : 0) +
      (user ? strlen(user) + 1 : 0) + (domain ? strlen(domain) + 1 : 0);
  if (len < need) {
    trace("getnetgrent_r_ERANGE", state->name);
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  char *cur = buf, *end = buf + len;
  if (group) {
    out->type = flnet_group;
    out->val.group = put(&cur, end, group);
  } else {
    out->type = flnet_triple;
    if (large) {
      out->val.triple.host = cur;
      memset(cur, 'n', 3072);
      cur[3072] = '\0';
      cur += 3073;
    } else out->val.triple.host = host ? put(&cur, end, host) : NULL;
    out->val.triple.user = user ? put(&cur, end, user) : NULL;
    out->val.triple.domain = domain ? put(&cur, end, domain) : NULL;
  }
  state->position++;
  return NSS_STATUS_SUCCESS;
}
