/* fixture_nss_modules.c -- account and network-service NSS module lookups
 * NSS service module (libnss_fltest.so.2 / libnss_fltestnoig.so.2, built from
 * fixture_nss_module_lib.c), as configured in nsswitch.conf.
 *
 * Prints one line per observation so the output can be compared byte for byte
 * with glibc under the same nsswitch.conf and LD_LIBRARY_PATH. With an
 * argument, runs only that section: pw, gr, sp, ent, ig, r. The services
 * command additionally pins each callable to the requested shared object.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *s(const char *p) { return p ? p : "(null)"; }

static void show_pw(const char *what, struct passwd *pw) {
  if (pw == NULL) {
    printf("%s: NULL\n", what);
    return;
  }
  printf("%s: %s:%s:%u:%u:%s:%s:%s\n", what, s(pw->pw_name), s(pw->pw_passwd),
         (unsigned)pw->pw_uid, (unsigned)pw->pw_gid, s(pw->pw_gecos), s(pw->pw_dir),
         s(pw->pw_shell));
}

static void show_gr(const char *what, struct group *gr) {
  if (gr == NULL) {
    printf("%s: NULL\n", what);
    return;
  }
  printf("%s: %s:%s:%u:", what, s(gr->gr_name), s(gr->gr_passwd), (unsigned)gr->gr_gid);
  for (char **m = gr->gr_mem; m && *m; m++) printf("%s%s", m == gr->gr_mem ? "" : ",", *m);
  printf("\n");
}

static void section_pw(void) {
  show_pw("getpwnam fltest1", getpwnam("fltest1"));
  show_pw("getpwnam root", getpwnam("root"));
  show_pw("getpwuid 4202", getpwuid(4202));
  show_pw("getpwuid 0", getpwuid(0));
  show_pw("getpwnam nosuch", getpwnam("fl_nosuch_user"));
}

static void section_gr(void) {
  show_gr("getgrnam fltestgrp", getgrnam("fltestgrp"));
  show_gr("getgrnam fltestgrp2", getgrnam("fltestgrp2"));
  show_gr("getgrgid 4303", getgrgid(4303));
  show_gr("getgrnam root", getgrnam("root"));
  show_gr("getgrgid 0", getgrgid(0));
  show_gr("getgrnam nosuch", getgrnam("fl_nosuch_group"));
}

static void section_sp(void) {
  struct spwd *sp = getspnam("fltest2");
  if (sp == NULL)
    printf("getspnam fltest2: NULL\n");
  else
    printf("getspnam fltest2: %s:%s:%ld:%ld:%ld:%ld:%ld:%ld\n", s(sp->sp_namp), s(sp->sp_pwdp),
           sp->sp_lstchg, sp->sp_min, sp->sp_max, sp->sp_warn, sp->sp_inact, sp->sp_expire);
  printf("getspnam nosuch: %s\n", getspnam("fl_nosuch_user") ? "found" : "NULL");
}

/* Enumeration: print only module-provided names (uid/gid 4200..4399) and the
 * running count of all entries, so the host's own files do not matter beyond
 * their count, which both libcs read from the same files. */
static void section_ent(void) {
  int n = 0;
  struct passwd *pw;
  setpwent();
  while ((pw = getpwent()) != NULL) {
    n++;
    if ((pw->pw_uid >= 4200 && pw->pw_uid < 4400) || strcmp(pw->pw_gecos ? pw->pw_gecos : "", "module root") == 0)
      printf("getpwent[%d]: %s %u\n", n, pw->pw_name, (unsigned)pw->pw_uid);
  }
  endpwent();
  printf("getpwent total>0: %d\n", n > 0);
  int g = 0;
  struct group *gr;
  setgrent();
  while ((gr = getgrent()) != NULL) {
    g++;
    if ((gr->gr_gid >= 4300 && gr->gr_gid < 4400) || strcmp(gr->gr_passwd ? gr->gr_passwd : "", "y") == 0)
      printf("getgrent[%d]: %s %u\n", g, gr->gr_name, (unsigned)gr->gr_gid);
  }
  endgrent();
  printf("getgrent total>0: %d\n", g > 0);
}

static void section_ig(void) {
  gid_t groups[16];
  int ngroups = 16;
  int rc = getgrouplist("fltest1", 4301, groups, &ngroups);
  printf("getgrouplist fltest1: rc=%d n=%d:", rc, ngroups);
  for (int i = 0; rc >= 0 && i < ngroups; i++) printf(" %u", (unsigned)groups[i]);
  printf("\n");
  ngroups = 1;
  rc = getgrouplist("fltest1", 4301, groups, &ngroups);
  printf("getgrouplist fltest1 small: rc=%d n=%d first=%u\n", rc, ngroups, (unsigned)groups[0]);
  ngroups = 16;
  rc = getgrouplist("fltest2", 4302, groups, &ngroups);
  printf("getgrouplist fltest2: rc=%d n=%d:", rc, ngroups);
  for (int i = 0; rc >= 0 && i < ngroups; i++) printf(" %u", (unsigned)groups[i]);
  printf("\n");
  if (geteuid() == 0) {
    if (initgroups("fltest1", 4301) != 0) {
      printf("initgroups: errno=%d\n", errno);
    } else {
      int n = getgroups(16, groups);
      printf("initgroups fltest1 -> getgroups n=%d:", n);
      for (int i = 0; i < n; i++) printf(" %u", (unsigned)groups[i]);
      printf("\n");
    }
  }
}

static void section_r(void) {
  struct passwd pwbuf, *pwres = (struct passwd *)1;
  char small[8], big[1024];
  int rc = getpwnam_r("fltest1", &pwbuf, small, sizeof small, &pwres);
  printf("getpwnam_r small: rc=%d res=%s\n", rc, pwres ? "set" : "NULL");
  rc = getpwnam_r("fltest1", &pwbuf, big, sizeof big, &pwres);
  printf("getpwnam_r big: rc=%d res=%s\n", rc, pwres == &pwbuf ? "pwbuf" : "other");
  if (pwres) show_pw("  value", pwres);
  rc = getpwuid_r(4202, &pwbuf, big, sizeof big, &pwres);
  printf("getpwuid_r 4202: rc=%d %s\n", rc, pwres ? pwres->pw_name : "NULL");
  rc = getpwnam_r("fl_nosuch_user", &pwbuf, big, sizeof big, &pwres);
  printf("getpwnam_r nosuch: rc=%d res=%s\n", rc, pwres ? "set" : "NULL");
  struct group grbuf, *grres = (struct group *)1;
  char gsmall[16];
  rc = getgrnam_r("fltestmany", &grbuf, gsmall, sizeof gsmall, &grres);
  printf("getgrnam_r small: rc=%d res=%s\n", rc, grres ? "set" : "NULL");
  rc = getgrnam_r("fltestmany", &grbuf, big, sizeof big, &grres);
  printf("getgrnam_r big: rc=%d\n", rc);
  if (grres) show_gr("  value", grres);
  rc = getgrgid_r(4302, &grbuf, big, sizeof big, &grres);
  printf("getgrgid_r 4302: rc=%d %s\n", rc, grres ? grres->gr_name : "NULL");
  struct spwd spbuf, *spres = NULL;
  rc = getspnam_r("fltest1", &spbuf, big, sizeof big, &spres);
  printf("getspnam_r fltest1: rc=%d %s\n", rc, spres ? spres->sp_pwdp : "NULL");
}

/* Provider-pinned service lookup campaign. This explicit section leaves the
 * original account/hosts transcripts unchanged. Each invocation runs in a
 * fresh process, with GNU's services policy set through its own NSS hook and
 * the candidate reading the corresponding private nsswitch.conf file. */
struct service_api {
  struct servent *(*name)(const char *, const char *);
  struct servent *(*port)(int, const char *);
  int (*name_r)(const char *, const char *, struct servent *, char *, size_t, struct servent **);
  int (*port_r)(int, const char *, struct servent *, char *, size_t, struct servent **);
  int (*addr)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
  void (*free_addr)(struct addrinfo *);
  int (*reverse)(const struct sockaddr *, socklen_t, char *, socklen_t, char *, socklen_t, int);
  int *(*error)(void);
  int (*profiles)(const char *, const struct addrinfo *, int *);
};

static struct service_api service_api;
static unsigned service_reentry_calls;

static int reenter_service_lookup(void) {
  ++service_reentry_calls;
  struct servent value, *entry;
  char buffer[1024];
  int rc = service_api.name_r("http", "tcp", &value, buffer, sizeof buffer, &entry);
  return rc || !entry || strcmp(entry->s_name, "module-http") || entry->s_port != htons(42480);
}

static int same_provider(const char *path, void *address) {
  Dl_info info;
  struct stat expected, actual;
  return dladdr(address, &info) && info.dli_fname && stat(path, &expected) == 0 &&
         stat(info.dli_fname, &actual) == 0 && expected.st_dev == actual.st_dev &&
         expected.st_ino == actual.st_ino;
}

static void *service_symbol(void *handle, const char *path, const char *symbol, int host) {
  const char *version =
#if defined(__x86_64__)
      "GLIBC_2.2.5";
#elif defined(__aarch64__)
      "GLIBC_2.17";
#else
      NULL;
#endif
  void *address = host && version ? dlvsym(handle, symbol, version) : dlsym(handle, symbol);
  if (!address || !same_provider(path, address)) {
    fprintf(stderr, "wrong provider: %s\n", symbol);
    exit(91);
  }
  return address;
}

static void show_service(const char *label, int rc, struct servent *entry) {
  printf("%s rc=%d errno=%d", label, rc, *service_api.error());
  if (!entry) { puts(" NULL"); return; }
  printf(" %s/%s/%u aliases", entry->s_name, entry->s_proto, ntohs((uint16_t)entry->s_port));
  for (char **alias = entry->s_aliases; alias && *alias; ++alias) {
    size_t n = strlen(*alias);
    if (n <= 64) printf(" %s", *alias);
    else printf(" %zu:%c:%c", n, (*alias)[0], (*alias)[n - 1]);
  }
  putchar('\n');
}

static int service_probe(int argc, char **argv) {
  if (argc != 5) return 90;
  alarm(8);
  int host = !strcmp(argv[2], "host");
  int source_harness = getenv("NSS_SOURCE_HARNESS") != NULL;
  void *gnu = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  Dl_info info;
  if (!gnu || !dladdr(dlsym(gnu, "getservbyname"), &info)) return 91;
  const char *path = host ? info.dli_fname : argv[2];
  if (!host && same_provider(path, dlsym(gnu, "getservbyname"))) return 91;
  void *provider = host ? gnu : dlopen(path, RTLD_NOW | RTLD_LOCAL);
  if (!provider) { fprintf(stderr, "load failed: %s\n", dlerror()); return 91; }
#define SERVICE_LOAD(field, symbol) \
  *(void **)(&service_api.field) = service_symbol(provider, path, symbol, host)
  SERVICE_LOAD(name, "getservbyname");
  SERVICE_LOAD(port, "getservbyport");
  SERVICE_LOAD(name_r, "getservbyname_r");
  SERVICE_LOAD(port_r, "getservbyport_r");
  if (source_harness && !host) {
    /* Local source-only tests expose the exact profile helper explicitly;
     * this is never accepted as the deployed getaddrinfo gate. */
    SERVICE_LOAD(profiles, "flc_test_service_profiles");
    *(void **)(&service_api.error) = dlsym(gnu, "__errno_location");
  } else {
    SERVICE_LOAD(addr, "getaddrinfo");
    SERVICE_LOAD(free_addr, "freeaddrinfo");
    SERVICE_LOAD(reverse, "getnameinfo");
    SERVICE_LOAD(error, "__errno_location");
  }
#undef SERVICE_LOAD
  if (host) {
    int (*configure)(const char *, const char *) = dlsym(gnu, "__nss_configure_lookup");
    if (!configure || configure("services", argv[3])) return 92;
  }
  const char *which = argv[4];
  if (!strcmp(which, "identity")) {
    puts(path);
  } else if (!strcmp(which, "queries")) {
    const char *names[] = {"fltest-service", "fltest-svc", "fltest-large-service", "http", "fltest-none", "fltest-again", "fltest-unavail"};
    const char *protocols[] = {NULL, "tcp", "udp", "sctp"};
    for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
      for (size_t j = 0; j < sizeof protocols / sizeof *protocols; ++j) {
        *service_api.error() = 123;
        struct servent *entry = service_api.name(names[i], protocols[j]);
        char label[128];
        snprintf(label, sizeof label, "name %s %s", names[i], s(protocols[j]));
        show_service(label, 0, entry);
      }
    }
    int ports[] = {htons(4343), htons(4344), htons(4345), htons(80), -1, 0x10000 | htons(4343)};
    for (size_t i = 0; i < sizeof ports / sizeof *ports; ++i) {
      for (size_t j = 0; j < sizeof protocols / sizeof *protocols; ++j) {
        *service_api.error() = 123;
        struct servent *entry = service_api.port(ports[i], protocols[j]);
        char label[128];
        snprintf(label, sizeof label, "port %d %s", ports[i], s(protocols[j]));
        show_service(label, 0, entry);
      }
    }
  } else if (!strcmp(which, "callback")) {
    void *module = dlopen("libnss_fltest.so.2", RTLD_NOW | RTLD_LOCAL);
    void (*install)(int (*)(void)) = module ? dlsym(module, "_nss_fltest_set_service_reentry") : NULL;
    if (!install) return 97;
    install(reenter_service_lookup);
    *service_api.error() = 123;
    struct servent *entry = service_api.name("fltest-reentry", "tcp");
    if (!entry || !service_reentry_calls) return 98;
    show_service("callback", 0, entry);
    install(NULL);
  } else if (!strcmp(which, "unchanged-errno")) {
    const char *names[] = {"fltest-errno-success", "fltest-errno-written", "fltest-errno-none", "fltest-errno-again", "fltest-errno-unavail"};
    for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
      *service_api.error() = 123;
      struct servent *entry = service_api.name(names[i], "tcp");
      show_service(names[i], 0, entry);
      struct servent value, *result;
      char buffer[8192];
      *service_api.error() = 123;
      int rc = service_api.name_r(names[i], "tcp", &value, buffer, sizeof buffer, &result);
      show_service(names[i], rc, result);
    }
  } else if (!strcmp(which, "reentrant") || !strcmp(which, "range-stop")) {
    const char *names[] = {"fltest-service", "fltest-large-service", "fltest-again", "fltest-unavail", "fltest-none", "http"};
    size_t sizes[] = {0, 7, 63, 79, 80, 1024, 8192};
    _Alignas(void *) char buffer[8193];
    size_t name_count = !strcmp(which, "range-stop") ? 2 : sizeof names / sizeof *names;
    for (size_t i = 0; i < name_count; ++i) {
      for (size_t j = 0; j < sizeof sizes / sizeof *sizes; ++j) {
        for (size_t offset = 0; offset < 2; ++offset) {
          memset(buffer, 0x5a, sizeof buffer);
          struct servent value, *result = (void *)1;
          *service_api.error() = 123;
          int rc = service_api.name_r(names[i], "tcp", &value, buffer + offset, sizes[j], &result);
          if (result && result != &value) return 93;
          if (sizes[j] + offset < sizeof buffer && buffer[sizes[j] + offset] != 0x5a) return 94;
          char label[128];
          snprintf(label, sizeof label, "reentrant %s %zu/%zu", names[i], sizes[j], offset);
          show_service(label, rc, result);
          if (result) {
            uintptr_t start = (uintptr_t)(buffer + offset), end = start + sizes[j];
            if ((uintptr_t)result->s_name < start || (uintptr_t)result->s_name >= end ||
                (uintptr_t)result->s_proto < start || (uintptr_t)result->s_proto >= end ||
                (uintptr_t)result->s_aliases < start || (uintptr_t)result->s_aliases >= end) return 95;
          }
        }
      }
    }
    struct servent value, *result;
    *service_api.error() = 123;
    int rc = service_api.port_r(htons(4344), NULL, &value, buffer, sizeof buffer, &result);
    show_service("reentrant port", rc, result);
  } else if (!strcmp(which, "profiles")) {
    void *module = dlopen("libnss_fltest.so.2", RTLD_NOW | RTLD_LOCAL);
    unsigned (*calls)(void) = module ? dlsym(module, "_nss_fltest_service_calls") : NULL;
    if (!calls) return 97;
    const char *services[] = {"fltest-service", "fltest-svc", "fltest-large-service", "http", "fltest-none", "4343"};
    const int hints[][3] = {{0,0,0},{SOCK_STREAM,0,0},{SOCK_DGRAM,0,0},{0,IPPROTO_TCP,0},
                           {0,IPPROTO_UDP,0},{SOCK_RAW,0,0},{SOCK_STREAM,IPPROTO_UDP,0},
                           {0,0,AI_NUMERICSERV}};
    for (size_t i = 0; i < sizeof services / sizeof *services; ++i) {
      for (size_t j = 0; j < sizeof hints / sizeof *hints; ++j) {
        unsigned before = calls();
        struct addrinfo hint = {.ai_family = AF_INET, .ai_socktype = hints[j][0],
                                .ai_protocol = hints[j][1], .ai_flags = hints[j][2]};
        int values[9], count = 0, rc;
        if (service_api.profiles) {
          count = service_api.profiles(services[i], &hint, values);
          rc = count < 0 ? count : 0;
        } else {
          struct addrinfo *result = NULL;
          rc = service_api.addr("127.0.0.1", services[i], &hint, &result);
          if (rc == 0) {
            for (struct addrinfo *entry = result; entry; entry = entry->ai_next) {
              if (count == 3 || entry->ai_family != AF_INET) return 96;
              values[count * 3] = ntohs(((struct sockaddr_in *)entry->ai_addr)->sin_port);
              values[count * 3 + 1] = entry->ai_socktype;
              values[count * 3 + 2] = entry->ai_protocol;
              ++count;
            }
            service_api.free_addr(result);
          }
        }
        if ((!strcmp(services[i], "4343") || (hint.ai_flags & AI_NUMERICSERV)) &&
            calls() != before) return 99;
        printf("profiles %s %zu rc=%d", services[i], j, rc);
        if (!rc) for (int k = 0; k < count; ++k) printf(" %d/%d/%d", values[k*3], values[k*3+1], values[k*3+2]);
        putchar('\n');
      }
    }
  } else if (!strcmp(which, "reverse")) {
    if (!service_api.reverse) return 90; /* Only a full deployed ABI may run this arm. */
    const int ports[] = {4343,4344,80,65534};
    const int flags[] = {NI_NUMERICHOST,NI_NUMERICHOST|NI_DGRAM,NI_NUMERICHOST|NI_NUMERICSERV};
    for (size_t i = 0; i < sizeof ports / sizeof *ports; ++i) {
      for (size_t j = 0; j < sizeof flags / sizeof *flags; ++j) {
        struct sockaddr_in address = {.sin_family=AF_INET,.sin_port=htons((uint16_t)ports[i]),.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
        char output[128] = {0};
        int rc = service_api.reverse((struct sockaddr *)&address, sizeof address, NULL, 0, output, sizeof output, flags[j]);
        printf("reverse %d %d rc=%d %s\n", ports[i], flags[j], rc, rc ? "-" : output);
      }
    }
  } else return 90;
  return 0;
}

int main(int argc, char **argv) {
  if (argc > 1 && !strcmp(argv[1], "services")) return service_probe(argc, argv);
  setvbuf(stdout, NULL, _IOLBF, 0);
  const char *only = argc > 1 ? argv[1] : NULL;
  if (!only || !strcmp(only, "pw")) section_pw();
  if (!only || !strcmp(only, "gr")) section_gr();
  if (!only || !strcmp(only, "sp")) section_sp();
  if (!only || !strcmp(only, "ent")) section_ent();
  if (!only || !strcmp(only, "r")) section_r();
  if (!only || !strcmp(only, "ig")) section_ig();
  return 0;
}
