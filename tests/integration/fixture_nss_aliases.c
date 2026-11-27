/* Provider-pinned aliases records, shared cursors, buffer retries and NSS.
 * Each invocation runs in a fresh process with a private aliases database.
 * Every byte in every member contributes to the printed fingerprint. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <aliases.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int same_object(const char *path, void *address) {
  Dl_info info;
  struct stat expected, actual;
  return dladdr(address, &info) && info.dli_fname && !stat(path, &expected) &&
         !stat(info.dli_fname, &actual) && expected.st_dev == actual.st_dev &&
         expected.st_ino == actual.st_ino;
}

static void *symbol(void *provider, const char *path, const char *name) {
  void *address = dlsym(provider, name);
  if (!address || !same_object(path, address)) {
    fprintf(stderr, "wrong provider for %s\n", name);
    exit(91);
  }
  return address;
}

static struct {
  int *(*error)(void);
  void (*set)(void), (*end)(void);
  struct aliasent *(*next)(void), *(*name)(const char *);
  int (*next_r)(struct aliasent *, char *, size_t, struct aliasent **);
  int (*name_r)(const char *, struct aliasent *, char *, size_t, struct aliasent **);
  int (*files_set)(void), (*files_end)(void);
  int (*files_next)(struct aliasent *, char *, size_t, int *);
  int (*files_name)(const char *, struct aliasent *, char *, size_t, int *);
  int (*configure)(const char *, const char *);
} api;

static void load(void *provider, const char *path) {
#define LOAD(field, name) *(void **)(&api.field) = symbol(provider, path, name)
  LOAD(error, "__errno_location");
  LOAD(set, "setaliasent"); LOAD(end, "endaliasent");
  LOAD(next, "getaliasent"); LOAD(name, "getaliasbyname");
  LOAD(next_r, "getaliasent_r"); LOAD(name_r, "getaliasbyname_r");
  LOAD(files_set, "_nss_files_setaliasent"); LOAD(files_end, "_nss_files_endaliasent");
  LOAD(files_next, "_nss_files_getaliasent_r");
  LOAD(files_name, "_nss_files_getaliasbyname_r");
  LOAD(configure, "__nss_configure_lookup");
#undef LOAD
}

static unsigned long long fingerprint(const unsigned char *text, size_t length) {
  uint64_t value = UINT64_C(14695981039346656037);
  for (size_t index = 0; index < length; ++index)
    value = (value ^ text[index]) * UINT64_C(1099511628211);
  return (unsigned long long)value;
}

static void show(const struct aliasent *entry) {
  if (!entry) { puts(" NULL"); return; }
  if (!entry->alias_name || !entry->alias_members || entry->alias_members_len > 4096) exit(92);
  size_t length = strlen(entry->alias_name);
  if (length > 65536) exit(92);
  printf(" name=");
  for (size_t index = 0; index < length; ++index)
    printf("%02x", (unsigned char)entry->alias_name[index]);
  printf(" count=%zu local=%d", entry->alias_members_len, entry->alias_local);
  for (size_t index = 0; index < entry->alias_members_len; ++index) {
    if (!entry->alias_members[index]) exit(92);
    const unsigned char *member = (unsigned char *)entry->alias_members[index];
    length = strlen((const char *)member);
    if (length > 65536) exit(92);
    printf(" %zu:%016llx", length, fingerprint(member, length));
  }
  putchar('\n');
}

static void bounded_string(const char *text, const char *buffer, size_t capacity) {
  uintptr_t address = (uintptr_t)text, start = (uintptr_t)buffer;
  if (address < start || address - start >= capacity ||
      !memchr(text, 0, capacity - (size_t)(address - start))) exit(92);
}

static void bounded(const struct aliasent *entry, const char *buffer, size_t capacity) {
  uintptr_t members = (uintptr_t)entry->alias_members, start = (uintptr_t)buffer;
  if (members % _Alignof(char *) || members < start || members - start > capacity ||
      entry->alias_members_len > (capacity - (size_t)(members - start)) / sizeof(char *)) exit(92);
  bounded_string(entry->alias_name, buffer, capacity);
  for (size_t index = 0; index < entry->alias_members_len; ++index)
    bounded_string(entry->alias_members[index], buffer, capacity);
}

/* kind: 0 public reentrant, 1 direct files provider, 2 public non-reentrant.
 * A NULL key selects enumeration. Bytes outside the declared buffer remain
 * canaries, including a zero-length caller buffer. */
static int observe(const char *label, const char *key, int kind,
                   size_t capacity, size_t skew) {
  _Alignas(16) unsigned char storage[65568];
  char *buffer = (char *)storage + 16 + skew;
  struct aliasent entry = {0}, *result = (void *)1;
  int error = 91, status;
  if (capacity > 65536 || skew > 7) exit(92);
  memset(storage, 0x5a, sizeof storage);
  *api.error() = 77;
  if (kind == 2) {
    result = key ? api.name(key) : api.next();
    status = result != NULL;
  } else if (kind == 1) {
    status = key ? api.files_name(key, &entry, buffer, capacity, &error)
                 : api.files_next(&entry, buffer, capacity, &error);
    result = status == 1 ? &entry : NULL;
  } else {
    status = key ? api.name_r(key, &entry, buffer, capacity, &result)
                 : api.next_r(&entry, buffer, capacity, &result);
    if (result && result != &entry) exit(92);
  }
  int saved_errno = *api.error();
  if (kind != 2) {
    if ((unsigned char)buffer[-1] != 0x5a || (unsigned char)buffer[capacity] != 0x5a) exit(92);
    if (result) bounded(result, buffer, capacity);
  }
  printf("%s kind=%d capacity=%zu skew=%zu status=%d errno=%d error=%d",
         label, kind, capacity, skew, status, saved_errno, kind == 1 ? error : -1);
  show(result);
  return result != NULL;
}

static void lifecycle(const char *label, int direct, int end) {
  *api.error() = 77;
  int status = 0;
  if (direct) status = end ? api.files_end() : api.files_set();
  else if (end) api.end();
  else api.set();
  printf("%s status=%d errno=%d\n", label, status, *api.error());
}

static void lookup(void) {
  char long_name[401];
  memset(long_name, 'n', sizeof long_name - 1); long_name[400] = 0;
  const char *keys[] = {"first", "FIRST", "folded", "included", "empty", "absent",
                        "many", "large", long_name, "space   ", "tail"};
  for (size_t index = 0; index < sizeof keys / sizeof *keys; ++index) {
    char label[32]; snprintf(label, sizeof label, "lookup-%zu", index);
    for (int kind = 0; kind < 3; ++kind) observe(label, keys[index], kind, 65536, 1);
  }
  struct aliasent *entry = api.name("first");
  if (entry) {
    entry = api.name(entry->alias_name);
    printf("lookup-own-key"); show(entry);
  }
}

static void bounds(void) {
  const size_t sizes[] = {0, 1, 7, 8, 15, 16, 23, 24, 31, 32, 63, 64, 111, 112, 4096, 65536};
  for (size_t index = 0; index < sizeof sizes / sizeof *sizes; ++index)
    for (int kind = 0; kind < 2; ++kind) {
      observe("bounds-hit", "first", kind, sizes[index], 0);
      observe("bounds-miss", "absent", kind, sizes[index], 0);
    }
  for (size_t skew = 1; skew < sizeof(char *); ++skew)
    for (int kind = 0; kind < 2; ++kind)
      observe("bounds-misaligned", "first", kind, 65536, skew);
}

static void warm_enumeration_buffer(void) {
  for (unsigned round = 0; round < 16; ++round) {
    int grew = 0;
    api.set();
    for (unsigned count = 0; count < 32; ++count) {
      *api.error() = 0;
      struct aliasent *entry = api.next();
      if (*api.error() == ERANGE) grew = 1;
      if (!entry) break;
      if (count == 31) exit(93);
    }
    if (!grew) return;
  }
  exit(93);
}

static void enumeration(void) {
  lifecycle("public-set", 0, 0);
  observe("public-small-1", NULL, 0, 1, 0);
  observe("public-small-2", NULL, 0, 1, 0);
  observe("public-retry", NULL, 0, 65536, 1);
  lifecycle("files-set", 1, 0);
  observe("files-small-1", NULL, 1, 1, 0);
  observe("files-small-2", NULL, 1, 1, 0);
  observe("files-retry", NULL, 1, 65536, 1);
  observe("key-during-enum", "tail", 0, 65536, 1);
  observe("public-shared-next", NULL, 0, 65536, 1);
  observe("files-shared-next", NULL, 1, 65536, 1);
  for (unsigned count = 0; count < 32; ++count)
    if (!observe("public-rest", NULL, 0, 65536, 1)) break;
  observe("eof-small", NULL, 0, 1, 0);
  observe("eof-retry", NULL, 0, 65536, 1);
  /* GNU's cold non-reentrant buffer growth can consume the oversized record
   * instead of replaying it. Warm that buffer before this differential pass;
   * the separate candidate-only growing scenario requires lossless replay. */
  warm_enumeration_buffer();
  lifecycle("public-rewind", 0, 0);
  for (unsigned count = 0; count < 32; ++count)
    if (!observe("public-growing", NULL, 2, 0, 0)) break;
  lifecycle("files-end", 1, 1);
  observe("public-after-files-end", NULL, 0, 65536, 1);
  lifecycle("public-end", 0, 1);
}

static void growing(void) {
  unsigned count = 0, many = 0, large = 0, long_name = 0;
  api.set();
  for (;;) {
    struct aliasent *entry = api.next();
    if (!entry) break;
    if (++count > 8) exit(94);
    if (!strcmp(entry->alias_name, "many") && entry->alias_members_len == 80) ++many;
    if (!strcmp(entry->alias_name, "large") && entry->alias_members_len == 1 &&
        strlen(entry->alias_members[0]) == 5000) ++large;
    if (strlen(entry->alias_name) == 400) ++long_name;
    printf("growing-record"); show(entry);
  }
  api.end();
  if (count != 8 || many != 1 || large != 1 || long_name != 1) exit(94);
  printf("growing entries=%u many=%u large=%u long-name=%u\n", count, many, large, long_name);
}

static void recovery(void) {
  observe("recovery-public-missing", NULL, 0, 65536, 1);
  observe("recovery-files-missing", NULL, 1, 65536, 1);
  lifecycle("recovery-files-set", 1, 0);
  lifecycle("recovery-public-set", 0, 0);
  /* The runner supplies a writable, fresh private /etc for this scenario. */
  FILE *file = fopen("/etc/aliases", "w");
  if (!file) exit(94);
  fputs("recovered: alice\nsecond: bob\n", file);
  if (fclose(file)) exit(94);
  puts("recovery-created");
  if (!observe("recovery-public-found", NULL, 0, 65536, 1)) exit(94);
  if (!observe("recovery-files-found", NULL, 1, 65536, 1)) exit(94);
  observe("recovery-public-eof", NULL, 0, 65536, 1);
  observe("recovery-files-eof", NULL, 1, 65536, 1);
  lifecycle("recovery-public-end", 0, 1);
}

static void policy(const char *sources) {
  *api.error() = 77;
  int status = api.configure("aliases", sources);
  printf("configure status=%d errno=%d\n", status, *api.error());
  if (status != 0) exit(94);
  const char *keys[] = {"module-hit", "module-range", "module-again", "module-down", "first", "absent"};
  for (size_t index = 0; index < sizeof keys / sizeof *keys; ++index) {
    observe(keys[index], keys[index], 0, 32, 1);
    observe(keys[index], keys[index], 0, 65536, 1);
    observe(keys[index], keys[index], 2, 0, 0);
  }
  for (unsigned round = 0; round < 2; ++round) {
    lifecycle("policy-set", 0, 0);
    for (unsigned count = 0; count < 32; ++count)
      if (!observe("policy-next", NULL, 0, 65536, 1)) break;
    lifecycle("policy-end", 0, 1);
  }
}

static unsigned reentries;
static int reentry_callback(void) {
  *api.error() = 77;
  struct aliasent *entry = api.next();
  int accepted = entry == NULL && *api.error() == EDEADLK;
  if (accepted) ++reentries;
  return accepted;
}

static void reentry(void) {
  void *module = dlopen("libnss_flalias.so.2", RTLD_NOW | RTLD_LOCAL);
  void (*install)(int (*)(void));
  if (!module) exit(94);
  *(void **)(&install) = dlsym(module, "flalias_install_reentry");
  if (!install || api.configure("aliases", "flalias") != 0) exit(94);
  install(reentry_callback);
  api.set();
  if (!observe("reentry-outer", NULL, 0, 65536, 1) || reentries != 1) exit(94);
  printf("reentry nested-EDEADLK=%u\n", reentries);
  api.end();
}

int main(int argc, char **argv) {
  if (argc < 3 || argc > 4) return 90;
  int host = !strcmp(argv[1], "host");
  void *gnu = dlopen("libc.so.6", RTLD_NOW | RTLD_LOCAL);
  Dl_info gnu_info;
  if (!gnu || !dladdr(dlsym(gnu, "getaliasbyname"), &gnu_info)) return 91;
  void *provider = host ? gnu : dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!provider || (!host && same_object(argv[1], dlsym(gnu, "getaliasbyname")))) return 91;
  const char *path = host ? gnu_info.dli_fname : argv[1];
  load(provider, path);
  setvbuf(stdout, NULL, _IOLBF, 0);
  if (!strcmp(argv[2], "provider")) puts(path);
  else if (!strcmp(argv[2], "lookup")) lookup();
  else if (!strcmp(argv[2], "bounds")) bounds();
  else if (!strcmp(argv[2], "enumeration")) enumeration();
  else if (!strcmp(argv[2], "policy") && argc == 4) policy(argv[3]);
  else if (!strcmp(argv[2], "reentry") && !host) reentry();
  else if (!strcmp(argv[2], "growing") && !host) growing();
  else if (!strcmp(argv[2], "recovery")) recovery();
  else return 90;
  return 0;
}
