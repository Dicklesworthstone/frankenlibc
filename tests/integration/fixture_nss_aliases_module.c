/* External aliases provider: only the documented NSS module ABI is used. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <aliases.h>
#include <errno.h>
#include <nss.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned position, resets;
static int (*reenter)(void);

void flalias_install_reentry(int (*callback)(void)) { reenter = callback; }

static enum nss_status fill(const char *name, int large, struct aliasent *out,
                           char *buffer, size_t length, int *error) {
  size_t padding = (sizeof(char *) - (uintptr_t)buffer % sizeof(char *)) % sizeof(char *);
  size_t member_length = large ? 5000 : strlen("module-member");
  char round[32];
  int round_length = snprintf(round, sizeof round, "reset-%u", resets);
  size_t need = padding + 2 * sizeof(char *) + strlen(name) + 1 +
                member_length + 1 + (size_t)round_length + 1;
  if (length < need || (large && length < 8192)) {
    *error = ERANGE;
    return NSS_STATUS_TRYAGAIN;
  }
  char **members = (char **)(buffer + padding);
  char *cursor = (char *)(members + 2);
  out->alias_name = cursor;
  strcpy(cursor, name);
  cursor += strlen(name) + 1;
  members[0] = cursor;
  if (large) { memset(cursor, 'm', member_length); cursor[member_length] = 0; }
  else strcpy(cursor, "module-member");
  cursor += member_length + 1;
  members[1] = cursor;
  memcpy(cursor, round, (size_t)round_length + 1);
  out->alias_members_len = 2;
  out->alias_members = members;
  out->alias_local = 0;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_flalias_setaliasent(void) {
  position = 0;
  ++resets;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_flalias_endaliasent(void) {
  position = 0;
  return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_flalias_getaliasent_r(struct aliasent *out, char *buffer,
                                        size_t length, int *error) {
  if (position != 0) return NSS_STATUS_NOTFOUND;
  if (reenter) {
    if (reenter() != 1) { *error = EIO; return NSS_STATUS_UNAVAIL; }
    *error = 0;
  }
  enum nss_status status = fill("module-enum", 0, out, buffer, length, error);
  if (status == NSS_STATUS_SUCCESS) ++position;
  return status;
}

enum nss_status _nss_flalias_getaliasbyname_r(const char *name, struct aliasent *out,
                                           char *buffer, size_t length, int *error) {
  if (!strcmp(name, "module-again")) { *error = EAGAIN; return NSS_STATUS_TRYAGAIN; }
  if (!strcmp(name, "module-down")) { *error = EIO; return NSS_STATUS_UNAVAIL; }
  if (!strcmp(name, "module-range")) return fill(name, 1, out, buffer, length, error);
  if (!strcmp(name, "module-hit") || !strcmp(name, "first"))
    return fill("module-hit", 0, out, buffer, length, error);
  return NSS_STATUS_NOTFOUND;
}
