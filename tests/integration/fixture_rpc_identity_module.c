#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <nss.h>
#include <stdlib.h>
#include <string.h>

/* Compile this public-ABI module twice. A distinct uid, gid, key and call
   counter proves which configured source actually supplied each result. */
#ifndef MODULE
#define MODULE rpcid_first
#endif
#ifndef SOURCE_ID
#define SOURCE_ID 1
#endif
#define JOIN2(module, name) _nss_##module##_##name
#define JOIN(module, name) JOIN2(module, name)
static unsigned calls[2];
unsigned rpc_identity_calls(unsigned kind) { return kind < 2 ? calls[kind] : 0; }

static enum nss_status status(void) {
    const char *value = getenv(SOURCE_ID == 1 ? "RPC_IDENTITY_FIRST_STATUS" :
                                             "RPC_IDENTITY_SECOND_STATUS");
    if (!value || !strcmp(value, "success")) return NSS_STATUS_SUCCESS;
    if (!strcmp(value, "notfound")) return NSS_STATUS_NOTFOUND;
    if (!strcmp(value, "tryagain")) return NSS_STATUS_TRYAGAIN;
    return NSS_STATUS_UNAVAIL;
}

enum nss_status JOIN(MODULE, netname2user)(char *name, uid_t *uid, gid_t *gid,
                                        int *count, gid_t *groups, int *error) {
    (void)name;
    /* GNU <nss.h> declares error, but older GLIBC_2.2.5 callers do not reliably
       pass it. Leaving it alone permits an independent GNU status oracle;
       the candidate must still use the complete public six-argument ABI. */
    if (getenv("RPC_IDENTITY_CHECK_USER_ERRNO")) *error = EKEYREJECTED;
    calls[0]++;
    enum nss_status result = status();
    if (result != NSS_STATUS_SUCCESS) return result;
    *uid = SOURCE_ID == 1 ? 1001 : 2002;
    *gid = SOURCE_ID == 1 ? 42 : 84;
    *count = 2;
    groups[0] = SOURCE_ID == 1 ? 17 : 29;
    groups[1] = SOURCE_ID == 1 ? 88 : 93;
    const char *bad = getenv("RPC_IDENTITY_BAD_RESULT");
    if (bad && !strcmp(bad, "negative-count")) *count = -1;
    if (bad && !strcmp(bad, "oversize-count")) *count = 65537;
    return result;
}

enum nss_status JOIN(MODULE, getpublickey)(const char *name, char *key, int *error) {
    (void)name;
    calls[1]++;
    *error = SOURCE_ID == 1 ? ENODATA : EREMOTE;
    enum nss_status result = status();
    if (result != NSS_STATUS_SUCCESS) return result;
    memset(key, SOURCE_ID == 1 ? 'a' : 'B', 48);
    key[48] = 0;
    const char *bad = getenv("RPC_IDENTITY_BAD_RESULT");
    if (bad && !strcmp(bad, "unterminated-key")) key[48] = 'a';
    if (bad && !strcmp(bad, "nonhex-key")) key[0] = 'z';
    return result;
}
