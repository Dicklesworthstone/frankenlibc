#include <errno.h>
#include <nss.h>
#include <stdlib.h>
#include <string.h>

#ifndef MODULE
#define MODULE rpcsecret_first
#endif
#ifndef SOURCE_ID
#define SOURCE_ID 1
#endif
#define JOIN2(module, name) _nss_##module##_##name
#define JOIN(module, name) JOIN2(module, name)

static unsigned calls;
unsigned rpc_secretkey_calls(void) { return calls; }

/* This declaration makes the compiler check all four arguments against the
   installed GNU public module ABI, including the mutable password argument. */
extern nss_getsecretkey JOIN(MODULE, getsecretkey);
enum nss_status JOIN(MODULE, getsecretkey)(const char *name, char *key,
                                         char *password, int *error) {
    calls++;
    if (strcmp(name, "unix.7@franken.invalid") ||
        strcmp(password, "password-plus-module-tail")) {
        *error = EINVAL;
        return NSS_STATUS_UNAVAIL;
    }
    *error = SOURCE_ID == 1 ? ENODATA : EREMOTE;
    const char *setting = getenv(SOURCE_ID == 1 ? "RPC_SECRET_FIRST_STATUS" :
                                                "RPC_SECRET_SECOND_STATUS");
    enum nss_status result = NSS_STATUS_SUCCESS;
    if (setting && !strcmp(setting, "notfound")) result = NSS_STATUS_NOTFOUND;
    if (setting && !strcmp(setting, "unavail")) result = NSS_STATUS_UNAVAIL;
    if (setting && !strcmp(setting, "tryagain")) result = NSS_STATUS_TRYAGAIN;
    const char *bad = getenv("RPC_SECRET_BAD_RESULT");
    if (result != NSS_STATUS_SUCCESS) {
        if (bad && !strcmp(bad, "failed-write")) memset(key, 'd', 49);
        return result;
    }
    if (SOURCE_ID == 1 && getenv("RPC_SECRET_EMPTY_FIRST")) {
        key[0] = 0;
        return result;
    }
    memset(key, SOURCE_ID == 1 ? 'a' : 'B', 48);
    key[48] = 0;
    if (bad && !strcmp(bad, "unterminated")) key[48] = 'a';
    if (bad && !strcmp(bad, "nonhex")) key[0] = 'z';
    if (bad && !strcmp(bad, "short")) key[1] = 0;
    if (bad && !strcmp(bad, "mutate-password")) password[0] = 'x';
    return result;
}
