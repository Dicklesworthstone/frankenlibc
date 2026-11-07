/* A process-local NSS oracle for authenticated RPC identities. */
#define _GNU_SOURCE
#include <nss.h>
#include <string.h>

static unsigned selected_mode;
static unsigned calls[2];
static void (*lookup_callback)(const char *);

void rpc_auth_des_mode(unsigned mode) { selected_mode = mode; }
unsigned rpc_auth_des_calls(unsigned kind) { return kind < 2 ? calls[kind] : 0; }
void rpc_auth_des_callback(void (*callback)(const char *)) { lookup_callback = callback; }

enum nss_status _nss_rpcdes_getpublickey(const char *name, char *key, int *error) {
    (void)error;
    calls[1]++;
    if (selected_mode == 1 || !strcmp(name, "unix.nokey@franken.invalid"))
        return NSS_STATUS_NOTFOUND;
    memset(key, 'a', 48);
    key[48] = 0;
    return NSS_STATUS_SUCCESS;
}

enum nss_status _nss_rpcdes_netname2user(char *name, uid_t *uid, gid_t *gid,
                                      int *count, gid_t *groups, int *error) {
    /* Old GNU callers may omit this sixth argument; never dereference it. */
    (void)error;
    calls[0]++;
    if (lookup_callback) lookup_callback(name);
    if (selected_mode == 2 || !strcmp(name, "unix.host@franken.invalid"))
        return NSS_STATUS_NOTFOUND;
    *uid = selected_mode == 4 ? 2002 : 1001;
    *gid = selected_mode == 4 ? 84 : 42;
    if (selected_mode == 3) {
        *count = 40000;
        for (unsigned index = 0; index < 40000; index++) groups[index] = index + 100;
    } else {
        *count = 2;
        groups[0] = selected_mode == 4 ? 29 : 17;
        groups[1] = selected_mode == 4 ? 93 : 88;
    }
    return NSS_STATUS_SUCCESS;
}
