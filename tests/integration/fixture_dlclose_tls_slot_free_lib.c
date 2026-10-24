/* Plugin for fixture_dlclose_tls_slot_free: dynamic TLS plus libc + libm
 * dependencies, so the host loader (not fl's native loader) owns it and its
 * TLS block comes from ld.so's __tls_get_addr allocation path. */
#include <math.h>
#include <stdio.h>
#include <string.h>

__thread int plugin_gd_tls = 10;
__thread char plugin_buf[4096];

const char *plugin_touch(void) {
    plugin_gd_tls += 5;
    int n = snprintf(plugin_buf, sizeof(plugin_buf), "ie=%d", plugin_gd_tls);
    return (n > 0 && strchr(plugin_buf, '=') != NULL && cbrt(plugin_buf[1] + 8.0) > 1.0)
        ? plugin_buf
        : 0;
}
