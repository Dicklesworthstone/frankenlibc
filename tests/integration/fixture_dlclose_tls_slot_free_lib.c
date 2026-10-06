/* Plugin for fixture_dlclose_tls_slot_free: dynamic TLS plus a libm
 * dependency, so the host loader (not fl's native loader) owns it and its
 * TLS block comes from ld.so's __tls_get_addr allocation path. */
#include <math.h>

__thread char plugin_buf[4096];

const char *plugin_touch(void) {
    plugin_buf[0] = 'x';
    return cbrt(plugin_buf[1] + 8.0) > 1.0 ? plugin_buf : 0;
}
