/* fixture_localtime_tz.c — local time must honour TZ / /etc/localtime
 * (bd-rc0923-epic-eeuy4f.11). fl was UTC-only. Prints tzset globals,
 * localtime_r + strftime %Z %z, tm_isdst/tm_gmtoff, mktime round trips
 * (including a skipped and a repeated hour) and ctime; the preload smoke
 * corpus runs it under several TZ values and requires byte parity with
 * host glibc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(int argc, char **argv) {
    tzset();
    printf("tzname=%s/%s timezone=%ld daylight=%d\n", tzname[0], tzname[1], timezone, daylight);
    long ts[] = {0, 1700000000, 1678604400, 1699164000, 1719835200, 4102444800L, -2000000000L};
    for (unsigned i = 0; i < sizeof ts / sizeof *ts; i++) {
        time_t t = ts[i]; struct tm tm; localtime_r(&t, &tm);
        char b[64]; strftime(b, sizeof b, "%Y-%m-%d %H:%M:%S %Z %z", &tm);
        struct tm c = tm; c.tm_isdst = -1; time_t back = mktime(&c);
        printf("%ld -> %s isdst=%d gmtoff=%ld back=%ld\n", t, b, tm.tm_isdst, tm.tm_gmtoff, (long)back);
    }
    struct tm g = {0}; g.tm_year = 123; g.tm_mon = 2; g.tm_mday = 12; g.tm_hour = 2; g.tm_min = 30; g.tm_isdst = -1;
    time_t gap = mktime(&g); printf("gap 02:30 -> %ld %02d:%02d isdst=%d\n", (long)gap, g.tm_hour, g.tm_min, g.tm_isdst);
    struct tm o = {0}; o.tm_year = 123; o.tm_mon = 10; o.tm_mday = 5; o.tm_hour = 1; o.tm_min = 30; o.tm_isdst = -1;
    time_t ov = mktime(&o); printf("overlap 01:30 -> %ld isdst=%d\n", (long)ov, o.tm_isdst);
    printf("ctime=%s", ctime(&(time_t){1700000000}));
    return 0;
}
