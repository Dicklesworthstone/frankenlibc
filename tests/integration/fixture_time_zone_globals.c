/* fixture_time_zone_globals.c — time-zone state glibc programs observe
 * (bd-rc0923-epic-eeuy4f.11). Output must be byte-identical to glibc in strict
 * and hardened modes (both read the same /usr/share/zoneinfo):
 *  - tzname/daylight/timezone after tzset and after localtime at instants
 *    spread over each zone's history (glibc recomputes them per instant);
 *  - strftime %s/%Z/%z/%c on a hand-built struct tm over every
 *    tm_zone x tm_isdst x tm_gmtoff combination (%s is local mktime).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void tz_globals(void) {
    const char *zones[] = {"Asia/Kolkata", "Europe/Istanbul", "Africa/Casablanca", "Asia/Kathmandu",
                           "Australia/Lord_Howe", "America/New_York", "Asia/Tokyo", "Asia/Shanghai",
                           "Europe/Moscow", "Pacific/Honolulu", "America/Phoenix", "Atlantic/Reykjavik",
                           "UTC", "Europe/Dublin", "America/Sao_Paulo", "Asia/Tehran", "Pacific/Apia",
                           "Europe/London", "America/Caracas", "Asia/Singapore"};
    time_t samples[] = {-2000000000, 0, 500000000, 1000000000, 1700000000, 2200000000};
    for (int z = 0; z < 20; z++) {
        setenv("TZ", zones[z], 1);
        tzset();
        printf("%s tzset: %s/%s daylight=%d timezone=%ld\n", zones[z], tzname[0], tzname[1], daylight, timezone);
        for (int s = 0; s < 6; s++) {
            struct tm tm;
            localtime_r(&samples[s], &tm);
            printf("  @%ld %s isdst=%d -> %s/%s daylight=%d timezone=%ld\n", (long)samples[s], tm.tm_zone,
                   tm.tm_isdst, tzname[0], tzname[1], daylight, timezone);
        }
    }
    }

static void strftime_zone_fields(void) {
    const char *zones[] = {"America/New_York", "UTC", "Asia/Kolkata"};
    const char *names[] = {NULL, "XYZ", ""};
    int dsts[] = {-1, 0, 1};
    long offs[] = {0, 3600, -19800};
    for (int z = 0; z < 3; z++) {
        setenv("TZ", zones[z], 1);
        tzset();
        for (int n = 0; n < 3; n++)
            for (int d = 0; d < 3; d++)
                for (int o = 0; o < 3; o++) {
                    struct tm tm = {.tm_year = 124, .tm_mon = 6, .tm_mday = 1, .tm_hour = 12};
                    tm.tm_isdst = dsts[d];
                    tm.tm_gmtoff = offs[o];
                    tm.tm_zone = names[n];
                    char s[96];
                    size_t len = strftime(s, sizeof s, "[%s] [%Z] [%z] [%c]", &tm);
                    printf("%s zone=%s isdst=%d gmtoff=%ld -> %zu %s\n", zones[z], names[n] ? names[n] : "NULL",
                           dsts[d], offs[o], len, s);
                }
    }
    }

int main(void) {
    tz_globals();
    strftime_zone_fields();
    return 0;
}
