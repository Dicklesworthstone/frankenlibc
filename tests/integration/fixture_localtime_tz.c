/* fixture_localtime_tz.c — local time must honour TZ / /etc/localtime
 * (bd-rc0923-epic-eeuy4f.11). fl was UTC-only. Prints tzset globals,
 * localtime_r + strftime %Z %z, tm_isdst/tm_gmtoff, mktime round trips
 * (including a skipped and a repeated hour) and ctime; the preload smoke
 * corpus runs it under several TZ values and requires byte parity with
 * host glibc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* `sweep` mode: for each zone, walk 1900..2100 in 1-day steps, bisect every
 * offset/isdst/abbreviation change to the exact second, and print every
 * transition with the local fields on both sides plus a mktime round trip.
 * The ~40 zones cover both hemispheres, half/quarter-hour offsets, zones
 * that changed standard offset, abolished DST, and POSIX-rule-only TZ. */
static const char *const SWEEP_ZONES[] = {
    "America/New_York", "America/Chicago", "America/Denver", "America/Phoenix",
    "America/Los_Angeles", "America/Anchorage", "Pacific/Honolulu", "America/Halifax",
    "America/St_Johns", "America/Sao_Paulo", "America/Argentina/Buenos_Aires",
    "America/Santiago", "America/Mexico_City", "America/Havana", "Europe/London",
    "Europe/Dublin", "Europe/Lisbon", "Europe/Paris", "Europe/Berlin", "Europe/Moscow",
    "Europe/Istanbul", "Europe/Kyiv", "Africa/Cairo", "Africa/Casablanca",
    "Africa/Johannesburg", "Asia/Jerusalem", "Asia/Tehran", "Asia/Kolkata",
    "Asia/Kathmandu", "Asia/Shanghai", "Asia/Tokyo", "Asia/Seoul", "Asia/Singapore",
    "Australia/Sydney", "Australia/Adelaide", "Australia/Lord_Howe", "Australia/Perth",
    "Pacific/Auckland", "Pacific/Chatham", "Pacific/Apia", "Pacific/Kiritimati",
    "UTC", "EST5EDT,M3.2.0,M11.1.0", "<-03>3<-02>,M3.5.0/-2,M10.5.0/-1",
};

static void describe(time_t t, char *out, size_t n) {
    struct tm tm;
    if (!localtime_r(&t, &tm)) { snprintf(out, n, "ERR"); return; }
    char b[96];
    strftime(b, sizeof b, "%Y-%m-%d %H:%M:%S %Z %z", &tm);
    struct tm c = tm;
    time_t back = mktime(&c);
    snprintf(out, n, "%s dst=%d off=%ld back=%s", b, tm.tm_isdst, tm.tm_gmtoff,
             back == t ? "=" : "!");
}

static int state_of(time_t t, long *off, int *dst, char *abbr) {
    struct tm tm;
    if (!localtime_r(&t, &tm)) return 0;
    *off = tm.tm_gmtoff; *dst = tm.tm_isdst;
    snprintf(abbr, 16, "%s", tm.tm_zone ? tm.tm_zone : "");
    return 1;
}

static int sweep(void) {
    const time_t lo = -2208988800LL, hi = 4102444800LL; /* 1900..2100 */
    for (size_t z = 0; z < sizeof SWEEP_ZONES / sizeof *SWEEP_ZONES; z++) {
        setenv("TZ", SWEEP_ZONES[z], 1);
        tzset();
        printf("zone %s tzname=%s/%s timezone=%ld daylight=%d\n", SWEEP_ZONES[z],
               tzname[0], tzname[1], timezone, daylight);
        long po; int pd; char pa[16];
        state_of(lo, &po, &pd, pa);
        unsigned count = 0;
        for (time_t t = lo + 86400; t <= hi; t += 86400) {
            long o; int d; char a[16];
            state_of(t, &o, &d, a);
            if (o == po && d == pd && strcmp(a, pa) == 0) continue;
            time_t a0 = t - 86400, a1 = t; /* state(a0) == prev, state(a1) != prev */
            while (a1 - a0 > 1) {
                time_t m = a0 + (a1 - a0) / 2;
                long mo; int md; char ma[16];
                state_of(m, &mo, &md, ma);
                if (mo == po && md == pd && strcmp(ma, pa) == 0) a0 = m; else a1 = m;
            }
            char before[160], after[160];
            describe(a1 - 1, before, sizeof before);
            describe(a1, after, sizeof after);
            printf("  %lld: %s | %s\n", (long long)a1, before, after);
            count++;
            po = o; pd = d; memcpy(pa, a, sizeof pa);
        }
        printf("  transitions=%u\n", count);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "sweep") == 0) return sweep();
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
