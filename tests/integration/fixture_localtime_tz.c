/* fixture_localtime_tz.c — local time must honour TZ / /etc/localtime
 * (bd-rc0923-epic-eeuy4f.11). fl was UTC-only. Prints tzset globals,
 * localtime_r + strftime %Z %z, tm_isdst/tm_gmtoff, mktime round trips
 * (including a skipped and a repeated hour) and ctime; the preload smoke
 * corpus runs it under several TZ values and requires byte parity with
 * host glibc.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <limits.h>
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
        if (!state_of(lo, &po, &pd, pa)) return 1;
        unsigned count = 0;
        for (time_t t = lo + 86400; t <= hi; t += 86400) {
            long o; int d; char a[16];
            if (!state_of(t, &o, &d, a)) return 1;
            if (o == po && d == pd && strcmp(a, pa) == 0) continue;
            time_t a0 = t - 86400, a1 = t; /* state(a0) == prev, state(a1) != prev */
            while (a1 - a0 > 1) {
                time_t m = a0 + (a1 - a0) / 2;
                long mo; int md; char ma[16];
                if (!state_of(m, &mo, &md, ma)) return 1;
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

/* These cases do not depend on installed tzdata. Keep them in the default
 * fixture path so the existing host/preload smoke comparison exercises the
 * actual exported mktime/localtime_r ABI in both runtime modes. */
static int timezone_regressions(void) {
    static const struct {
        const char *zone;
        int month, day, hour, minute, wday, yday;
        long long wall;
        long standard, daylight;
        int fixed;
    } cases[] = {
        {"EST5EDT,M3.2.0,M11.1.0", 3, 12, 2, 30, 0, 70,
         1678588200LL, -18000, -14400, 0},
        {"AEST-10AEDT,M10.1.0,M4.1.0/3", 10, 1, 2, 30, 0, 273,
         1696127400LL, 36000, 39600, 0},
        {"<+1030>-10:30<+11>-11,M10.1.0,M4.1.0", 10, 1, 2, 15, 0, 273,
         1696126500LL, 37800, 39600, 0},
        {"IST-1GMT0,M10.5.0,M3.5.0/1", 3, 26, 1, 30, 0, 84,
         1679794200LL, 3600, 0, 0},
        {"UTC0", 7, 1, 12, 0, 6, 181, 1688212800LL, 0, 3600, 1},
        {"GMT0", 7, 1, 12, 0, 6, 181, 1688212800LL, 0, 3600, 1},
        {"JST-9", 7, 1, 12, 0, 6, 181, 1688212800LL, 32400, 36000, 1},
        {"<+0530>-5:30", 7, 1, 12, 0, 6, 181,
         1688212800LL, 19800, 23400, 1},
    };
    static const int hints[] = {-2, -1, 0, 1, 2, INT_MAX};
    unsigned checked = 0, failures = 0;
    for (size_t c = 0; c < sizeof cases / sizeof *cases; c++) {
        if (setenv("TZ", cases[c].zone, 1) != 0) {
            perror("timezone regression setenv");
            return 1;
        }
        tzset();
        /* Reverse the order too: mktime caches an offset across calls. */
        for (size_t order = 0; order < 2; order++) {
            const size_t count = sizeof hints / sizeof *hints;
            for (size_t i = 0; i < count; i++) {
                const int hint = hints[order ? count - 1 - i : i];
                const int want_dst = hint > 0;
                const long used = want_dst ? cases[c].daylight : cases[c].standard;
                const int normalized_dst = cases[c].fixed ? 0 : !want_dst;
                const long normalized_off = normalized_dst
                    ? cases[c].daylight : cases[c].standard;
                const long normalized_minutes = cases[c].hour * 60 + cases[c].minute
                    + (normalized_off - used) / 60;
                const time_t expected = (time_t)(cases[c].wall - used);
                struct tm tm = {0};
                tm.tm_year = 123;
                tm.tm_mon = cases[c].month - 1;
                tm.tm_mday = cases[c].day;
                tm.tm_hour = cases[c].hour;
                tm.tm_min = cases[c].minute;
                tm.tm_isdst = hint;
                const time_t actual = mktime(&tm);
                const int ok = actual == expected && tm.tm_year == 123
                    && tm.tm_mon == cases[c].month - 1 && tm.tm_mday == cases[c].day
                    && tm.tm_hour == normalized_minutes / 60
                    && tm.tm_min == normalized_minutes % 60 && tm.tm_sec == 0
                    && tm.tm_isdst == normalized_dst && tm.tm_gmtoff == normalized_off
                    && tm.tm_wday == cases[c].wday && tm.tm_yday == cases[c].yday;
                checked++;
                if (!ok) {
                    failures++;
                    fprintf(stderr, "mktime regression zone=%s hint=%d order=%zu "
                            "got=%lld %02d:%02d dst=%d off=%ld expected=%lld "
                            "%02ld:%02ld dst=%d off=%ld\n",
                            cases[c].zone, hint, order, (long long)actual,
                            tm.tm_hour, tm.tm_min, tm.tm_isdst, tm.tm_gmtoff,
                            (long long)expected, normalized_minutes / 60,
                            normalized_minutes % 60, normalized_dst, normalized_off);
                }
            }
        }
    }
    static const struct {
        const char *zone;
        time_t instant;
        long offset;
        int dst, year, month, day, hour, wday, yday;
    } new_year[] = {
        {"STD14DST15,J1/-24,J100/-24", 1672531200LL, -54000,
         1, 2022, 12, 31, 9, 6, 364},
        {"STD-14DST-15,J1/0,J365/0", 1672488000LL, 50400,
         0, 2023, 1, 1, 2, 0, 0},
        {"STD5DST4,J1/0,J365/24", 1672538400LL, -18000,
         0, 2022, 12, 31, 21, 6, 364},
    };
    for (size_t c = 0; c < sizeof new_year / sizeof *new_year; c++) {
        if (setenv("TZ", new_year[c].zone, 1) != 0) {
            perror("timezone regression setenv");
            return 1;
        }
        tzset();
        struct tm tm = {0};
        const int ok = localtime_r(&new_year[c].instant, &tm) != NULL
            && tm.tm_gmtoff == new_year[c].offset && tm.tm_isdst == new_year[c].dst
            && tm.tm_year == new_year[c].year - 1900
            && tm.tm_mon == new_year[c].month - 1 && tm.tm_mday == new_year[c].day
            && tm.tm_hour == new_year[c].hour && tm.tm_min == 0 && tm.tm_sec == 0
            && tm.tm_wday == new_year[c].wday && tm.tm_yday == new_year[c].yday;
        checked++;
        if (!ok) {
            failures++;
            fprintf(stderr, "localtime regression zone=%s dst=%d off=%ld\n",
                    new_year[c].zone, tm.tm_isdst, tm.tm_gmtoff);
        }
    }
    printf("timezone-regressions checked=%u failures=%u\n", checked, failures);
    return failures != 0;
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
    return timezone_regressions();
}
