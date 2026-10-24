/* Float libm results over 2^20 deterministic pseudo-random inputs (plus every
 * power of two), as one FNV hash per function, compared byte for byte with host
 * glibc by ld_preload_smoke.sh. glibc 2.43's float functions listed here are
 * correctly rounded (CORE-MATH) or, for expf, glibc's own 0.5-ULP kernel; fl
 * evaluates them in f64 and rounds once. An exhaustive sweep (bd-li7fb3) found
 * fl's former f32 evaluations differing from glibc on up to 1.7G of the 2^32
 * inputs (acoshf: inf for finite results above ~1.8e19; lgammaf: 7.5M ULP).
 * NaN results are canonicalised: payloads are the special-values gate's job.
 * sinf/cosf are omitted: glibc's are not correctly rounded and fl's
 * differ by 1 ULP on ~0.7% of inputs. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const char *names[] = {"expf",  "expm1f", "acoshf", "lgammaf", "erfcf", "log10f",
                              "asinhf", "atanf",  "tanf",   "asinf",   "acosf", "erff",
                              "atanhf", "sinhf",  "coshf",  "tgammaf", "exp10f", 0};

int main(void) {
    /* Nothing references libm directly (--as-needed would drop it); load it
       globally. Under LD_PRELOAD the preloaded library still wins RTLD_DEFAULT. */
    dlopen("libm.so.6", RTLD_NOW | RTLD_GLOBAL);
    for (const char **n = names; *n; n++) {
        float (*f)(float) = (float (*)(float))dlsym(RTLD_DEFAULT, *n);
        if (!f) {
            printf("%-8s missing\n", *n);
            continue;
        }
        uint64_t st = 0x9e3779b97f4a7c15ull, h = 1469598103934665603ull;
        for (uint32_t i = 0; i < (1u << 20) + 512; i++) {
            uint32_t u;
            if (i < 512) {
                u = (i & 255) << 23 | (i >= 256 ? 0x80000000u : 0);
            } else {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                u = (uint32_t)(st >> 17);
            }
            float x, r;
            uint32_t b;
            memcpy(&x, &u, 4);
            r = f(x);
            memcpy(&b, &r, 4);
            if ((b & 0x7fffffffu) > 0x7f800000u) {
                b = 0x7fc00000u;
            }
            h = (h ^ b) * 1099511628211ull;
        }
        printf("%-8s %016llx\n", *n, (unsigned long long)h);
    }
    return 0;
}
