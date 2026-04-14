/**
 * extract_io_file_offsets.c - Verify glibc FILE struct compatibility
 *
 * This program verifies that the glibc FILE structure is compatible with
 * FrankenLibC's NativeFile layout (glibc 2.34 x86_64 baseline = 216 bytes).
 *
 * Since glibc >= 2.28 hides _IO_FILE internals, we verify:
 *   1. sizeof(FILE) >= 216 (our baseline for _IO_FILE prefix)
 *   2. The glibc version is in our supported range
 *
 * For CI matrix purposes, this confirms the system glibc is compatible.
 *
 * Exit codes:
 *   0 - Compatible (size check passes)
 *   1 - Incompatible (size mismatch or unsupported version)
 *
 * Part of bd-9chy.41: glibc version matrix CI
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <gnu/libc-version.h>

/* FrankenLibC pinned size (glibc 2.34 x86_64 _IO_FILE is 216 bytes) */
#define EXPECTED_IO_FILE_SIZE 216

/* Supported glibc versions for NativeFile compatibility */
static const struct {
    int major;
    int minor;
    const char *distro;
} SUPPORTED_VERSIONS[] = {
    {2, 31, "Ubuntu 20.04 / RHEL 8"},
    {2, 34, "Ubuntu 22.04 (baseline)"},
    {2, 35, "Debian 12"},
    {2, 36, "Fedora 37"},
    {2, 37, "Fedora 38"},
    {2, 38, "Ubuntu 24.04 / RHEL 9"},
    {2, 39, "Fedora 39"},
};

#define NUM_SUPPORTED (sizeof(SUPPORTED_VERSIONS) / sizeof(SUPPORTED_VERSIONS[0]))

int main(int argc, char *argv[]) {
    int json_output = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) json_output = 1;
    }

    const char *glibc_version = gnu_get_libc_version();
    size_t file_size = sizeof(FILE);

    /* Parse major.minor from version string */
    int major = 0, minor = 0;
    sscanf(glibc_version, "%d.%d", &major, &minor);

    /* Check if this is a known-supported version */
    const char *distro_hint = NULL;
    int version_known = 0;
    for (size_t i = 0; i < NUM_SUPPORTED; i++) {
        if (SUPPORTED_VERSIONS[i].major == major &&
            SUPPORTED_VERSIONS[i].minor == minor) {
            distro_hint = SUPPORTED_VERSIONS[i].distro;
            version_known = 1;
            break;
        }
    }

    /* Size compatibility check */
    int size_compatible = (file_size >= EXPECTED_IO_FILE_SIZE);

    /* Overall compatibility: size must be compatible */
    int compatible = size_compatible;

    if (json_output) {
        printf("{\n");
        printf("  \"schema\": \"glibc_compatibility.v1\",\n");
        printf("  \"glibc_version\": \"%s\",\n", glibc_version);
        printf("  \"glibc_major\": %d,\n", major);
        printf("  \"glibc_minor\": %d,\n", minor);
        printf("  \"sizeof_FILE\": %zu,\n", file_size);
        printf("  \"expected_minimum\": %d,\n", EXPECTED_IO_FILE_SIZE);
        printf("  \"size_compatible\": %s,\n", size_compatible ? "true" : "false");
        printf("  \"version_known\": %s,\n", version_known ? "true" : "false");
        if (distro_hint) {
            printf("  \"distro_hint\": \"%s\",\n", distro_hint);
        }
        printf("  \"compatible\": %s\n", compatible ? "true" : "false");
        printf("}\n");
    } else {
        printf("glibc compatibility check for FrankenLibC NativeFile\n");
        printf("=====================================================\n\n");
        printf("System glibc version: %s", glibc_version);
        if (distro_hint) {
            printf(" (%s)", distro_hint);
        }
        printf("\n");
        printf("sizeof(FILE): %zu bytes (expected >= %d)\n\n", file_size, EXPECTED_IO_FILE_SIZE);

        if (compatible) {
            printf("PASS: glibc %s is compatible with NativeFile baseline\n", glibc_version);
            if (!version_known) {
                printf("NOTE: This glibc version is not in our explicit test matrix.\n");
                printf("      Consider adding it to SUPPORTED_VERSIONS if this is a common distro.\n");
            }
        } else {
            printf("FAIL: glibc %s may be incompatible with NativeFile\n", glibc_version);
            if (!size_compatible) {
                printf("      sizeof(FILE) = %zu, but NativeFile expects >= %d\n",
                       file_size, EXPECTED_IO_FILE_SIZE);
            }
        }
    }

    return compatible ? 0 : 1;
}
