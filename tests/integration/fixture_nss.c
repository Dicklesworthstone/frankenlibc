/* fixture_nss.c — NSS/resolver lookup smoke fixture (bd-x2sq)
 * Exit 0 = PASS, nonzero = FAIL with diagnostics.
 */
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

static int test_getpwnam_root(void) {
    struct passwd *pw = getpwnam("root");
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwnam(root) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (pw->pw_name == NULL || strcmp(pw->pw_name, "root") != 0) {
        fprintf(stderr, "FAIL: getpwnam(root) returned unexpected name\n");
        return 1;
    }
    return 0;
}

static int test_getpwuid_zero(void) {
    struct passwd *pw = getpwuid(0);
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwuid(0) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (pw->pw_name == NULL || pw->pw_name[0] == '\0') {
        fprintf(stderr, "FAIL: getpwuid(0) returned empty name\n");
        return 1;
    }
    return 0;
}

static int test_getpwnam_missing(void) {
    errno = 0;
    struct passwd *pw = getpwnam("frankenlibc_missing_user_xyz");
    if (pw != NULL) {
        fprintf(stderr, "FAIL: getpwnam(missing) expected NULL\n");
        return 1;
    }
    return 0;
}

static int test_getgrnam_root(void) {
    struct group *gr = getgrnam("root");
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrnam(root) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (gr->gr_name == NULL || strcmp(gr->gr_name, "root") != 0) {
        fprintf(stderr, "FAIL: getgrnam(root) returned unexpected name\n");
        return 1;
    }
    return 0;
}

static int test_getgrgid_zero(void) {
    struct group *gr = getgrgid(0);
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrgid(0) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (gr->gr_name == NULL || gr->gr_name[0] == '\0') {
        fprintf(stderr, "FAIL: getgrgid(0) returned empty group name\n");
        return 1;
    }
    return 0;
}

static int test_getgrnam_missing(void) {
    errno = 0;
    struct group *gr = getgrnam("frankenlibc_missing_group_xyz");
    if (gr != NULL) {
        fprintf(stderr, "FAIL: getgrnam(missing) expected NULL\n");
        return 1;
    }
    return 0;
}

static int test_passwd_group_enumeration_controls(void) {
    setpwent();
    struct passwd *pw = getpwent();
    endpwent();
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwent() returned NULL after setpwent()\n");
        return 1;
    }

    setgrent();
    struct group *gr = getgrent();
    endgrent();
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrent() returned NULL after setgrent()\n");
        return 1;
    }

    return 0;
}

static int test_getaddrinfo_localhost(void) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int rc = getaddrinfo("localhost", "80", &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) rc=%d (%s)\n", rc, gai_strerror(rc));
        return 1;
    }
    if (res == NULL) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) returned NULL list\n");
        return 1;
    }

    int family = res->ai_family;
    freeaddrinfo(res);

    if (!(family == AF_INET || family == AF_INET6)) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) family=%d\n", family);
        return 1;
    }
    return 0;
}

int main(void) {
    int fails = 0;

    fails += test_getpwnam_root();
    fails += test_getpwuid_zero();
    fails += test_getpwnam_missing();
    fails += test_getgrnam_root();
    fails += test_getgrgid_zero();
    fails += test_getgrnam_missing();
    fails += test_passwd_group_enumeration_controls();
    fails += test_getaddrinfo_localhost();

    if (fails) {
        fprintf(stderr, "fixture_nss: %d FAILED\n", fails);
        return 1;
    }

    printf("fixture_nss: PASS (8 tests)\n");
    return 0;
}
