/* Integration test: compile and link against frankenlibc's libc.so */
/* Build: cc -o link_test link_test.c -L../../target/release -lfrankenlibc_abi */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>

int main(void) {
    /* Test memcpy */
    char src[] = "Hello, frankenlibc!";
    char dst[32] = {0};
    memcpy(dst, src, strlen(src) + 1);

    if (strcmp(dst, src) != 0) {
        fprintf(stderr, "FAIL: memcpy/strcmp\n");
        return 1;
    }

    /* Test malloc/free */
    char *p = malloc(64);
    if (p == NULL) {
        fprintf(stderr, "FAIL: malloc returned NULL\n");
        return 1;
    }
    memset(p, 'A', 63);
    p[63] = '\0';
    if (strlen(p) != 63) {
        fprintf(stderr, "FAIL: strlen after malloc\n");
        free(p);
        return 1;
    }
    free(p);

    /* Test calloc */
    int *arr = calloc(10, sizeof(int));
    if (arr == NULL) {
        fprintf(stderr, "FAIL: calloc returned NULL\n");
        return 1;
    }
    for (int i = 0; i < 10; i++) {
        if (arr[i] != 0) {
            fprintf(stderr, "FAIL: calloc not zeroed at index %d\n", i);
            free(arr);
            return 1;
        }
    }
    free(arr);

    /* Test basic NSS passwd/group lookups (files backend). */
    errno = 0;
    struct passwd *pw = getpwnam("root");
    if (pw == NULL) {
        fprintf(stderr, "FAIL: getpwnam(root) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (pw->pw_name == NULL || strcmp(pw->pw_name, "root") != 0) {
        fprintf(stderr, "FAIL: getpwnam(root) returned unexpected name\n");
        return 1;
    }

    errno = 0;
    struct group *gr = getgrnam("root");
    if (gr == NULL) {
        fprintf(stderr, "FAIL: getgrnam(root) returned NULL errno=%d\n", errno);
        return 1;
    }
    if (gr->gr_name == NULL || strcmp(gr->gr_name, "root") != 0) {
        fprintf(stderr, "FAIL: getgrnam(root) returned unexpected name\n");
        return 1;
    }

    /* Test resolver bootstrap: getaddrinfo should succeed for localhost via numeric/hosts subset. */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *ai = NULL;
    int gai_rc = getaddrinfo("localhost", "80", &hints, &ai);
    if (gai_rc != 0 || ai == NULL) {
        fprintf(stderr, "FAIL: getaddrinfo(localhost,80) rc=%d (%s)\n", gai_rc, gai_strerror(gai_rc));
        return 1;
    }
    freeaddrinfo(ai);

    printf("PASS: all integration tests passed\n");
    return 0;
}
