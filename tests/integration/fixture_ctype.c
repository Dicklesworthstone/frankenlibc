/* fixture_ctype.c — ctype conformance smoke fixture (bd-15n.2)
 * Exit 0 = PASS, nonzero = FAIL with diagnostics.
 */
#include <ctype.h>
#include <stdio.h>

static int test_classification(void) {
    if (!isalpha('A')) {
        fprintf(stderr, "FAIL: isalpha('A')\n");
        return 1;
    }
    if (!isdigit('9')) {
        fprintf(stderr, "FAIL: isdigit('9')\n");
        return 1;
    }
    if (!islower('q')) {
        fprintf(stderr, "FAIL: islower('q')\n");
        return 1;
    }
    if (!isupper('Q')) {
        fprintf(stderr, "FAIL: isupper('Q')\n");
        return 1;
    }
    if (!isspace(' ')) {
        fprintf(stderr, "FAIL: isspace(' ')\n");
        return 1;
    }
    if (!isxdigit('f')) {
        fprintf(stderr, "FAIL: isxdigit('f')\n");
        return 1;
    }
    return 0;
}

static int test_case_map(void) {
    if (tolower('Q') != 'q') {
        fprintf(stderr, "FAIL: tolower('Q')\n");
        return 1;
    }
    if (toupper('q') != 'Q') {
        fprintf(stderr, "FAIL: toupper('q')\n");
        return 1;
    }
    return 0;
}

int main(void) {
    int fails = 0;
    fails += test_classification();
    fails += test_case_map();

    if (fails) {
        fprintf(stderr, "fixture_ctype: %d FAILED\n", fails);
        return 1;
    }
    printf("fixture_ctype: PASS (2 tests)\n");
    return 0;
}
