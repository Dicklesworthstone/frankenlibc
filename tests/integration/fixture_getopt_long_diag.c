// getopt_long / getopt_long_only diagnostics and return codes, compared with
// glibc byte for byte (stderr is folded into stdout).
//
// fl printed none of glibc's long-option messages (unrecognized, ambiguous with
// its possibilities, doesn't allow / requires an argument): `prog --bogus`
// failed silently. Also covered: a ':' after a leading '+' silences errors and
// makes a missing argument return ':' (fl only looked at byte 0), and
// getopt_long_only reading `-s` as the short option when 's' is one. Runs
// in-process, so it also checks that glibc's optopt lives in private getopt
// state: it is copied out on every call, so a program's reset to 0 does not
// stick and an old error's value keeps being reported.
#define _GNU_SOURCE
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const struct option longs[] = {
    {"help", no_argument, 0, 'h'},   {"size", required_argument, 0, 's'},
    {"sort", optional_argument, 0, 'o'}, {"verbose", no_argument, 0, 'v'},
    {"verify", no_argument, 0, 'v'}, {"color", required_argument, 0, 'c'},
    {"colour", required_argument, 0, 'c'}, {0, 0, 0, 0}};

static void run(const char *label, int long_only, int opterr_val, const char *optstring, char **args) {
    // In-process (the smoke battery's perf gate times the whole fixture, and a
    // fork per scenario made it measure fork). optind = 0 is GNU getopt's full
    // reinitialisation, including the permutation state.
    int argc = 0;
    while (args[argc]) argc++;
    optind = 0;
    optopt = 0;
    optarg = NULL;
    opterr = opterr_val;
    printf("[%s]\n", label);
    fflush(stdout);
    int c;
    while ((c = long_only ? getopt_long_only(argc, args, optstring, longs, NULL)
                          : getopt_long(argc, args, optstring, longs, NULL)) != -1) {
        printf("  c=%d optind=%d optopt=%d optarg=%s\n", c, optind, optopt, optarg ? optarg : "-");
        fflush(stdout);
    }
    printf("  end optind=%d optopt=%d\n", optind, optopt);
    fflush(stdout);
}

int main(void) {
    // Diagnostics go to stderr; interleave them with the results.
    dup2(1, 2);
    printf("initial optopt=%d\n", optopt);
    run("unknown", 0, 1, "hs:", (char *[]){"prog", "--bogus", "--bogus=1", NULL});
    run("ambiguous", 0, 1, "hs:", (char *[]){"prog", "--s", "--s=3", NULL});
    run("equivalent dup prefixes", 0, 1, "hs:", (char *[]){"prog", "--ver", "--col=red", NULL});
    run("ambiguous mixed", 0, 1, "hs:", (char *[]){"prog", "--co", "x", "--v", NULL});
    run("no-arg given arg", 0, 1, "hs:", (char *[]){"prog", "--help=yes", "--verbose=1", NULL});
    run("missing required", 0, 1, "hs:", (char *[]){"prog", "--size", NULL});
    run("opterr=0", 0, 0, "hs:", (char *[]){"prog", "--bogus", "--size", NULL});
    run("colon optstring", 0, 1, ":hs:", (char *[]){"prog", "--bogus", "--size", NULL});
    run("plus colon optstring", 0, 1, "+:hs:", (char *[]){"prog", "--bogus", "--size", NULL});
    run("long_only unknown", 1, 1, "hs:", (char *[]){"prog", "-zork", "-hx", "-size", NULL});
    run("long_only prefix", 1, 1, "hs:", (char *[]){"prog", "-he", "-si", "4", "-verb", NULL});
    run("long_only ambiguous", 1, 1, "hs:", (char *[]){"prog", "-so", "-s", "3", NULL});
    run("argv0 path", 0, 1, "hs:", (char *[]){"/usr/local/bin/tool", "--nope", NULL});
    run("plus colon short", 0, 1, "+:hs:", (char *[]){"prog", "-x", "-s", NULL});
    run("minus colon short", 0, 1, "-:hs:", (char *[]){"prog", "-x", "a", "-s", NULL});
    run("in-order operand and -- keep optopt", 0, 1, "-hs:", (char *[]){"prog", "-x", "a", "--", "b", NULL});
    run("permuted -- keeps optopt", 0, 1, "hs:", (char *[]){"prog", "-x", "--", "b", NULL});
    return 0;
}
