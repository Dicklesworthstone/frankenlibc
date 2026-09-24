/* fixture_argp.c — GNU argp parsing protocol (bd-rc0923-epic-eeuy4f.7).
 *
 * Runs a table of argp_parse scenarios (option kinds, argument permutation,
 * flags, children, the ARGP_KEY_* callback protocol, error paths) and logs
 * every parser callback with the observable state, the final argv order,
 * the arg index and the return value. stderr is folded into stdout so argp's
 * diagnostics are ordered with the log. The preload smoke corpus requires
 * byte parity with host glibc.
 */
#include <argp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *keyname(int key, char *buf) {
    switch (key) {
    case ARGP_KEY_ARG: return "ARG";
    case ARGP_KEY_ARGS: return "ARGS";
    case ARGP_KEY_END: return "END";
    case ARGP_KEY_NO_ARGS: return "NO_ARGS";
    case ARGP_KEY_INIT: return "INIT";
    case ARGP_KEY_FINI: return "FINI";
    case ARGP_KEY_SUCCESS: return "SUCCESS";
    case ARGP_KEY_ERROR: return "ERROR";
    }
    if (key > 32 && key < 127) sprintf(buf, "'%c'", key);
    else sprintf(buf, "%d", key);
    return buf;
}

/* Per-scenario behaviour switches read by the parsers. */
static struct {
    int root_takes_args;   /* ARG: consume (0 = return ARGP_ERR_UNKNOWN) */
    int root_takes_rest;   /* ARGS: set next = argc */
    int root_fail_on;      /* option key that returns EIO */
    int root_argp_error;   /* option key that calls argp_error */
    int root_eat_next;     /* ARG "take": also consume argv[next] */
    int root_unknown_on;   /* option key the root parser disowns */
} cfg;

/* Set per scenario: argp adds -V/--version only when one of these is set. */
const char *argp_program_version;
const char *argp_program_bug_address;

static int root_input_tag = 111, child_input_tag = 222;

static void log_call(const char *who, int key, char *arg, struct argp_state *st) {
    char kb[16];
    printf("  %s %s arg=%s next=%d arg_num=%u quoted=%d input=%s\n", who, keyname(key, kb),
           arg ? arg : "(null)", st->next, st->arg_num, st->quoted,
           st->input == &root_input_tag ? "root" : st->input == &child_input_tag ? "child"
           : st->input ? "other" : "null");
}

static error_t root_parser(int key, char *arg, struct argp_state *st) {
    log_call("root", key, arg, st);
    if (key == ARGP_KEY_INIT) {
        if (st->child_inputs) st->child_inputs[0] = &child_input_tag;
        return 0;
    }
    if (cfg.root_fail_on && key == cfg.root_fail_on) return EIO;
    if (cfg.root_unknown_on && key == cfg.root_unknown_on) return ARGP_ERR_UNKNOWN;
    if (cfg.root_argp_error && key == cfg.root_argp_error) {
        argp_error(st, "bad option value '%s'", arg ? arg : "");
        return EINVAL;
    }
    switch (key) {
    case 'v': case 'o': case 'p': case 'q': case 300: return 0;
    case ARGP_KEY_ARG:
        if (!cfg.root_takes_args) return ARGP_ERR_UNKNOWN;
        if (cfg.root_eat_next && strcmp(arg, "take") == 0 && st->next < st->argc) {
            printf("  root eats %s\n", st->argv[st->next]);
            st->next++;
        }
        return 0;
    case ARGP_KEY_ARGS:
        if (!cfg.root_takes_rest) return ARGP_ERR_UNKNOWN;
        printf("  root takes rest from %s\n", st->argv[st->next]);
        st->next = st->argc;
        return 0;
    case ARGP_KEY_END: case ARGP_KEY_NO_ARGS: case ARGP_KEY_SUCCESS:
    case ARGP_KEY_ERROR: case ARGP_KEY_FINI:
        return 0;
    }
    return ARGP_ERR_UNKNOWN;
}

static error_t child_parser(int key, char *arg, struct argp_state *st) {
    log_call("child", key, arg, st);
    switch (key) {
    case 'c': case 301: return 0;
    }
    return ARGP_ERR_UNKNOWN;
}

static struct argp_option child_opts[] = {
    {"child", 'c', 0, 0, "Child flag", 0},
    {"child-level", 301, "LEVEL", 0, "Child long-only option", 0},
    {0},
};
static struct argp child_argp = {child_opts, child_parser, 0, "child doc", 0, 0, 0};
static struct argp_child children[] = {{&child_argp, 0, "Child options:", 0}, {0}};

static struct argp_option root_opts[] = {
    {"verbose", 'v', 0, 0, "Be verbose", 0},
    {"out", 'o', "FILE", 0, "Output file", 0},
    {"output", 0, 0, OPTION_ALIAS, 0, 0},
    {"opt", 'p', "X", OPTION_ARG_OPTIONAL, "Optional arg", 0},
    {"quiet", 'q', 0, OPTION_HIDDEN, "Hidden", 0},
    {"level", 300, "N", 0, "Long-only option", 0},
    {0},
};
static struct argp root_argp = {root_opts, root_parser, "ARG...", "Root doc", children, 0, 0};

/* A root with no parser and no options: only the child parses. */
static struct argp bare_argp = {0, 0, 0, 0, children, 0, 0};

struct scenario {
    const char *name;
    unsigned flags;
    int takes_args, takes_rest, fail_on, argp_err, eat_next;
    int bare;
    const char *argv[16];
    int null_idx, unknown_on;
    const char *version;
};

#define NOEXIT (ARGP_NO_EXIT)
static const struct scenario scenarios[] = {
    {"getent-shape", NOEXIT, 0, 0, 0, 0, 0, 0, {"getent", "hosts", "localhost"}},
    {"getent-shape-with-option", NOEXIT, 0, 0, 0, 0, 0, 0, {"getent", "-v", "passwd", "root"}},
    {"permute", NOEXIT, 1, 0, 0, 0, 0, 0,
     {"prog", "-v", "a", "-o", "F", "b", "--out=G", "c", "-oH", "d"}},
    {"in-order", NOEXIT | ARGP_IN_ORDER, 1, 0, 0, 0, 0, 0,
     {"prog", "-v", "a", "-o", "F", "b", "--out=G", "c"}},
    {"no-args-flag", NOEXIT | ARGP_NO_ARGS, 1, 0, 0, 0, 0, 0, {"prog", "-v", "a", "-o", "F", "b"}},
    {"double-dash", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-v", "x", "--", "-o", "y", "--"}},
    {"optional-arg", NOEXIT, 1, 0, 0, 0, 0, 0,
     {"prog", "-p", "-pX", "--opt", "--opt=Y", "-p", "Z", "--opt", "W"}},
    {"clustered-shorts", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-vqoFILE", "-vc", "-qo", "G"}},
    {"long-abbrev-alias", NOEXIT, 1, 0, 0, 0, 0, 0,
     {"prog", "--verb", "--output", "A", "--outp=B", "--lev", "3", "--child-l=2", "--ch"}},
    {"ambiguous-long", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--o", "x"}},
    {"unknown-short", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-v", "-z", "a"}},
    {"unknown-long", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--nope", "a"}},
    {"missing-arg-short", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "a", "-o"}},
    {"missing-arg-long", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--out"}},
    {"arg-to-flag", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--verbose=1"}},
    {"no-errs", NOEXIT | ARGP_NO_ERRS, 1, 0, 0, 0, 0, 0, {"prog", "-z", "--nope", "a"}},
    {"child-options", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-c", "--child-level", "5", "a"}},
    {"key-args-rest", NOEXIT, 0, 1, 0, 0, 0, 0, {"prog", "a", "-v", "b", "c"}},
    {"too-many-args", NOEXIT, 0, 0, 0, 0, 0, 0, {"prog", "a", "b"}},
    {"no-args-at-all", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-v"}},
    {"parser-error", NOEXIT, 1, 0, 'o', 0, 0, 0, {"prog", "a", "-o", "F", "b"}},
    {"parser-argp-error", NOEXIT, 1, 0, 0, 'o', 0, 0, {"prog", "-o", "F", "b"}},
    {"eat-next", NOEXIT, 1, 0, 0, 0, 1, 0, {"prog", "take", "-v", "x", "y"}},
    {"parse-argv0", NOEXIT | ARGP_PARSE_ARGV0, 1, 0, 0, 0, 0, 0, {"prog", "a"}},
    {"long-only", NOEXIT | ARGP_LONG_ONLY, 1, 0, 0, 0, 0, 0,
     {"prog", "-verbose", "-out", "F", "-v", "-level=4", "a"}},
    {"bare-root", NOEXIT, 1, 0, 0, 0, 0, 1, {"prog", "-c", "a"}},
    {"empty-argv", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog"}},
    {"lone-dash", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-", "-v"}},
    {"argv0-path", NOEXIT, 1, 0, 0, 0, 0, 0, {"/x/y/prog", "-z"}},
    {"argv0-path-parse-argv0", NOEXIT | ARGP_PARSE_ARGV0, 1, 0, 0, 0, 0, 0, {"/x/y/prog", "-z"}},
    {"null-index-too-many", NOEXIT, 0, 0, 0, 0, 0, 0, {"prog", "a", "b"}, .null_idx = 1},
    {"null-index-all-consumed", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "a"}, .null_idx = 1},
    {"no-help-error", NOEXIT | ARGP_NO_HELP, 1, 0, 0, 0, 0, 0, {"prog", "-z"}},
    {"no-help-no-options", NOEXIT | ARGP_NO_HELP, 1, 0, 0, 0, 0, 0, {"prog", "--help", "--usage"}},
    {"end-error", NOEXIT, 1, 0, ARGP_KEY_END, 0, 0, 0, {"prog", "a"}},
    {"success-error", NOEXIT, 1, 0, ARGP_KEY_SUCCESS, 0, 0, 0, {"prog", "a"}},
    {"no-args-error", NOEXIT, 1, 0, ARGP_KEY_NO_ARGS, 0, 0, 0, {"prog"}},
    {"option-disowned", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-q", "a"}, .unknown_on = 'q'},
    {"option-disowned-long", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--level=2"}, .unknown_on = 300},
    {"version", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "-V", "a", "--vers"}, .version = "fixture 1.0"},
    {"version-no-help", NOEXIT | ARGP_NO_HELP, 1, 0, 0, 0, 0, 0, {"prog", "--version"},
     .version = "fixture 2.0"},
    {"program-name", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--program-name=other", "-z"}},
    {"in-order-double-dash", NOEXIT | ARGP_IN_ORDER, 1, 0, 0, 0, 0, 0, {"prog", "a", "--", "-v", "b"}},
    {"no-args-flag-all-options", NOEXIT | ARGP_NO_ARGS, 1, 0, 0, 0, 0, 0, {"prog", "-v"}},
    {"hang-zero", NOEXIT, 1, 0, 0, 0, 0, 0, {"prog", "--HANG=0", "a"}},
};

/* ---- help/usage formatting battery ------------------------------------ */

static error_t quiet_parser(int key, char *arg, struct argp_state *st) {
    (void)key; (void)arg; (void)st;
    return ARGP_ERR_UNKNOWN;
}

static struct argp_option tool_opts[] = {
    {0, 0, 0, 0, "Input/Output format specification:", 1},
    {"from-code", 'f', "NAME", 0, "encoding of original text", 0},
    {"to-code", 't', "NAME", 0, "encoding for output", 0},
    {0, 0, 0, 0, "Information:", 2},
    {"list", 'l', 0, 0, "list all known coded character sets", 0},
    {0, 0, 0, 0, "Output control:", 3},
    {0, 'c', 0, 0, "omit invalid characters from output", 0},
    {"output", 'o', "FILE", 0, "output file", 0},
    {"silent", 's', 0, 0, "suppress warnings", 0},
    {"verbose", 1000, 0, 0, "print progress information", 0},
    {"a-really-long-option-name-that-overflows", 'R', "VALUE", 0,
     "a documentation string that is long enough that it must be wrapped across "
     "several lines of output by the help formatter, and then some more words", 0},
    {"maybe", 'm', "LEVEL", OPTION_ARG_OPTIONAL, "optional argument option", 0},
    {"hidden-thing", 'H', 0, OPTION_HIDDEN, "not shown", 0},
    {"alias-one", 'a', 0, 0, "option with aliases", 0},
    {"alias-two", 'b', 0, OPTION_ALIAS, 0, 0},
    {"alias-three", 0, 0, OPTION_ALIAS, 0, 0},
    {"FORMAT", 0, 0, OPTION_DOC, "a documentation entry, not an option", 0},
    {0, 0, 0, 0, "Negative group:", -2},
    {"late", 1001, "N", 0, "an option in a negative group", 0},
    {0},
};

static struct argp_option sub_opts[] = {
    {"sub-flag", 'S', 0, 0, "a flag from the child argp", 0},
    {"sub-value", 1002, "X", 0, "a value from the child argp", 0},
    {0},
};
static struct argp sub_argp = {sub_opts, quiet_parser, "SUBARG", "child pre doc\vchild post doc", 0, 0, 0};
static struct argp_child tool_children[] = {{&sub_argp, 0, "Child options:", 5}, {0}};

static char *tool_filter(int key, const char *text, void *input) {
    (void)input;
    if (key == ARGP_KEY_HELP_EXTRA) return strdup("Extra text from the filter.");
    if (key == ARGP_KEY_HELP_POST_DOC && text) {
        char *s = malloc(strlen(text) + 32);
        sprintf(s, "%s [filtered]", text);
        return s;
    }
    return (char *)text;
}

static struct argp tool_argp = {
    tool_opts, quiet_parser, "[FILE...]\n-l",
    "Convert encoding of given files from one encoding to another.\vFor bug reporting "
    "instructions, please see a place that has a fairly long description so it wraps.",
    tool_children, tool_filter, 0};

static struct argp_option plain_opts[] = {
    {"alpha", 'A', 0, 0, "first", 0},
    {"beta", 'B', "ARG", 0, "second", 0},
    {0},
};
static struct argp plain_argp = {plain_opts, quiet_parser, "database [key ...]", "Get entries.", 0, 0, 0};

/* Sort ties: same first letter, long-only vs short, case. */
static struct argp_option tie_opts[] = {
    {"cz", 'c', 0, 0, "short c", 0}, {"ca", 300, 0, 0, "long ca", 0}, {"cb", 301, 0, 0, "long cb", 0},
    {"Cc", 302, 0, 0, "long Cc", 0}, {"dog", 'D', 0, 0, "short D", 0}, {"dab", 303, 0, 0, "long dab", 0},
    {"Dz", 'd', 0, 0, "short d", 0}, {"--weird", 0, 0, OPTION_DOC, "doc entry with dashes", 0},
    {"zeta", 0, 0, OPTION_DOC, "doc entry sorted after options", 0}, {0}};
static struct argp tie_argp = {tie_opts, quiet_parser, 0, 0, 0, 0, 0};

static void help_battery(void) {
    static const struct { const char *label; struct argp *argp; unsigned flags; } cases[] = {
        {"tool std-help", &tool_argp, ARGP_HELP_STD_HELP & ~ARGP_HELP_EXIT_OK},
        {"tool usage", &tool_argp, ARGP_HELP_USAGE},
        {"tool short-usage+see", &tool_argp, ARGP_HELP_SHORT_USAGE | ARGP_HELP_SEE},
        {"tool long-only", &tool_argp, ARGP_HELP_LONG},
        {"tool docs-only", &tool_argp, ARGP_HELP_PRE_DOC | ARGP_HELP_POST_DOC},
        {"tool long-only-fmt", &tool_argp, ARGP_HELP_LONG | ARGP_HELP_LONG_ONLY},
        {"tool bug", &tool_argp, ARGP_HELP_BUG_ADDR},
        {"plain std-help", &plain_argp, ARGP_HELP_STD_HELP & ~ARGP_HELP_EXIT_OK},
        {"plain usage", &plain_argp, ARGP_HELP_USAGE},
        {"root std-help", &root_argp, ARGP_HELP_STD_HELP & ~ARGP_HELP_EXIT_OK},
        {"root usage", &root_argp, ARGP_HELP_USAGE},
        {"bare usage", &bare_argp, ARGP_HELP_USAGE | ARGP_HELP_LONG},
        {"tie long", &tie_argp, ARGP_HELP_LONG | ARGP_HELP_USAGE},
    };
    static const char *fmts[] = {NULL, "rmargin=50,opt-doc-col=20", "no-dup-args,long-opt-col=10",
                                 "short-opt-col=4,header-col=3,usage-indent=4", "dup-args"};
    argp_program_bug_address = "<bugs@example.test>";
    for (size_t f = 0; f < sizeof fmts / sizeof *fmts; f++) {
        if (fmts[f]) setenv("ARGP_HELP_FMT", fmts[f], 1); else unsetenv("ARGP_HELP_FMT");
        for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
            if (f && i >= 2) break; /* format variants: first two cases only */
            printf("== help %s [ARGP_HELP_FMT=%s]\n", cases[i].label, fmts[f] ? fmts[f] : "");
            argp_help(cases[i].argp, stdout, cases[i].flags, "prog");
            printf("== end\n");
        }
    }
    unsetenv("ARGP_HELP_FMT");
    argp_program_bug_address = 0;
    /* Through argp_parse: the default --help/--usage/--version children. */
    argp_program_version = "fixture 3.0";
    const char *runs[][4] = {{"prog", "--help"}, {"prog", "--usage"}, {"prog", "-?"}};
    for (size_t r = 0; r < 3; r++) {
        char *argv[3] = {strdup(runs[r][0]), strdup(runs[r][1]), 0};
        printf("== parse %s\n", runs[r][1]);
        int idx = -1;
        argp_parse(&tool_argp, 2, argv, ARGP_NO_EXIT, &idx, 0);
        printf("== end idx=%d\n", idx);
        free(argv[0]);
        free(argv[1]);
    }
    argp_program_version = 0;
}

int main(int argc, char **main_argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    dup2(1, 2);
    if (argc > 1 && strcmp(main_argv[1], "help") == 0) {
        help_battery();
        return 0;
    }
    for (size_t s = 0; s < sizeof scenarios / sizeof *scenarios; s++) {
        const struct scenario *sc = &scenarios[s];
        char *argv[17] = {0};
        int argc = 0;
        while (sc->argv[argc]) {
            argv[argc] = strdup(sc->argv[argc]);
            argc++;
        }
        cfg.root_takes_args = sc->takes_args;
        cfg.root_takes_rest = sc->takes_rest;
        cfg.root_fail_on = sc->fail_on;
        cfg.root_argp_error = sc->argp_err;
        cfg.root_eat_next = sc->eat_next;
        cfg.root_unknown_on = sc->unknown_on;
        argp_program_version = sc->version;
        printf("== %s flags=%#x argc=%d\n", sc->name, sc->flags, argc);
        int idx = -1;
        error_t err = argp_parse(sc->bare ? &bare_argp : &root_argp, argc, argv, sc->flags,
                                 sc->null_idx ? NULL : &idx, &root_input_tag);
        printf("  -> err=%d idx=%d argv:", err, idx);
        for (int i = 0; i < argc; i++) printf(" %s", argv[i]);
        printf("\n");
        for (int i = 0; i < argc; i++) free(argv[i]);
    }
    return 0;
}
