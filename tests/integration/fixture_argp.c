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
} cfg;

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
};

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    dup2(1, 2);
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
        printf("== %s flags=%#x argc=%d\n", sc->name, sc->flags, argc);
        int idx = -1;
        error_t err = argp_parse(sc->bare ? &bare_argp : &root_argp, argc, argv, sc->flags, &idx,
                                 &root_input_tag);
        printf("  -> err=%d idx=%d argv:", err, idx);
        for (int i = 0; i < argc; i++) printf(" %s", argv[i]);
        printf("\n");
        for (int i = 0; i < argc; i++) free(argv[i]);
    }
    return 0;
}
