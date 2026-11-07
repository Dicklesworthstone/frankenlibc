/* Self-contained code: rejected images cannot pass through host fallback. */
#ifdef TEST_IFUNC
static volatile int resolved;
static int implementation(void) { return 73; }
static int (*resolve_selected(void))(void) {
    ++resolved;
    return implementation;
}
int selected(void) __attribute__((ifunc("resolve_selected")));
int relro_execution_probe(void) {
    return resolved == 1 && selected() == 73;
}
#else
static volatile int constructed;
__attribute__((constructor)) static void initialize(void) {
    constructed = 29;
}
int relro_execution_probe(void) { return constructed == 29; }
#endif
