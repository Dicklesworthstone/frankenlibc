extern int dep_value(void);
static int value = 7;
static int *volatile relocated = &value;
static __thread int local = 3;
static int initialized;
static int *finished;
__attribute__((constructor)) static void initialize(void) {
    initialized = dep_value() + 1;
}
__attribute__((destructor)) static void finalize(void) {
    if (finished) *finished = dep_value() + 1;
}
int answer(void) { return *relocated + local + initialized + dep_value(); }
int tls_step(void) { return ++local; }
void set_finalizer_counter(int *counter) { finished = counter; }
