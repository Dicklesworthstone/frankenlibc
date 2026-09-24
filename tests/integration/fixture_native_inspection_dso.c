/* Self-contained native-loader fixture: build -shared -fPIC -nostdlib.
   Deliberately carries PT_GNU_EH_FRAME and dynamic TLS, but no host DT_NEEDED. */
int inspection_data[4] = {11, 22, 33, 44};
__thread int inspection_tls = 31;
static void (*notify_finalized)(void *);
static void *finalizer_argument;

void inspection_install_finalizer(void (*notify)(void *), void *argument) {
    notify_finalized = notify;
    finalizer_argument = argument;
}

__attribute__((destructor)) static void inspection_fini(void) {
    if (notify_finalized) notify_finalized(finalizer_argument);
}

__attribute__((noinline)) int inspection_function(int value) {
    return value + inspection_data[1];
}

/* An exception thrown by the caller's callback must cross this native frame.
   Build with -fexceptions; the fixture itself does not depend on libstdc++. */
__attribute__((noinline)) int inspection_invoke(int (*callback)(int), int value) {
    int result = callback(value);
    return result + 1;
}

int *inspection_tls_address(void) { return &inspection_tls; }

__asm__(".pushsection .text\n"
        ".globl inspection_zero\n"
        ".type inspection_zero,@function\n"
        "inspection_zero:\n"
        ".byte 0x90,0x90,0x90,0xc3\n"
        ".size inspection_zero,0\n"
        ".popsection\n");
