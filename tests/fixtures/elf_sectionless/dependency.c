static int value = 5;
__attribute__((constructor)) static void initialize(void) { value = 11; }
int dep_value(void) { return value; }
