/* No host runtime dependencies: this fixture must be owned by the native
   loader, not made green by its host-coupled pathname fallback. */
int inspect_values[8] = { 11, 22, 33, 44, 55, 66, 77, 88 };
__attribute__((visibility("protected"))) int inspect_protected = 73;
__attribute__((visibility("hidden"))) int inspect_hidden = 91;
__attribute__((noinline)) int inspect_answer(void) { return inspect_values[2] + 9; }
void *inspect_hidden_address(void) { return &inspect_hidden; }
int inspect_visit(int (*callback)(void *), void *data) { return callback(data); }
