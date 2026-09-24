/* Not linked against the versioned provider: no DT_VERSYM/DT_VERNEED here.
 * GNU relocation compatibility selects version index 2, unlike dlsym. */
extern int api(void), dispatch(void);
extern int data;
extern __thread int tls_value;
int legacy_values(void) { return api() + data + tls_value + dispatch(); }
