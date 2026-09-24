extern int api(void), old_api(void);
extern int data, old_data;
extern __thread int tls_value, old_tls;
extern int dispatch(void), old_dispatch(void);
__asm__(".symver old_api,api@VERS_1");
__asm__(".symver old_data,data@VERS_1");
__asm__(".symver old_tls,tls_value@VERS_1");
__asm__(".symver old_dispatch,dispatch@VERS_1");
/* All four relocation families must agree on the selected version. */
int current_values(void) { return api() + data + tls_value + dispatch(); }
int previous_values(void) { return old_api() + old_data + old_tls + old_dispatch(); }
