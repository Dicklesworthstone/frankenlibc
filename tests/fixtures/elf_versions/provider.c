/* Deliberately put the obsolete implementation before the public default. */
int api_old(void) { return 11; }
int api_new(void) { return 22; }
__asm__(".symver api_old,api@VERS_1");
__asm__(".symver api_new,api@@VERS_2");
int retired_old(void) { return 33; }
__asm__(".symver retired_old,retired@VERS_1");
int recent_private(void) { return 44; }
__asm__(".symver recent_private,recent@VERS_2");
int data_old = 101, data_new = 202;
__asm__(".symver data_old,data@VERS_1");
__asm__(".symver data_new,data@@VERS_2");
__thread int tls_old = 303, tls_new = 404;
__asm__(".symver tls_old,tls_value@VERS_1");
__asm__(".symver tls_new,tls_value@@VERS_2");
static int implementation_old(void) { return 55; }
static int implementation_new(void) { return 66; }
static int (*resolve_old(void))(void) { return implementation_old; }
static int (*resolve_new(void))(void) { return implementation_new; }
int dispatch_old(void) __attribute__((ifunc("resolve_old")));
int dispatch_new(void) __attribute__((ifunc("resolve_new")));
__asm__(".symver dispatch_old,dispatch@VERS_1");
__asm__(".symver dispatch_new,dispatch@@VERS_2");
int unversioned(void) { return 77; }
