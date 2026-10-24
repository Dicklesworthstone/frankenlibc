/* fixture_nss_modules.c -- passwd/group/shadow/initgroups through a dlopen'ed
 * NSS service module (libnss_fltest.so.2 / libnss_fltestnoig.so.2, built from
 * fixture_nss_module_lib.c), as configured in nsswitch.conf.
 *
 * Prints one line per observation so the output can be compared byte for byte
 * with glibc under the same nsswitch.conf and LD_LIBRARY_PATH. With an
 * argument, runs only that section: pw, gr, sp, ent, ig, r.
 */
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *s(const char *p) { return p ? p : "(null)"; }

static void show_pw(const char *what, struct passwd *pw) {
  if (pw == NULL) {
    printf("%s: NULL\n", what);
    return;
  }
  printf("%s: %s:%s:%u:%u:%s:%s:%s\n", what, s(pw->pw_name), s(pw->pw_passwd),
         (unsigned)pw->pw_uid, (unsigned)pw->pw_gid, s(pw->pw_gecos), s(pw->pw_dir),
         s(pw->pw_shell));
}

static void show_gr(const char *what, struct group *gr) {
  if (gr == NULL) {
    printf("%s: NULL\n", what);
    return;
  }
  printf("%s: %s:%s:%u:", what, s(gr->gr_name), s(gr->gr_passwd), (unsigned)gr->gr_gid);
  for (char **m = gr->gr_mem; m && *m; m++) printf("%s%s", m == gr->gr_mem ? "" : ",", *m);
  printf("\n");
}

static void section_pw(void) {
  show_pw("getpwnam fltest1", getpwnam("fltest1"));
  show_pw("getpwnam root", getpwnam("root"));
  show_pw("getpwuid 4202", getpwuid(4202));
  show_pw("getpwuid 0", getpwuid(0));
  show_pw("getpwnam nosuch", getpwnam("fl_nosuch_user"));
}

static void section_gr(void) {
  show_gr("getgrnam fltestgrp", getgrnam("fltestgrp"));
  show_gr("getgrnam fltestgrp2", getgrnam("fltestgrp2"));
  show_gr("getgrgid 4303", getgrgid(4303));
  show_gr("getgrnam root", getgrnam("root"));
  show_gr("getgrgid 0", getgrgid(0));
  show_gr("getgrnam nosuch", getgrnam("fl_nosuch_group"));
}

static void section_sp(void) {
  struct spwd *sp = getspnam("fltest2");
  if (sp == NULL)
    printf("getspnam fltest2: NULL\n");
  else
    printf("getspnam fltest2: %s:%s:%ld:%ld:%ld:%ld:%ld:%ld\n", s(sp->sp_namp), s(sp->sp_pwdp),
           sp->sp_lstchg, sp->sp_min, sp->sp_max, sp->sp_warn, sp->sp_inact, sp->sp_expire);
  printf("getspnam nosuch: %s\n", getspnam("fl_nosuch_user") ? "found" : "NULL");
}

/* Enumeration: print only module-provided names (uid/gid 4200..4399) and the
 * running count of all entries, so the host's own files do not matter beyond
 * their count, which both libcs read from the same files. */
static void section_ent(void) {
  int n = 0;
  struct passwd *pw;
  setpwent();
  while ((pw = getpwent()) != NULL) {
    n++;
    if ((pw->pw_uid >= 4200 && pw->pw_uid < 4400) || strcmp(pw->pw_gecos ? pw->pw_gecos : "", "module root") == 0)
      printf("getpwent[%d]: %s %u\n", n, pw->pw_name, (unsigned)pw->pw_uid);
  }
  endpwent();
  printf("getpwent total>0: %d\n", n > 0);
  int g = 0;
  struct group *gr;
  setgrent();
  while ((gr = getgrent()) != NULL) {
    g++;
    if ((gr->gr_gid >= 4300 && gr->gr_gid < 4400) || strcmp(gr->gr_passwd ? gr->gr_passwd : "", "y") == 0)
      printf("getgrent[%d]: %s %u\n", g, gr->gr_name, (unsigned)gr->gr_gid);
  }
  endgrent();
  printf("getgrent total>0: %d\n", g > 0);
}

static void section_ig(void) {
  gid_t groups[16];
  int ngroups = 16;
  int rc = getgrouplist("fltest1", 4301, groups, &ngroups);
  printf("getgrouplist fltest1: rc=%d n=%d:", rc, ngroups);
  for (int i = 0; rc >= 0 && i < ngroups; i++) printf(" %u", (unsigned)groups[i]);
  printf("\n");
  ngroups = 1;
  rc = getgrouplist("fltest1", 4301, groups, &ngroups);
  printf("getgrouplist fltest1 small: rc=%d n=%d first=%u\n", rc, ngroups, (unsigned)groups[0]);
  ngroups = 16;
  rc = getgrouplist("fltest2", 4302, groups, &ngroups);
  printf("getgrouplist fltest2: rc=%d n=%d:", rc, ngroups);
  for (int i = 0; rc >= 0 && i < ngroups; i++) printf(" %u", (unsigned)groups[i]);
  printf("\n");
  if (geteuid() == 0) {
    if (initgroups("fltest1", 4301) != 0) {
      printf("initgroups: errno=%d\n", errno);
    } else {
      int n = getgroups(16, groups);
      printf("initgroups fltest1 -> getgroups n=%d:", n);
      for (int i = 0; i < n; i++) printf(" %u", (unsigned)groups[i]);
      printf("\n");
    }
  }
}

static void section_r(void) {
  struct passwd pwbuf, *pwres = (struct passwd *)1;
  char small[8], big[1024];
  int rc = getpwnam_r("fltest1", &pwbuf, small, sizeof small, &pwres);
  printf("getpwnam_r small: rc=%d res=%s\n", rc, pwres ? "set" : "NULL");
  rc = getpwnam_r("fltest1", &pwbuf, big, sizeof big, &pwres);
  printf("getpwnam_r big: rc=%d res=%s\n", rc, pwres == &pwbuf ? "pwbuf" : "other");
  if (pwres) show_pw("  value", pwres);
  rc = getpwuid_r(4202, &pwbuf, big, sizeof big, &pwres);
  printf("getpwuid_r 4202: rc=%d %s\n", rc, pwres ? pwres->pw_name : "NULL");
  rc = getpwnam_r("fl_nosuch_user", &pwbuf, big, sizeof big, &pwres);
  printf("getpwnam_r nosuch: rc=%d res=%s\n", rc, pwres ? "set" : "NULL");
  struct group grbuf, *grres = (struct group *)1;
  char gsmall[16];
  rc = getgrnam_r("fltestmany", &grbuf, gsmall, sizeof gsmall, &grres);
  printf("getgrnam_r small: rc=%d res=%s\n", rc, grres ? "set" : "NULL");
  rc = getgrnam_r("fltestmany", &grbuf, big, sizeof big, &grres);
  printf("getgrnam_r big: rc=%d\n", rc);
  if (grres) show_gr("  value", grres);
  rc = getgrgid_r(4302, &grbuf, big, sizeof big, &grres);
  printf("getgrgid_r 4302: rc=%d %s\n", rc, grres ? grres->gr_name : "NULL");
  struct spwd spbuf, *spres = NULL;
  rc = getspnam_r("fltest1", &spbuf, big, sizeof big, &spres);
  printf("getspnam_r fltest1: rc=%d %s\n", rc, spres ? spres->sp_pwdp : "NULL");
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  const char *only = argc > 1 ? argv[1] : NULL;
  if (!only || !strcmp(only, "pw")) section_pw();
  if (!only || !strcmp(only, "gr")) section_gr();
  if (!only || !strcmp(only, "sp")) section_sp();
  if (!only || !strcmp(only, "ent")) section_ent();
  if (!only || !strcmp(only, "r")) section_r();
  if (!only || !strcmp(only, "ig")) section_ig();
  return 0;
}
