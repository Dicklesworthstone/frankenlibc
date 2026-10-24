/* A destroyed mutex is unusable until re-initialised: lock/trylock/
 * timedlock/unlock and cond_timedwait return EINVAL for every mutex kind,
 * destroying it again succeeds, and pthread_mutex_init makes it usable again
 * -- glibc 2.43 behaviour (it marks __kind -1). fl used to zero the storage,
 * so the next lock adopted it as a fresh default mutex (timedlock succeeded,
 * then a NORMAL relock deadlocked). Output must match glibc
 * (bd-rc0923-epic-eeuy4f.15).
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#define S(x) do { int _r = (x); printf(" %s=%d", #x, _r); fflush(stdout); } while (0)
static void deadline(struct timespec *ts){ clock_gettime(CLOCK_REALTIME,ts); ts->tv_nsec+=2000000; if(ts->tv_nsec>=1000000000){ts->tv_sec++;ts->tv_nsec-=1000000000;} }
static void run(const char *name, pthread_mutexattr_t *a){
  pthread_mutex_t m; struct timespec ts; deadline(&ts);
  printf("%s:", name);
  S(pthread_mutex_init(&m,a)); S(pthread_mutex_destroy(&m));
  S(pthread_mutex_trylock(&m)); S(pthread_mutex_unlock(&m)); S(pthread_mutex_timedlock(&m,&ts)); S(pthread_mutex_lock(&m));
  S(pthread_mutex_destroy(&m)); S(pthread_mutex_init(&m,a)); S(pthread_mutex_lock(&m)); S(pthread_mutex_unlock(&m)); S(pthread_mutex_destroy(&m));
  printf("\n");
}
int main(void){
  pthread_mutexattr_t a; 
  pthread_mutexattr_init(&a); pthread_mutexattr_settype(&a,PTHREAD_MUTEX_NORMAL); run("normal",&a);
  pthread_mutexattr_settype(&a,PTHREAD_MUTEX_RECURSIVE); run("recursive",&a);
  pthread_mutexattr_settype(&a,PTHREAD_MUTEX_ERRORCHECK); run("errorcheck",&a);
  run("nullattr",NULL);
  pthread_mutexattr_init(&a); pthread_mutexattr_setrobust(&a,PTHREAD_MUTEX_ROBUST); run("robust",&a);
  pthread_mutexattr_init(&a); pthread_mutexattr_setprotocol(&a,PTHREAD_PRIO_INHERIT); run("pi",&a);
  pthread_mutexattr_init(&a); pthread_mutexattr_setpshared(&a,PTHREAD_PROCESS_SHARED); run("pshared",&a);
  pthread_mutex_t s = PTHREAD_MUTEX_INITIALIZER; printf("static:"); S(pthread_mutex_destroy(&s)); S(pthread_mutex_trylock(&s)); printf("\n");
  pthread_mutex_t z = PTHREAD_MUTEX_INITIALIZER; printf("busy:"); S(pthread_mutex_lock(&z)); S(pthread_mutex_destroy(&z)); S(pthread_mutex_unlock(&z)); printf("\n");
  pthread_mutex_t c = PTHREAD_MUTEX_INITIALIZER; pthread_cond_t cv = PTHREAD_COND_INITIALIZER; struct timespec ts; deadline(&ts);
  printf("cond:"); S(pthread_mutex_destroy(&c)); S(pthread_cond_timedwait(&cv,&c,&ts)); printf("\n");
  return 0;}
