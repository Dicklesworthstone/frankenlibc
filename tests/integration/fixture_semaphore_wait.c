#define _GNU_SOURCE
#include <semaphore.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
struct api {
    int (*init)(sem_t *,int,unsigned);
    int (*destroy)(sem_t *);
    int (*post)(sem_t *);
    int (*wait)(sem_t *);
    int (*trywait)(sem_t *);
    int (*timedwait)(sem_t *,const struct timespec *);
    int (*clockwait)(sem_t *,clockid_t,const struct timespec *);
    int (*value)(sem_t *,int *);
    int *(*error)(void);
    int (*create)(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *);
    int (*join)(pthread_t,void **);
    int (*cancel)(pthread_t);
    pthread_t (*self)(void);
    void (*testcancel)(void);
};
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
static struct timespec future(int clock,long ns) {
    struct timespec ts;clock_gettime(clock,&ts);ts.tv_nsec+=ns;
    ts.tv_sec+=ts.tv_nsec/1000000000;ts.tv_nsec%=1000000000;return ts;
}
static int timed(const struct api *a,sem_t *s,int op,const struct timespec *ts) {
    return op==0?a->timedwait(s,ts):a->clockwait(s,op==1?CLOCK_REALTIME:CLOCK_MONOTONIC,ts);
}
int semaphore_deadlines(const struct api *a) {
    const int64_t seconds[]={INT64_MIN,-1,0};
    for(int shared=0;shared<2;shared++) for(int op=0;op<3;op++) {
        for(int token=0;token<2;token++) for(int bad=0;bad<4;bad++) {
            const int64_t ns[]={-1,1000000000,INT64_MIN,INT64_MAX};
            sem_t s;CHECK(!a->init(&s,shared,token));struct timespec ts={0,ns[bad]};
            *a->error()=0;CHECK(timed(a,&s,op,&ts)==-1 && *a->error()==EINVAL);
            int v;CHECK(!a->value(&s,&v)&&v==token);CHECK(!a->destroy(&s));
        }
        for(int token=0;token<2;token++) for(int i=0;i<3;i++) {
            sem_t s;CHECK(!a->init(&s,shared,token));struct timespec ts={seconds[i],0};
            *a->error()=0;int r=timed(a,&s,op,&ts);
            CHECK(token ? r==0 : r==-1 && *a->error()==ETIMEDOUT);
            int v;CHECK(!a->value(&s,&v)&&v==0);CHECK(!a->destroy(&s));
        }
        sem_t s;CHECK(!a->init(&s,shared,0));struct timespec before,after;
        struct timespec until=future(op==2?CLOCK_MONOTONIC:CLOCK_REALTIME,30000000);
        clock_gettime(CLOCK_MONOTONIC,&before);*a->error()=0;
        CHECK(timed(a,&s,op,&until)==-1 && *a->error()==ETIMEDOUT);
        clock_gettime(CLOCK_MONOTONIC,&after);
        int64_t elapsed=(after.tv_sec-before.tv_sec)*1000000000LL+after.tv_nsec-before.tv_nsec;
        CHECK(elapsed>=25000000 && elapsed<3000000000LL);CHECK(!a->destroy(&s));
    }
    return 0;
}
struct cancel_state { const struct api *api;sem_t semaphore;int op;_Atomic int ready,returned,cleaned; };
static void clean(void *p) { struct cancel_state *s=p;atomic_fetch_add(&s->cleaned,1); }
static void *cancel_worker(void *p) {
    struct cancel_state *s=p;
    pthread_cleanup_push(clean,s);
    if(s->api->cancel(s->api->self())) {atomic_store(&s->returned,10);return (void*)10;}
    struct timespec until={INT64_MAX,0};
    if(s->op==0) s->api->wait(&s->semaphore);else timed(s->api,&s->semaphore,s->op-1,&until);
    atomic_store(&s->returned,1);
    s->api->testcancel();
    pthread_cleanup_pop(1);
    return (void*)2;
}
int semaphore_pending_cancel(const struct api *a) {
    for(int op=0;op<4;op++) {
        struct cancel_state s={.api=a,.op=op};CHECK(!a->init(&s.semaphore,0,1));
        pthread_t t;CHECK(!a->create(&t,0,cancel_worker,&s));void *result=0;
        CHECK(!a->join(t,&result));int v;CHECK(!a->value(&s.semaphore,&v));
        CHECK(!a->destroy(&s.semaphore));
        CHECK(result==PTHREAD_CANCELED && atomic_load(&s.cleaned)==1);
        /* Live glibc distinguishes mandatory sem_wait/sem_timedwait checks
           from sem_clockwait's immediately available-token path. */
        CHECK(atomic_load(&s.returned)==(op>=2));
        CHECK(v==(op<2));
    }
    return 0;
}
static void *blocked_worker(void *p) {
    struct cancel_state *s=p;
    pthread_cleanup_push(clean,s);
    atomic_store(&s->ready,1);struct timespec until={INT64_MAX,0};
    if(s->op==0) s->api->wait(&s->semaphore);else timed(s->api,&s->semaphore,s->op-1,&until);
    atomic_store(&s->returned,1);
    pthread_cleanup_pop(1);return (void*)2;
}
int semaphore_blocked_cancel(const struct api *a) {
    for(int op=0;op<4;op++) {
        struct cancel_state s={.api=a,.op=op};CHECK(!a->init(&s.semaphore,0,0));
        pthread_t t;CHECK(!a->create(&t,0,blocked_worker,&s));
        while(!atomic_load(&s.ready)) { }
        struct timespec delay={0,20000000};nanosleep(&delay,0);CHECK(!a->cancel(t));
        void *result=0;CHECK(!a->join(t,&result)&&result==PTHREAD_CANCELED);
        CHECK(atomic_load(&s.cleaned)==1 && !atomic_load(&s.returned));
        CHECK(!a->post(&s.semaphore)&&!a->trywait(&s.semaphore)&&!a->destroy(&s.semaphore));
    }
    return 0;
}
struct overflow_state { const struct api *api;sem_t semaphore;pthread_barrier_t barrier;_Atomic int bad; };
static void *overflow_worker(void *p) {
    struct overflow_state *s=p;pthread_barrier_wait(&s->barrier);
    for(int i=0;i<100000;i++) {
        if(s->api->post(&s->semaphore)!=-1 || *s->api->error()!=EOVERFLOW) atomic_store(&s->bad,1);
    }
    return 0;
}
int semaphore_post_overflow_never_changes_state(const struct api *a) {
    struct overflow_state s={.api=a};CHECK(!a->init(&s.semaphore,0,INT_MAX));
    CHECK(!pthread_barrier_init(&s.barrier,0,5));pthread_t workers[4];
    for(int i=0;i<4;i++) CHECK(!a->create(&workers[i],0,overflow_worker,&s));
    pthread_barrier_wait(&s.barrier);
    for(int i=0;i<100000;i++) {int v;CHECK(!a->value(&s.semaphore,&v));if(v!=INT_MAX)atomic_store(&s.bad,1);}
    for(int i=0;i<4;i++)CHECK(!a->join(workers[i],0));
    CHECK(!pthread_barrier_destroy(&s.barrier)&&!a->destroy(&s.semaphore));
    CHECK(!atomic_load(&s.bad));return 0;
}
#ifdef SEMAPHORE_DRIVER
static int *error_slot(void) { return &errno; }
int main(int argc,char **argv) {
    struct api a={sem_init,sem_destroy,sem_post,sem_wait,sem_trywait,sem_timedwait,sem_clockwait,sem_getvalue,error_slot,pthread_create,pthread_join,pthread_cancel,pthread_self,pthread_testcancel};
    if(argc!=2)return 2;int op=atoi(argv[1]);
    int r=op==0?semaphore_deadlines(&a):op==1?semaphore_pending_cancel(&a):op==2?semaphore_blocked_cancel(&a):semaphore_post_overflow_never_changes_state(&a);
    printf("protocol=%d line=%d\n",op,r);return r?1:0;
}
#endif
