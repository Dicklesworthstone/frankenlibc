#define _GNU_SOURCE 1
#include <aio.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", __LINE__, #x, errno); _Exit(1); } } while (0)
#if defined(_FILE_OFFSET_BITS) && _FILE_OFFSET_BITS == 64
#define SYMBOL(n) n "64"
#else
#define SYMBOL(n) n
#endif
_Static_assert(sizeof(struct aioinit)==32 && offsetof(struct aioinit,aio_idle_time)==24, "GNU aioinit layout");
_Static_assert(offsetof(struct aiocb,aio_offset)==128 && offsetof(struct aiocb,__error_code)==112, "Linux LP64 aiocb layout");
static int (*ar)(struct aiocb *);
static int (*ae)(const struct aiocb *);
static ssize_t (*av)(struct aiocb *);
static int (*ac)(int, struct aiocb *);
static int (*ll)(int, struct aiocb *const[], int, struct sigevent *);
static void (*ai)(const struct aioinit *);

static void *bind(const char *name) {
    void *p = dlsym(RTLD_DEFAULT, name);
    CHECK(p != NULL);
    const char *library = getenv("FRANKENLIBC_TEST_LIBRARY");
    if (library) {
        Dl_info info;
        struct stat expected, actual;
        CHECK(dladdr(p, &info) != 0);
        CHECK(stat(library, &expected) == 0 && stat(info.dli_fname, &actual) == 0);
        CHECK(expected.st_dev == actual.st_dev && expected.st_ino == actual.st_ino);
    }
    return p;
}
static void init_api(void) {
    ar = bind(SYMBOL("aio_read")); ae = bind(SYMBOL("aio_error"));
    av = bind(SYMBOL("aio_return")); ac = bind(SYMBOL("aio_cancel"));
    ll = bind(SYMBOL("lio_listio")); ai = bind("aio_init");
}
static void pause_ms(int ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000L};
    while (nanosleep(&t, &t) && errno == EINTR) {}
}
static void config(int workers, int idle) {
    struct aioinit hint = {.aio_threads=workers, .aio_num=1, .aio_idle_time=idle};
    ai(&hint);
    memset(&hint, 0x55, sizeof hint); /* implementation must have consumed it */
}
static void request(struct aiocb *cb, int fd, void *buffer) {
    memset(cb, 0, sizeof *cb);
    cb->aio_fildes=fd; cb->aio_buf=buffer; cb->aio_nbytes=1;
    cb->aio_sigevent.sigev_notify=SIGEV_NONE;
}
static void completed(struct aiocb *cb, char *byte, char expected) {
    for (int i=0; i<5000 && ae(cb)==EINPROGRESS; i++) pause_ms(1);
    CHECK(ae(cb)==0); CHECK(av(cb)==1); CHECK(*byte==expected);
}
static int tasks(void) {
    DIR *d=opendir("/proc/self/task"); CHECK(d);
    int count=0; struct dirent *entry;
    while ((entry=readdir(d))) if (entry->d_name[0]>='0' && entry->d_name[0]<='9') count++;
    CHECK(closedir(d)==0); return count;
}
/* Observe the actual blocking read, not a sleep-dependent guess or a cancel
 * probe that could itself cancel a not-yet-started request. */
static int kernel_reader(int fd) {
    DIR *d=opendir("/proc/self/task"); CHECK(d);
    struct dirent *entry; int found=0;
    while ((entry=readdir(d))) {
        if (entry->d_name[0]<'0' || entry->d_name[0]>'9') continue;
        char path[320], text[512];
        CHECK(snprintf(path, sizeof path, "/proc/self/task/%s/syscall", entry->d_name)>0);
        int f=open(path, O_RDONLY|O_CLOEXEC); if (f<0) continue;
        ssize_t n=read(f,text,sizeof text-1); close(f);
        if (n<=0) continue;
        text[n]=0; long call; unsigned long arg;
        if (sscanf(text, "%ld %lx", &call, &arg)==2 && call==SYS_read && arg==(unsigned long)fd) found=1;
    }
    closedir(d); return found;
}
static void running(int fd, struct aiocb *cb) {
    for (int i=0; i<3000 && !kernel_reader(fd); i++) pause_ms(1);
    CHECK(kernel_reader(fd)); CHECK(ae(cb)==EINPROGRESS); CHECK(ac(fd,cb)==AIO_NOTCANCELED);
}
static void pair(int p[2]) { CHECK(pipe(p)==0); }
static void finish_pair(int p[2]) { CHECK(close(p[0])==0); CHECK(close(p[1])==0); }

static void backlog(void) {
    enum {N=128}; config(2,1); int baseline=tasks(), p[2]; pair(p);
    struct aiocb cb[N]; char bytes[N]={0}, input[N]; memset(input,'q',sizeof input);
    request(&cb[0],p[0],&bytes[0]); CHECK(ar(&cb[0])==0); running(p[0],&cb[0]);
    for (int i=1;i<N;i++) { request(&cb[i],p[0],&bytes[i]); CHECK(ar(&cb[i])==0); }
    CHECK(tasks()<=baseline+2); /* queued control blocks are not sleeping threads */
    CHECK(write(p[1],input,sizeof input)==sizeof input);
    for (int i=0;i<N;i++) completed(&cb[i],&bytes[i],'q');
    finish_pair(p);
}

static void limit(int configured) {
    enum {N=12}; config(configured,1); int cap=configured<1?1:configured;
    int baseline=tasks(), blocked[2][2], ready[N][2];
    struct aiocb blockers[2], cb[N]; char b[2]={0}, bytes[N]={0};
    for (int i=0;i<cap;i++) { pair(blocked[i]); request(&blockers[i],blocked[i][0],&b[i]); CHECK(ar(&blockers[i])==0); running(blocked[i][0],&blockers[i]); }
    for (int i=0;i<N;i++) { pair(ready[i]); CHECK(write(ready[i][1],"z",1)==1); request(&cb[i],ready[i][0],&bytes[i]); CHECK(ar(&cb[i])==0); }
    CHECK(tasks()<=baseline+cap);
    for (int i=0;i<N;i++) CHECK(ae(&cb[i])==EINPROGRESS);
    CHECK(ac(ready[0][0],&cb[0])==AIO_CANCELED);
    CHECK(ae(&cb[0])==ECANCELED && av(&cb[0])==-1);
    char untouched=0; CHECK(read(ready[0][0],&untouched,1)==1 && untouched=='z');
    for (int i=0;i<cap;i++) { CHECK(write(blocked[i][1],"b",1)==1); completed(&blockers[i],&b[i],'b'); finish_pair(blocked[i]); }
    for (int i=1;i<N;i++) completed(&cb[i],&bytes[i],'z');
    for (int i=0;i<N;i++) finish_pair(ready[i]);
}

static void default_limit(void) {
    enum {CAP=20,N=28}; int baseline=tasks(), p[N][2]; struct aiocb cb[N]; char bytes[N]={0};
    for (int i=0;i<N;i++) {
        pair(p[i]); request(&cb[i],p[i][0],&bytes[i]); CHECK(ar(&cb[i])==0);
        if (i<CAP) running(p[i][0],&cb[i]);
    }
    CHECK(tasks()<=baseline+CAP);
    for (int i=CAP;i<N;i++) { CHECK(ac(p[i][0],&cb[i])==AIO_CANCELED); CHECK(ae(&cb[i])==ECANCELED && av(&cb[i])==-1); }
    for (int i=0;i<CAP;i++) CHECK(write(p[i][1],"d",1)==1);
    for (int i=0;i<CAP;i++) completed(&cb[i],&bytes[i],'d');
    for (int i=0;i<N;i++) finish_pair(p[i]);
}

static void idle_restart(void) {
    config(2,1); int baseline=tasks(), p[2]; pair(p);
    for (int wave=0;wave<3;wave++) {
        struct aiocb cb; char byte=0;
        for (int i=0;i<80;i++) {
            CHECK(write(p[1],"i",1)==1); request(&cb,p[0],&byte); CHECK(ar(&cb)==0); completed(&cb,&byte,'i');
        }
        CHECK(tasks()>baseline && tasks()<=baseline+2);
        for (int i=0;i<4000 && tasks()!=baseline;i++) pause_ms(1);
        CHECK(tasks()==baseline);
    }
    finish_pair(p);
}

struct callback_state { int fd; size_t stack; _Atomic int calls; };
static void nested_callback(union sigval value) {
    struct callback_state *s=value.sival_ptr;
    pthread_attr_t attr; size_t stack;
    CHECK(pthread_getattr_np(pthread_self(),&attr)==0);
    CHECK(pthread_attr_getstacksize(&attr,&stack)==0 && stack==s->stack);
    CHECK(pthread_attr_destroy(&attr)==0);
    struct aiocb next; char byte=0; request(&next,s->fd,&byte);
    CHECK(ar(&next)==0); completed(&next,&byte,'2');
    atomic_fetch_add_explicit(&s->calls,1,memory_order_release);
    pthread_exit(NULL); /* must not unwind through / retire the I/O pool */
}
static void callback_progress(void) {
    config(1,1); int p[2]; pair(p); struct aiocb cb; char byte=0;
    struct callback_state state={.fd=p[0],.stack=1024*1024};
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    pthread_attr_t *attr=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(attr!=MAP_FAILED);
    CHECK(pthread_attr_init(attr)==0); CHECK(pthread_attr_setstacksize(attr,state.stack)==0);
    request(&cb,p[0],&byte); cb.aio_sigevent.sigev_notify=SIGEV_THREAD;
    cb.aio_sigevent.sigev_notify_function=nested_callback;
    cb.aio_sigevent.sigev_notify_attributes=attr; cb.aio_sigevent.sigev_value.sival_ptr=&state;
    CHECK(ar(&cb)==0);
    running(p[0],&cb); CHECK(write(p[1],"12",2)==2); completed(&cb,&byte,'1');
    for (int i=0;i<5000 && atomic_load_explicit(&state.calls,memory_order_acquire)==0;i++) pause_ms(1);
    CHECK(atomic_load(&state.calls)==1);
    /* Nested callback has exited; a subsequent request still has a live pool. */
    struct aiocb later; char more=0; CHECK(write(p[1],"3",1)==1); request(&later,p[0],&more); CHECK(ar(&later)==0); completed(&later,&more,'3');
    CHECK(pthread_attr_destroy(attr)==0); CHECK(munmap(attr,page)==0); finish_pair(p);
}
static void count_callback(union sigval value) {
    _Atomic int *calls=value.sival_ptr;
    atomic_fetch_add_explicit(calls,1,memory_order_release);
}
static _Atomic int signal_count, signal_value, signal_code;
static void aio_signal(int signo, siginfo_t *info, void *context) {
    (void)signo; (void)context;
    atomic_store_explicit(&signal_value,info->si_value.sival_int,memory_order_relaxed);
    atomic_store_explicit(&signal_code,info->si_code,memory_order_relaxed);
    atomic_fetch_add_explicit(&signal_count,1,memory_order_release);
}
static void canceled_notifications(void) {
    _Static_assert(ATOMIC_INT_LOCK_FREE==2, "signal handler needs lock-free atomics");
    struct sigaction action={.sa_sigaction=aio_signal,.sa_flags=SA_SIGINFO};
    sigemptyset(&action.sa_mask); CHECK(sigaction(SIGUSR1,&action,NULL)==0);
    config(1,1); int p[2]; pair(p); struct aiocb blocker; char first=0;
    request(&blocker,p[0],&first); CHECK(ar(&blocker)==0); running(p[0],&blocker);
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    struct aiocb *cb=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); CHECK(cb!=MAP_FAILED);
    char *bytes=(char *)(cb+3); _Atomic int calls=0;
    struct aiocb *list[3]={cb,cb+1,cb+2};
    for (int i=0;i<3;i++) { request(&cb[i],p[0],bytes+i); cb[i].aio_lio_opcode=LIO_READ; }
    cb[0].aio_sigevent.sigev_notify=SIGEV_SIGNAL; cb[0].aio_sigevent.sigev_signo=SIGUSR1;
    cb[0].aio_sigevent.sigev_value.sival_int=731;
    cb[1].aio_sigevent.sigev_notify=SIGEV_THREAD;
    cb[1].aio_sigevent.sigev_notify_function=count_callback; cb[1].aio_sigevent.sigev_value.sival_ptr=&calls;
    struct sigevent event={.sigev_notify=SIGEV_THREAD,.sigev_notify_function=count_callback};
    event.sigev_value.sival_ptr=&calls;
    CHECK(ll(LIO_NOWAIT,list,3,&event)==0);
    CHECK(ac(p[0],NULL)==AIO_NOTCANCELED);
    for (int i=0;i<3;i++) CHECK(ae(&cb[i])==ECANCELED && av(&cb[i])==-1);
    CHECK(mprotect(cb,page,PROT_NONE)==0);
    for (int i=0;i<3000 && atomic_load_explicit(&signal_count,memory_order_acquire)==0;i++) pause_ms(1);
    CHECK(atomic_load(&signal_count)==1 && atomic_load(&signal_value)==731 && atomic_load(&signal_code)==SI_ASYNCIO);
    for (int i=0;i<3000 && atomic_load_explicit(&calls,memory_order_acquire)!=2;i++) pause_ms(1);
    CHECK(atomic_load(&calls)==2); /* notifications must not wait for blocked I/O */
    CHECK(ae(&blocker)==EINPROGRESS); CHECK(write(p[1],"c",1)==1); completed(&blocker,&first,'c');
    pause_ms(20); CHECK(atomic_load(&calls)==2); CHECK(munmap(cb,page)==0); finish_pair(p);
}

struct producer { int fd; pthread_barrier_t *start; };
static void *produce(void *arg) {
    struct producer *s=arg; int rc=pthread_barrier_wait(s->start); CHECK(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD);
    for (int i=0;i<100;i++) { struct aiocb cb; char byte=0; request(&cb,s->fd,&byte); CHECK(ar(&cb)==0); completed(&cb,&byte,'r'); if (i%7==0) pause_ms(1); }
    return NULL;
}
static void retirement_race(void) {
    config(3,0); int fd=(int)syscall(SYS_memfd_create,"aio-pool",0); CHECK(fd>=0); CHECK(write(fd,"r",1)==1);
    enum {N=8}; pthread_t threads[N]; pthread_barrier_t start; CHECK(pthread_barrier_init(&start,NULL,N)==0);
    struct producer s={fd,&start};
    for (int i=0;i<N;i++) CHECK(pthread_create(&threads[i],NULL,produce,&s)==0);
    for (int i=0;i<N;i++) CHECK(pthread_join(threads[i],NULL)==0);
    CHECK(pthread_barrier_destroy(&start)==0); CHECK(close(fd)==0);
}

int main(int argc,char **argv) {
    CHECK(argc==2); alarm(25); init_api();
    if (!strcmp(argv[1],"backlog")) backlog();
    else if (!strcmp(argv[1],"limit")) limit(2);
    else if (!strcmp(argv[1],"clamp")) limit(0);
    else if (!strcmp(argv[1],"default-limit")) default_limit();
    else if (!strcmp(argv[1],"idle-restart")) idle_restart();
    else if (!strcmp(argv[1],"callback-progress")) callback_progress();
    else if (!strcmp(argv[1],"canceled-notifications")) canceled_notifications();
    else if (!strcmp(argv[1],"retirement-race")) retirement_race();
    else CHECK(0);
    printf("PASS %s\n",argv[1]); return 0;
}
