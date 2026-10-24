#define _GNU_SOURCE
#include <semaphore.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/wait.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"line=%d errno=%d\n",__LINE__,errno);return __LINE__; } } while(0)
struct api {
    int (*init)(sem_t*,int,unsigned);
    int (*destroy)(sem_t*);
    int (*post)(sem_t*);
    int (*wait)(sem_t*);
    int (*trywait)(sem_t*);
    int (*timedwait)(sem_t*,const struct timespec*);
    int (*getvalue)(sem_t*,int*);
    sem_t *(*open)(const char*,int,...);
    int (*close)(sem_t*);
    int (*unlink)(const char*);
};
static struct api own={sem_init,sem_destroy,sem_post,sem_wait,sem_trywait,sem_timedwait,sem_getvalue,sem_open,sem_close,sem_unlink},host;
static struct timespec until(void) { struct timespec t;clock_gettime(CLOCK_REALTIME,&t);t.tv_sec+=2;return t; }
static void pause_ms(long n) { struct timespec t={n/1000,(n%1000)*1000000};while(nanosleep(&t,&t)&&errno==EINTR){} }
static int value(const struct api *a,sem_t *s) { int v=-1;return a->getvalue(s,&v)?-2:v; }
static int load_host(void) {
    void *lib=dlopen("libc.so.6",RTLD_NOW);CHECK(lib);
#define LOAD(field,name) do { *(void **)(&host.field)=dlsym(lib,name);CHECK(host.field); } while(0)
    LOAD(init,"sem_init");LOAD(destroy,"sem_destroy");LOAD(post,"sem_post");LOAD(wait,"sem_wait");
    LOAD(trywait,"sem_trywait");LOAD(timedwait,"sem_timedwait");LOAD(getvalue,"sem_getvalue");
    LOAD(open,"sem_open");LOAD(close,"sem_close");LOAD(unlink,"sem_unlink");
    if(getenv("FL_REQUIRE_INTERPOSE")) CHECK(host.post!=own.post && host.init!=own.init);
    return 0;
}
struct blocked { const struct api *api;sem_t *s;_Atomic int ready,done;int rc,err; };
static void *wait_worker(void *p) {
    struct blocked *w=p;struct timespec t=until();atomic_store(&w->ready,1);
    w->rc=w->api->timedwait(w->s,&t);w->err=errno;atomic_store(&w->done,1);return 0;
}
static int mixed(unsigned mask) {
    const struct api *init=mask&1?&own:&host,*wait=mask&2?&own:&host,*post=mask&4?&own:&host;
    sem_t s;CHECK(!init->init(&s,(mask>>3)&1,0));
    struct blocked w={.api=wait,.s=&s};pthread_t t;CHECK(!pthread_create(&t,0,wait_worker,&w));
    while(!atomic_load(&w.ready)){} pause_ms(30);CHECK(!atomic_load(&w.done));
    CHECK(!post->post(&s));CHECK(!pthread_join(t,0));
    CHECK(w.rc==0);CHECK(value(init,&s)==0);CHECK(!init->destroy(&s));return 0;
}
struct exchange { const struct api *producer,*consumer;sem_t ready,ack;unsigned data,reply;int bad; };
static void *exchange_worker(void *p) {
    struct exchange *x=p;
    for(unsigned n=1;n<=4000;n++) {
        struct timespec t=until();
        if(x->consumer->timedwait(&x->ready,&t) || x->data!=n) {x->bad=1;return 0;}
        x->reply=n^0x12345678u;
        if(x->consumer->post(&x->ack)) {x->bad=2;return 0;}
    }
    return 0;
}
static int exchange(unsigned mask) {
    const struct api *init=mask&1?&own:&host;
    struct exchange x={.producer=mask&2?&own:&host,.consumer=mask&2?&host:&own};
    CHECK(!init->init(&x.ready,mask&4,0));CHECK(!init->init(&x.ack,mask&4,0));
    pthread_t t;CHECK(!pthread_create(&t,0,exchange_worker,&x));
    for(unsigned n=1;n<=4000;n++) {
        x.data=n;CHECK(!x.producer->post(&x.ready));struct timespec end=until();
        CHECK(!x.producer->timedwait(&x.ack,&end));CHECK(x.reply==(n^0x12345678u));
    }
    CHECK(!pthread_join(t,0)&&!x.bad);CHECK(!init->destroy(&x.ready)&&!init->destroy(&x.ack));return 0;
}
struct release {const struct api *api;sem_t *s;_Atomic int ready;int rc;};
static void *release_worker(void *p) {
    struct release *r=p;struct timespec t=until();atomic_store(&r->ready,1);
    r->rc=r->api->timedwait(r->s,&t);
    if(!r->rc) {r->rc=r->api->destroy(r->s);if(mprotect(r->s,4096,PROT_NONE))r->rc=999;}
    return 0;
}
static int release_after_last_wait(unsigned own_wait) {
    const struct api *wait=own_wait?&own:&host;
    for(unsigned n=0;n<400;n++) {
        sem_t *s=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);CHECK(s!=MAP_FAILED);
        CHECK(!own.init(s,0,0));struct release r={.api=wait,.s=s};pthread_t t;
        CHECK(!pthread_create(&t,0,release_worker,&r));while(!atomic_load(&r.ready)){}
        CHECK(!own.post(s));CHECK(!pthread_join(t,0)&&!r.rc);CHECK(!munmap(s,4096));
    }
    return 0;
}
static int named_child(const char *name,const char *readyfd) {
    sem_t *s=sem_open(name,0);CHECK(s!=SEM_FAILED);
    int fd=atoi(readyfd);CHECK(write(fd,"x",1)==1);CHECK(!close(fd));struct timespec t=until();
    CHECK(!sem_timedwait(s,&t));CHECK(!sem_close(s));return 0;
}
static int named_exec(const char *executable,unsigned mask) {
    const struct api *creator=mask&1?&own:&host;
    char name[96];snprintf(name,sizeof(name),"/fl-mixed-%ld-%u",(long)getpid(),mask);
    sem_t *s=creator->open(name,O_CREAT|O_EXCL,0600,0);CHECK(s!=SEM_FAILED);
    int pipefd[2];CHECK(!pipe(pipefd));pid_t child=fork();CHECK(child>=0);
    if(!child) {
        close(pipefd[0]);char ready[32];snprintf(ready,sizeof(ready),"%d",pipefd[1]);
        if(!(mask&2)) {unsetenv("LD_PRELOAD");unsetenv("FL_REQUIRE_INTERPOSE");}
        execl(executable,executable,"child",name,ready,(char*)0);_exit(111);
    }
    CHECK(!close(pipefd[1]));char b=0;CHECK(read(pipefd[0],&b,1)==1&&b=='x');CHECK(!close(pipefd[0]));
    pause_ms(30);CHECK(!creator->post(s));int status=0;CHECK(waitpid(child,&status,0)==child);
    CHECK(!creator->unlink(name));int v=value(creator,s);CHECK(!creator->close(s));
    CHECK(WIFEXITED(status)&&WEXITSTATUS(status)==0&&v==0);return 0;
}
static int layout(void) {
    for(int shared=0;shared<2;shared++) {
        sem_t s;memset(&s,0xa5,sizeof(s));CHECK(!sem_init(&s,shared,7));
        uint32_t words[3];memcpy(words,&s,sizeof(words));
        printf("shared=%d value=%u waiters=%u flag=%u\n",shared,words[0],words[1],words[2]);
        CHECK(!sem_destroy(&s));
    }
    return 0;
}
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"child"))return argc==4?named_child(argv[2],argv[3]):2;
    CHECK(!load_host());unsigned mask=argc>2?(unsigned)strtoul(argv[2],0,10):0;int rc;
    if(!strcmp(argv[1],"mixed"))rc=mixed(mask);
    else if(!strcmp(argv[1],"exchange"))rc=exchange(mask);
    else if(!strcmp(argv[1],"named"))rc=named_exec(argv[0],mask);
    else if(!strcmp(argv[1],"release"))rc=release_after_last_wait(mask);
    else if(!strcmp(argv[1],"layout"))rc=layout();else return 2;
    printf("%s/%u %s\n",argv[1],mask,rc?"FAIL":"PASS");return rc?1:0;
}
