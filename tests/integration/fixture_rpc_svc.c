#define _GNU_SOURCE
/* Published glibc LP64 Sun RPC layouts; libtirpc's SVCXPRT is NOT this ABI.
 * Wire expectations below are independent network-order words, not the
 * implementation's serializer. No rpcbind, external DNS or privileged ports. */
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct { int flavor; char *base; unsigned length; } Auth;
typedef struct Xprt Xprt;
typedef int (*Proc)(void *, void *);
typedef struct {
    int (*recv)(Xprt *, void *); int (*stat)(Xprt *);
    int (*getargs)(Xprt *, Proc, void *); int (*reply)(Xprt *, void *);
    int (*freeargs)(Xprt *, Proc, void *); void (*destroy)(Xprt *);
} Ops;
struct Xprt {
    int fd; unsigned short port; const Ops *ops; int addrlen;
    struct sockaddr_in peer; Auth verifier; void *p1, *p2; char padding[256];
};
typedef struct { unsigned long program, version, procedure; Auth cred; void *cooked; Xprt *x; } Request;
typedef struct { unsigned long stamp; char *machine; unsigned uid, gid, count, *groups; } SysAuth;
_Static_assert(sizeof(Xprt) == 336 && offsetof(Xprt, verifier) == 40, "glibc LP64 SVCXPRT");
_Static_assert(sizeof(Request) == 64 && sizeof(Auth) == 24, "glibc LP64 request/auth");
static Xprt *(*create)(int), *(*bufcreate)(int,unsigned,unsigned);
static int (*reg)(Xprt *,unsigned long,unsigned long,void (*)(Request *,Xprt *),int);
static void (*unreg)(unsigned long,unsigned long), (*common)(int), (*getmask)(int), (*getset)(fd_set *), (*getpoll)(struct pollfd *,int);
static void (*run)(void), (*stop)(void);
static int (*sendreply)(Xprt *,Proc,void *), (*xu32)(void *,void *), (*xstr)(void *,char **,unsigned);
static void (*err_decode)(Xprt *), (*err_proc)(Xprt *), (*err_prog)(Xprt *), (*err_sys)(Xprt *), (*err_weak)(Xprt *), (*err_auth)(Xprt *,int), (*err_vers)(Xprt *,unsigned long,unsigned long);
static void *(*fdset_slot)(void), *(*poll_slot)(void), *(*count_slot)(void);
static unsigned calls, cleaned;
static const unsigned PROGRAM = 0x31234567;
static const char *scenario;
static Xprt *server;
static int client;

static void check(int ok,const char *expression,int line) {
    if (!ok) { fprintf(stderr,"FAIL line %d: %s errno=%d\n",line,expression,errno); _Exit(1); }
}
#define CHECK(x) check(!!(x),#x,__LINE__)
static void *symbol(const char *name) {
    void *p=dlsym(RTLD_DEFAULT,name);
    if (!p) p=dlvsym(RTLD_DEFAULT,name,"GLIBC_2.2.5");
    CHECK(p!=NULL);
    const char *expected=getenv("FRANKENLIBC_TEST_LIBRARY");
    if (expected) {
        Dl_info info; struct stat a,b;
        CHECK(dladdr(p,&info) && !stat(info.dli_fname,&a) && !stat(expected,&b));
        if (a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) { fprintf(stderr,"WRONG_PROVIDER %s\n",name); _Exit(2); }
    }
    return p;
}
#define LOAD(p,n) (*(void **)(&(p))=symbol(n))
static void load(void) {
    LOAD(create,"svcudp_create"); LOAD(bufcreate,"svcudp_bufcreate"); LOAD(reg,"svc_register"); LOAD(unreg,"svc_unregister");
    LOAD(common,"svc_getreq_common"); LOAD(getmask,"svc_getreq"); LOAD(getset,"svc_getreqset"); LOAD(getpoll,"svc_getreq_poll");
    LOAD(run,"svc_run"); LOAD(stop,"svc_exit"); LOAD(sendreply,"svc_sendreply"); LOAD(xu32,"xdr_u_int"); LOAD(xstr,"xdr_string");
    LOAD(err_decode,"svcerr_decode"); LOAD(err_proc,"svcerr_noproc"); LOAD(err_prog,"svcerr_noprog"); LOAD(err_sys,"svcerr_systemerr");
    LOAD(err_weak,"svcerr_weakauth"); LOAD(err_auth,"svcerr_auth"); LOAD(err_vers,"svcerr_progvers");
    LOAD(fdset_slot,"__rpc_thread_svc_fdset"); LOAD(poll_slot,"__rpc_thread_svc_pollfd"); LOAD(count_slot,"__rpc_thread_svc_max_pollfd");
}
static int void_proc(void *x,void *p) { (void)x;(void)p; return 1; }
static int string_proc(void *x,void *p) { return xstr(x,p,128); }
static void cleanup(void *p) { (void)p; ++cleaned; }
static void handler(Request *r,Xprt *x) {
    ++calls; CHECK(r->program==PROGRAM && r->version==1 && r->x==x);
    if (r->procedure==1) {
        unsigned value=0;
        if (!x->ops->getargs(x,xu32,&value)) { err_decode(x); return; }
        value+=7; CHECK(sendreply(x,xu32,&value)); CHECK(x->ops->freeargs(x,xu32,&value));
    } else if (r->procedure==2) {
        char *text=NULL; CHECK(x->ops->getargs(x,string_proc,&text)); CHECK(!strcmp(text,"native-rpc"));
        CHECK(sendreply(x,string_proc,&text)); CHECK(x->ops->freeargs(x,string_proc,&text));
    } else if (r->procedure==3) err_proc(x);
    else if (r->procedure==4) err_decode(x);
    else if (r->procedure==5) err_sys(x);
    else if (r->procedure==6) err_weak(x);
    else if (r->procedure==7) err_auth(x,4);
    else if (r->procedure==8) err_vers(x,1,9);
    else if (r->procedure==9) {
        CHECK(r->cred.flavor==1 && r->cooked!=NULL);
        SysAuth *a=r->cooked;
        CHECK(a->stamp==1234 && !strcmp(a->machine,"host") && a->uid==1001 && a->gid==1002 && a->count==2 && a->groups[0]==11 && a->groups[1]==12);
        CHECK(sendreply(x,void_proc,NULL));
    } else if (r->procedure==10) { CHECK(sendreply(x,void_proc,NULL)); x->ops->destroy(x); }
    else if (r->procedure==11) { unreg(PROGRAM,1); CHECK(reg(x,PROGRAM,1,handler,0)); CHECK(sendreply(x,void_proc,NULL)); }
    else if (r->procedure==12) {
        pthread_cleanup_push(cleanup,NULL);
        CHECK(sendreply(x,void_proc,NULL)); pthread_exit((void *)19);
        pthread_cleanup_pop(1);
    } else if (r->procedure==13) { CHECK(sendreply(x,void_proc,NULL)); stop(); }
    else if (r->procedure==14) { err_prog(x); }
    else CHECK(sendreply(x,void_proc,NULL));
}
static void other_handler(Request *r,Xprt *x) { (void)r; (void)x; CHECK(0); }
static void word(unsigned char *data,size_t offset,uint32_t value) { value=htonl(value); memcpy(data+offset,&value,4); }
static uint32_t readword(const unsigned char *data,size_t offset) { uint32_t value;memcpy(&value,data+offset,4);return ntohl(value); }
static size_t request(unsigned char *data,unsigned xid,unsigned prog,unsigned vers,unsigned proc) {
    unsigned v[]={xid,0,2,prog,vers,proc,0,0,0,0};
    for (size_t i=0;i<10;++i) word(data,4*i,v[i]);
    return 40;
}
static void send_packet(const void *data,size_t len) {
    struct sockaddr_in dest={.sin_family=AF_INET,.sin_port=htons(server->port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(sendto(client,data,len,0,(void *)&dest,sizeof(dest))==(ssize_t)len);
}
static void drive(void) {
    struct pollfd p={.fd=server->fd,.events=POLLIN}; CHECK(poll(&p,1,1000)==1 && (p.revents&POLLIN));
    if (!strcmp(scenario,"fdset")) {
        fd_set set=*(fd_set *)fdset_slot(); CHECK(FD_ISSET(server->fd,&set));
        struct timeval wait={1,0}; CHECK(select(server->fd+1,&set,NULL,NULL,&wait)==1); getset(&set);
    } else if (!strcmp(scenario,"poll")) {
        int count=*(int *)count_slot(); struct pollfd *fds=*(struct pollfd **)poll_slot(); CHECK(count>0 && fds);
        int ready=poll(fds,(nfds_t)count,1000); CHECK(ready>=1); getpoll(fds,ready);
    } else if (!strcmp(scenario,"mask")) { CHECK(server->fd<32); getmask((int)(1u<<server->fd)); }
    else common(server->fd);
}
static size_t response(unsigned char *data) {
    struct pollfd p={.fd=client,.events=POLLIN}; CHECK(poll(&p,1,1000)==1 && (p.revents&POLLIN));
    ssize_t n=recv(client,data,2048,0);CHECK(n>=20); return (size_t)n;
}
static void expect_reply(unsigned xid,int denied,unsigned code,int detail,unsigned result) {
    unsigned char data[2048];size_t n=response(data);
    if(getenv("RPC_TRACE")) {
        fprintf(stderr,"reply expected xid=%u code=%u:",xid,code);
        for(size_t i=0;i+4<=n;i+=4) fprintf(stderr," %u",readword(data,i));
        fprintf(stderr,"\n");
    }
    CHECK(readword(data,0)==xid && readword(data,4)==1 && readword(data,8)==(unsigned)denied);
    if (denied) { CHECK(readword(data,12)==code); if (detail>=0) CHECK(readword(data,16)==(unsigned)detail); }
    else { CHECK(n>=24 && readword(data,12)==0 && readword(data,16)==0 && readword(data,20)==code);
        if (detail>=0) CHECK(n>=28 && readword(data,24)==result); }
}
static void exchange(unsigned proc,unsigned xid) {
    unsigned char data[2048]; size_t n=request(data,xid,PROGRAM,1,proc);
    if (proc==1) { word(data,n,35); n+=4; }
    send_packet(data,n); drive(); expect_reply(xid,0,0,proc==1?0:-1,42);
}
static void *serve_thread(void *unused) { (void)unused; common(server->fd); return NULL; }
static void *run_client(void *unused) {
    (void)unused; unsigned char data[2048]; size_t n=request(data,71,PROGRAM,1,13);
    send_packet(data,n); expect_reply(71,0,0,-1,0); return NULL;
}
static void transport(void) {
    unsigned char data[2048];size_t n=request(data,22,PROGRAM,1,1);word(data,n,35);send_packet(data,n+4);
    struct pollfd p={server->fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
    unsigned long msg[12]={0};char cred[400],verifier[400];
    ((Auth *)((char *)msg+48))->base=cred;((Auth *)((char *)msg+72))->base=verifier;
    CHECK(server->ops->recv(server,msg));CHECK(msg[0]==22 && msg[2]==2 && msg[3]==PROGRAM && msg[4]==1 && msg[5]==1);
    unsigned value=0;CHECK(server->ops->getargs(server,xu32,&value) && value==35);value+=7;
    memset(msg,0,sizeof(msg)); *(int *)((char *)msg+8)=1;
    *(void **)((char *)msg+56)=&value; *(Proc *)((char *)msg+64)=xu32;
    CHECK(server->ops->reply(server,msg)); expect_reply(22,0,0,0,42);
    CHECK(server->ops->freeargs(server,xu32,&value));
}
int main(int argc,char **argv) {
    CHECK(argc==2);scenario=argv[1];load();
    int borrowed=-1;
    if (!strcmp(scenario,"borrowed")) {
        borrowed=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK,0);CHECK(borrowed>=0);
        struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        CHECK(!bind(borrowed,(void *)&a,sizeof(a)));
    }
    server=!strcmp(scenario,"oversized")?bufcreate(-1,128,128):create(borrowed);
    CHECK(server!=NULL && server->fd>=0 && server->port && server->ops!=NULL);
    if (borrowed>=0) CHECK(server->fd==borrowed && (fcntl(borrowed,F_GETFL)&O_NONBLOCK));
    client=socket(AF_INET,SOCK_DGRAM,0);CHECK(client>=0);
    CHECK(reg(server,PROGRAM,1,handler,0));
    if (!strcmp(scenario,"transport")) transport();
    else if (!strcmp(scenario,"errors")) {
        unsigned char data[2048];
        size_t n=request(data,30,PROGRAM+1,1,0);send_packet(data,n);drive();expect_reply(30,0,1,-1,0);
        n=request(data,31,PROGRAM,2,0);send_packet(data,n);drive();expect_reply(31,0,2,0,1);
        for (unsigned proc=3;proc<=8;++proc) { n=request(data,proc,PROGRAM,1,proc);send_packet(data,n);drive();
            if(proc==6 || proc==7) expect_reply(proc,1,1,proc==6?5:4,0);
            else expect_reply(proc,0,proc==3?3:proc==4?4:proc==5?5:2,proc==8?0:-1,1);
        }
    } else if (!strcmp(scenario,"auth")) {
        unsigned char data[2048];request(data,40,PROGRAM,1,9);word(data,24,1);word(data,28,32);
        unsigned body[]={1234,4,0x686f7374,1001,1002,2,11,12};
        for(unsigned i=0;i<8;++i)word(data,32+4*i,body[i]);
        word(data,64,0);word(data,68,0);
        send_packet(data,72);drive();expect_reply(40,0,0,-1,0);
        size_t n=request(data,41,PROGRAM,1,0);word(data,24,99);send_packet(data,n);drive();expect_reply(41,1,1,2,0);
    } else if (!strcmp(scenario,"short-args")) {
        unsigned char data[2048];size_t n=request(data,32,PROGRAM,1,1);
        send_packet(data,n);drive();expect_reply(32,0,4,-1,0);exchange(1,33);
    } else if (!strcmp(scenario,"string")) {
        unsigned char data[2048];size_t n=request(data,44,PROGRAM,1,2);word(data,n,10);memcpy(data+n+4,"native-rpc",10);memset(data+n+14,0,2);
        send_packet(data,n+16);drive();n=response(data);CHECK(n==40 && readword(data,24)==10 && !memcmp(data+28,"native-rpc",10));
    } else if (!strcmp(scenario,"lifecycle")) {
        CHECK(reg(server,PROGRAM,1,handler,0));CHECK(!reg(server,PROGRAM,1,other_handler,0));exchange(11,50);
        unreg(PROGRAM,1);unsigned char data[2048];size_t n=request(data,51,PROGRAM,1,0);send_packet(data,n);drive();expect_reply(51,0,1,-1,0);
        CHECK(reg(server,PROGRAM,1,handler,0));exchange(1,52);
    } else if (!strcmp(scenario,"run-exit")) {
        pthread_t t;CHECK(!pthread_create(&t,NULL,run_client,NULL));run();CHECK(!pthread_join(t,NULL));CHECK(calls==1);
    } else if (!strcmp(scenario,"destroy-dispatch")) {
        int fd=server->fd;unsigned char data[2048];size_t n=request(data,53,PROGRAM,1,10);send_packet(data,n);drive();expect_reply(53,0,0,-1,0);
        CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);server=NULL;
    } else if (!strcmp(scenario,"callback-exit")) {
        unsigned char data[2048];size_t n=request(data,54,PROGRAM,1,12);send_packet(data,n);
        struct pollfd p={server->fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
        pthread_t t;void *result;CHECK(!pthread_create(&t,NULL,serve_thread,NULL));CHECK(!pthread_join(t,&result));CHECK(result==(void *)19 && cleaned==1);
        expect_reply(54,0,0,-1,0);exchange(1,56);
    } else if (!strcmp(scenario,"malformed") || !strcmp(scenario,"oversized")) {
        unsigned char data[2048];size_t n=request(data,60,PROGRAM,1,0);
        if (!strcmp(scenario,"malformed")) {
            send_packet(data,11);drive();struct pollfd p={client,POLLIN,0};CHECK(poll(&p,1,30)==0);
            n=request(data,61,PROGRAM,1,0);word(data,8,3);send_packet(data,n);drive();expect_reply(61,1,0,2,0);
            n=request(data,62,PROGRAM,1,0);word(data,28,401);send_packet(data,n);drive();CHECK(poll(&p,1,30)==0);
        } else { memset(data+n,0,512-n);send_packet(data,512);drive();struct pollfd p={client,POLLIN,0};CHECK(poll(&p,1,30)==0);CHECK(calls==0); }
        exchange(1,63);
    } else exchange(1,21);
    if(server) { int fd=server->fd;server->ops->destroy(server);CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF); }
    close(client);printf("PASS %s\n",scenario);return 0;
}
