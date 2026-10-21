#define _GNU_SOURCE
/* Published glibc LP64 Sun RPC layouts; libtirpc's SVCXPRT is NOT this ABI.
 * Wire expectations below are independent network-order words, not the
 * implementation's serializer. register-* uses the runner's exclusive loopback
 * portmapper peer; other cases require no privileged port. No external DNS. */
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
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
#include <sys/mman.h>
#include <unistd.h>

typedef struct { int flavor; char *base; unsigned length; } Auth;
typedef struct Xprt Xprt;
typedef int (*Proc)(void *, void *);
enum { XDR_ENCODE=0, XDR_DECODE=1, XDR_FREE=2 };
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
typedef struct { unsigned long xid; int direction; unsigned long rpcvers, program, version, procedure; Auth cred, verifier; } Call;
typedef union { max_align_t alignment; unsigned char bytes[400]; } Cooked;
typedef struct RpcClient RpcClient;
typedef struct {
    int (*call)(RpcClient *,unsigned long,Proc,void *,Proc,void *,struct timeval);
    void (*abort)(RpcClient *); void (*geterr)(RpcClient *,void *);
    int (*freeres)(RpcClient *,Proc,void *); void (*destroy)(RpcClient *);
    int (*control)(RpcClient *,int,void *);
} ClientOps;
struct RpcClient { void *auth; const ClientOps *ops; void *private_state; };
typedef struct {
    void (*next)(void *); int (*marshal)(void *,void *); int (*validate)(void *,void *);
    int (*refresh)(void *); void (*destroy)(void *);
} AuthOps;
typedef struct { Auth cred, verifier; unsigned char key[8]; const AuthOps *ops; void *private_state; } ClientAuth;
_Static_assert(sizeof(Xprt) == 336 && offsetof(Xprt, verifier) == 40, "glibc LP64 SVCXPRT");
_Static_assert(sizeof(Request) == 64 && sizeof(Auth) == 24, "glibc LP64 request/auth");
_Static_assert(sizeof(Call)==96 && offsetof(Call,cred)==48 && sizeof(SysAuth)==40,"glibc LP64 call/cooked credentials");
static Xprt *(*create)(int), *(*bufcreate)(int,unsigned,unsigned);
static Xprt *(*tcpcreate)(int,unsigned,unsigned), *(*fdcreate)(int,unsigned,unsigned);
static int (*reg)(Xprt *,unsigned long,unsigned long,void (*)(Request *,Xprt *),int);
static void (*unreg)(unsigned long,unsigned long), (*common)(int), (*getmask)(int), (*getset)(fd_set *), (*getpoll)(struct pollfd *,int);
static void (*run)(void), (*stop)(void);
static int (*sendreply)(Xprt *,Proc,void *), (*xu32)(void *,void *), (*xstr)(void *,char **,unsigned);
static void (*err_decode)(Xprt *), (*err_proc)(Xprt *), (*err_prog)(Xprt *), (*err_sys)(Xprt *), (*err_weak)(Xprt *), (*err_auth)(Xprt *,int), (*err_vers)(Xprt *,unsigned long,unsigned long);
static void *(*fdset_slot)(void), *(*poll_slot)(void), *(*count_slot)(void);
static int (*authenticate)(Request *,Call *);
static int (*simple_reg)(unsigned long,unsigned long,unsigned long,void *(*)(void *),Proc,Proc);
static Proc xvoid;
static int (*xopaque)(void *,void *,unsigned);
static RpcClient *(*udpclient)(struct sockaddr_in *,unsigned long,unsigned long,struct timeval,int *);
static ClientAuth *(*unixauth)(char *,unsigned,unsigned,int,unsigned *);
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
    LOAD(authenticate,"_authenticate"); LOAD(udpclient,"clntudp_create"); LOAD(unixauth,"authunix_create");
    LOAD(simple_reg,"registerrpc"); LOAD(xvoid,"xdr_void");
    LOAD(tcpcreate,"svctcp_create"); LOAD(fdcreate,"svcfd_create"); LOAD(xopaque,"xdr_opaque");
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
    } else if (r->procedure==15) {
        CHECK(r->cred.flavor==1 && r->cooked);
        SysAuth *a=r->cooked;
        CHECK(a->stamp && !strcmp(a->machine,"host") && a->uid==1001 && a->gid==1002 && a->count==2 && a->groups[0]==11 && a->groups[1]==12);
        unsigned result=a->uid+a->gid+a->groups[0]+a->groups[1];
        CHECK(sendreply(x,xu32,&result));
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
static size_t system_body(unsigned char *body,unsigned stamp,unsigned length,unsigned groups) {
    memset(body,0,400);word(body,0,stamp);word(body,4,length);
    for(unsigned i=0;i<length;++i) body[8+i]=(unsigned char)('a'+i%26);
    size_t at=8+((length+3)&~3u);
    word(body,at,UINT32_MAX);word(body,at+4,0x80000000);word(body,at+8,groups);
    for(unsigned i=0;i<groups;++i)word(body,at+12+4*i,i+100);
    return at+12+4*groups;
}
static void direct_authentication(void) {
    unsigned char body[400], verifier[]={1,2,3}, response_verifier[400];
    Cooked area; memset(&area,0xa5,sizeof(area));
    Xprt x={0};x.verifier=(Auth){23,(char *)response_verifier,19};
    Call message={.xid=9,.rpcvers=2,.program=PROGRAM,.version=1,.procedure=9,
        .cred={0,(char *)body,7},.verifier={99,(char *)verifier,3}};
    Request r={.program=77,.version=88,.procedure=99,.cred={-1,NULL,0},.cooked=&area,.x=&x};
    if (!strcmp(scenario,"authenticate-none")) {
        memset(body,0x5a,sizeof(body));
        CHECK(authenticate(&r,&message)==0);
        CHECK(r.cred.flavor==0 && r.cred.base==(char *)body && r.cred.length==7);
        CHECK(r.program==77 && r.version==88 && r.procedure==99 && r.cooked==&area && r.x==&x);
        CHECK(x.verifier.flavor==0 && x.verifier.length==0 && x.verifier.base==(char *)response_verifier);
        for(size_t i=0;i<sizeof(area.bytes);++i)CHECK(area.bytes[i]==0xa5);
    } else if (!strcmp(scenario,"authenticate-sys")) {
        unsigned lengths[]={0,1,3,4,255};
        for(unsigned i=0;i<5;++i) for(unsigned count=0;count<=16;count+=16) {
            unsigned stamp=i&1?0x80000001:UINT32_MAX;
            size_t length=system_body(body,stamp,lengths[i],count);
            message.cred=(Auth){1,(char *)body,(unsigned)length};
            CHECK(authenticate(&r,&message)==0);
            CHECK(r.cred.flavor==1 && r.cred.base==(char *)body && r.cred.length==length);
            SysAuth *a=r.cooked;CHECK(a==(void *)&area);
            CHECK(a->stamp==(unsigned long)stamp && a->uid==UINT32_MAX && a->gid==0x80000000 && a->count==count);
            CHECK(a->machine==(char *)area.bytes+sizeof(SysAuth));
            CHECK(a->groups==(unsigned *)(area.bytes+sizeof(SysAuth)+256));
            CHECK(a->machine[lengths[i]]==0);
            for(unsigned j=0;j<lengths[i];++j) CHECK(a->machine[j]==(char)('a'+j%26));
            for(unsigned j=0;j<count;++j)CHECK(a->groups[j]==100+j);
            CHECK(x.verifier.flavor==99 && x.verifier.base==(char *)verifier && x.verifier.length==3);
            memset(body,0,sizeof(body));
            CHECK(a->stamp==(unsigned long)stamp && strlen(a->machine)==lengths[i]);
            for(unsigned j=0;j<count;++j)CHECK(a->groups[j]==100+j);
        }
        message.verifier.length=0;x.verifier.base=(char *)response_verifier;
        message.cred.length=(unsigned)system_body(body,1234,3,2);
        CHECK(authenticate(&r,&message)==0 && x.verifier.flavor==0 && x.verifier.length==0 && x.verifier.base==(char *)response_verifier);
    } else if (!strcmp(scenario,"authenticate-reject")) {
        int flavors[]={-1,2,99,INT32_MAX};
        for(unsigned i=0;i<4;++i) {
            message.cred.flavor=flavors[i];
            CHECK(authenticate(&r,&message)==2 && r.cred.flavor==flavors[i]);
            CHECK(x.verifier.flavor==0 && x.verifier.length==0);
        }
    } else if (!strcmp(scenario,"authenticate-malformed")) {
        message.cred.flavor=1;
        /* GNU's inline decoder reads fields before its length check. The
           entire 400-byte storage remains readable even for short lengths. */
        unsigned length=(unsigned)system_body(body,1,3,2);
        for(unsigned n=0;n<length;n+=4) { message.cred.length=n;CHECK(authenticate(&r,&message)==1); }
        word(body,4,256);message.cred.length=400;CHECK(authenticate(&r,&message)==1);
        system_body(body,1,0,0);word(body,16,17);CHECK(authenticate(&r,&message)==1);
    } else {
        CHECK(!strcmp(scenario,"auth-bounds"));
        CHECK(authenticate(NULL,&message)==7 && authenticate(&r,NULL)==7);
        message.cred=(Auth){1,(char *)body,401};CHECK(authenticate(&r,&message)==1);
        message.cred.base=NULL;message.cred.length=20;CHECK(authenticate(&r,&message)==1);
        message.cred.base=(char *)body;
        unsigned length=(unsigned)system_body(body,1,3,2);
        for(unsigned n=0;n<length;++n) { message.cred.length=n;CHECK(authenticate(&r,&message)==1); }
        int hardened=getenv("FRANKENLIBC_MODE") && !strcmp(getenv("FRANKENLIBC_MODE"),"hardened");
        message.cred.length=length+4;CHECK(authenticate(&r,&message)==(hardened?1:0));
        message.cred.length=length;body[9]=0;CHECK(authenticate(&r,&message)==(hardened?1:0));
        system_body(body,1,3,2);r.cooked=NULL;CHECK(authenticate(&r,&message)==7);
        r.cooked=&area;message.verifier.length=401;CHECK(authenticate(&r,&message)==3);
        message.verifier.length=3;message.verifier.base=NULL;CHECK(authenticate(&r,&message)==3);
        message.verifier.length=0;
        long page=sysconf(_SC_PAGESIZE);CHECK(page>0);
        void *inaccessible=mmap(NULL,(size_t)page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        CHECK(inaccessible!=MAP_FAILED);message.cred.base=inaccessible;
        CHECK(authenticate(&r,&message)==1);CHECK(!munmap(inaccessible,(size_t)page));
        message.cred.flavor=0;r.x=NULL;CHECK(authenticate(&r,&message)==7);
    }
}
static void *authenticated_client(void *unused) {
    (void)unused;
    struct sockaddr_in dest={.sin_family=AF_INET,.sin_port=htons(server->port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    int fd=-1;RpcClient *c=udpclient(&dest,PROGRAM,1,(struct timeval){1,0},&fd);CHECK(c && fd>=0);
    unsigned groups[]={11,12};ClientAuth *a=unixauth("host",1001,1002,2,groups);CHECK(a && a->ops);
    c->auth=a;unsigned result=0;
    CHECK(c->ops->call(c,15,void_proc,NULL,xu32,&result,(struct timeval){3,0})==0 && result==2026);
    c->ops->destroy(c);a->ops->destroy(a);
    CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);return NULL;
}
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
static unsigned simple_calls, simple_frees;
static int counted_u32(void *x,void *p) {
    if (*(int *)x==XDR_FREE) ++simple_frees;
    return xu32(x,p);
}
static int rejecting_u32(void *x,void *p) {
    int ok=counted_u32(x,p);
    return *(int *)x==XDR_DECODE && ok && *(unsigned *)p==99 ? 0 : ok;
}
static int counted_string(void *x,void *p) {
    if (*(int *)x==XDR_FREE) ++simple_frees;
    return string_proc(x,p);
}
static int partial_string(void *x,void *p) {
    int ok=counted_string(x,p);
    if (*(int *)x==XDR_DECODE && ok) { unsigned missing=0;return xu32(x,&missing); }
    return ok;
}
static void *simple_add(void *p) { ++simple_calls;*(unsigned *)p+=7;return p; }
static void *simple_replace(void *p) { ++simple_calls;*(unsigned *)p+=9;return p; }
static void *simple_reenter(void *p) {
    CHECK(simple_reg(PROGRAM,1,1,simple_replace,counted_u32,xu32)==0);
    return simple_add(p);
}
static int simple_encode_failure(void *x,void *p) { (void)x;(void)p;return 0; }
static void *simple_text(void *p) { ++simple_calls;CHECK(!strcmp(*(char **)p,"native-rpc"));return p; }
static void *simple_null(void *p) { (void)p;++simple_calls;return NULL; }
static void *simple_exit(void *p) { (void)p;++simple_calls;pthread_exit((void *)27); }
static int simple_fd(void) {
    fd_set bits=*(fd_set *)fdset_slot();int fd=-1;
    for(int i=0;i<FD_SETSIZE;++i) if(FD_ISSET(i,&bits)) { CHECK(fd==-1);fd=i; }
    CHECK(fd>=0);return fd;
}
static void mapping_lookup(unsigned expected,unsigned protocol) {
    int fd=socket(AF_INET,SOCK_DGRAM,0);CHECK(fd>=0);
    struct sockaddr_in mapper={.sin_family=AF_INET,.sin_port=htons(111),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    unsigned char packet[2048];request(packet,0x1234,100000,2,3);
    word(packet,40,PROGRAM);word(packet,44,1);word(packet,48,protocol);word(packet,52,0);
    CHECK(sendto(fd,packet,56,0,(void *)&mapper,sizeof(mapper))==56);
    struct pollfd p={fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
    CHECK(recv(fd,packet,sizeof(packet),0)==28);
    CHECK(readword(packet,0)==0x1234 && readword(packet,4)==1 && readword(packet,8)==0 && readword(packet,12)==0 && readword(packet,16)==0 && readword(packet,20)==0 && readword(packet,24)==expected);
    close(fd);
}
static void simple_services(void) {
    if (!strcmp(scenario,"register-zero")) {
        CHECK(simple_reg(PROGRAM,1,0,simple_add,counted_u32,xu32)==-1);return;
    }
    if (!strcmp(scenario,"register-invalid")) {
        CHECK(simple_reg(PROGRAM,1,1,NULL,counted_u32,xu32)==-1);
        CHECK(simple_reg(PROGRAM,1,1,simple_add,NULL,xu32)==-1);
        CHECK(simple_reg(PROGRAM,1,1,simple_add,counted_u32,NULL)==-1);
        CHECK(simple_reg(PROGRAM,1,1UL<<32,simple_add,counted_u32,xu32)==-1);
        fd_set bits=*(fd_set *)fdset_slot();for(int i=0;i<FD_SETSIZE;++i)CHECK(!FD_ISSET(i,&bits));return;
    }
    if (!strcmp(scenario,"register-denied"))
        CHECK(simple_reg(PROGRAM+1,1,1,simple_add,counted_u32,xu32)==-1);
    Proc input=counted_u32, output=xu32;void *(*callback)(void *)=simple_add;
    if (!strcmp(scenario,"register-string")) { input=counted_string;output=string_proc;callback=simple_text; }
    if (!strcmp(scenario,"register-partial")) { input=partial_string;callback=simple_add; }
    if (!strcmp(scenario,"register-void")) { input=xvoid;output=xvoid;callback=simple_null; }
    if (!strcmp(scenario,"register-no-reply")) callback=simple_null;
    if (!strcmp(scenario,"register-callback-exit")) callback=simple_exit;
    if (!strcmp(scenario,"register-decoder-error")) input=rejecting_u32;
    if (!strcmp(scenario,"register-reentry")) callback=simple_reenter;
    if (!strcmp(scenario,"register-encode-error")) output=simple_encode_failure;
    CHECK(simple_reg(PROGRAM,1,1,callback,input,output)==0);
    Xprt address={.fd=simple_fd()};server=&address;
    struct sockaddr_in a;socklen_t size=sizeof(a);CHECK(!getsockname(address.fd,(void *)&a,&size));address.port=ntohs(a.sin_port);CHECK(address.port);
    mapping_lookup(address.port,17);
    client=socket(AF_INET,SOCK_DGRAM,0);CHECK(client>=0);
    unsigned char data[2048];size_t n;
    n=request(data,81,PROGRAM,1,0);send_packet(data,n);drive();expect_reply(81,0,0,-1,0);CHECK(!simple_calls);
    if (!strcmp(scenario,"register-unknown")) {
        n=request(data,96,PROGRAM,1,99);send_packet(data,n);drive();CHECK(0);
    }
    if (!strcmp(scenario,"register-string") || !strcmp(scenario,"register-partial")) {
        n=request(data,82,PROGRAM,1,1);word(data,n,10);memcpy(data+n+4,"native-rpc",10);memset(data+n+14,0,2);
        send_packet(data,n+16);drive();
        if (!strcmp(scenario,"register-partial")) { expect_reply(82,0,4,-1,0);CHECK(!simple_calls && simple_frees==1); }
        else { n=response(data);CHECK(n==40 && readword(data,24)==10 && !memcmp(data+28,"native-rpc",10));CHECK(simple_calls==1 && simple_frees==1); }
    } else if (!strcmp(scenario,"register-decode") || !strcmp(scenario,"register-decoder-error")) {
        n=request(data,83,PROGRAM,1,1);
        if (!strcmp(scenario,"register-decoder-error")) { word(data,n,99);n+=4; }
        send_packet(data,n);drive();expect_reply(83,0,4,-1,0);CHECK(!simple_calls);
        exchange(1,84);CHECK(simple_calls==1);
    } else if (!strcmp(scenario,"register-no-reply")) {
        n=request(data,85,PROGRAM,1,1);word(data,n,35);send_packet(data,n+4);drive();
        struct pollfd p={client,POLLIN,0};CHECK(poll(&p,1,50)==0 && simple_calls==1);
        if(getenv("FRANKENLIBC_TEST_LIBRARY"))CHECK(simple_frees==1);
    } else if (!strcmp(scenario,"register-void")) {
        n=request(data,86,PROGRAM,1,1);send_packet(data,n);drive();expect_reply(86,0,0,-1,0);CHECK(simple_calls==1);
    } else if (!strcmp(scenario,"register-callback-exit")) {
        n=request(data,87,PROGRAM,1,1);word(data,n,35);send_packet(data,n+4);
        struct pollfd p={server->fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
        pthread_t t;void *result;CHECK(!pthread_create(&t,NULL,serve_thread,NULL));CHECK(!pthread_join(t,&result));
        CHECK(result==(void *)27 && simple_calls==1 && simple_frees==1);
        CHECK(simple_reg(PROGRAM,1,1,simple_add,counted_u32,xu32)==0);exchange(1,88);CHECK(simple_calls==2 && simple_frees==2);
    } else {
        exchange(1,89);CHECK(simple_calls==1 && simple_frees==1);
        if (!strcmp(scenario,"register-reentry")) {
            n=request(data,97,PROGRAM,1,1);word(data,n,35);send_packet(data,n+4);drive();expect_reply(97,0,0,0,44);
            CHECK(simple_calls==2 && simple_frees==2);
        }
        if (!strcmp(scenario,"register-multi")) {
            CHECK(simple_reg(PROGRAM,2,1,simple_replace,counted_u32,xu32)==0);
            CHECK(simple_reg(PROGRAM,1,2,simple_add,counted_u32,xu32)==0 && simple_fd()==address.fd);
            for(unsigned version=1;version<=2;++version) {
                n=request(data,90+version,PROGRAM,version,1);word(data,n,35);send_packet(data,n+4);drive();expect_reply(90+version,0,0,0,44);
            }
            n=request(data,93,PROGRAM,1,2);word(data,n,35);send_packet(data,n+4);drive();expect_reply(93,0,0,0,42);
            CHECK(simple_calls==4 && simple_frees==4);unreg(PROGRAM,2);
        }
    }
    unreg(PROGRAM,1);
    mapping_lookup(0,17);
    n=request(data,94,PROGRAM,1,0);send_packet(data,n);drive();expect_reply(94,0,1,-1,0);
    CHECK(simple_reg(PROGRAM,1,3,simple_add,counted_u32,xu32)==0 && simple_fd()==address.fd);
    n=request(data,95,PROGRAM,1,3);word(data,n,35);send_packet(data,n+4);drive();expect_reply(95,0,0,0,42);
    unreg(PROGRAM,1);CHECK(fcntl(address.fd,F_GETFD)>=0);close(client);server=NULL;
}

static Xprt *tcp_listener, *tcp_connection;
static int tcp_fd;
static unsigned tcp_encodes, tcp_stop_count;
static unsigned char tcp_bulk[4*1024*1024];
static size_t tcp_bulk_length;
static atomic_int tcp_reader_done;
static int tcp_bulk_proc(void *x,void *p) {
    (void)p;if(*(int *)x==XDR_ENCODE)++tcp_encodes;
    return xopaque(x,tcp_bulk,(unsigned)tcp_bulk_length);
}
static int tcp_bad_encoder(void *x,void *p) { (void)x;(void)p;++tcp_encodes;return 0; }
static void tcp_handler(Request *r,Xprt *x) {
    tcp_connection=x;
    if (r->procedure==16) {
        ++calls;CHECK(x->ops->getargs(x,tcp_bulk_proc,NULL));
        for(size_t i=0;i<tcp_bulk_length;++i)CHECK(tcp_bulk[i]==(unsigned char)(i*31+7));
        CHECK(sendreply(x,tcp_bulk_proc,NULL));CHECK(x->ops->freeargs(x,tcp_bulk_proc,NULL));
    } else if (r->procedure==17) {
        ++calls;CHECK(!sendreply(x,tcp_bad_encoder,NULL));err_sys(x);
    } else if (r->procedure==18) {
        ++calls;CHECK(sendreply(x,tcp_bulk_proc,NULL));
    } else {
        handler(r,x);
        if(r->procedure==13)tcp_stop_count=calls;
        if(!strcmp(scenario,"tcp-client") && calls==2)stop();
    }
}
static void tcp_write(int fd,const void *bytes,size_t length) {
    const unsigned char *p=bytes;
    while(length) { ssize_t n=send(fd,p,length,MSG_NOSIGNAL);CHECK(n>0);p+=n;length-=(size_t)n; }
}
static void tcp_read(int fd,void *bytes,size_t length) {
    unsigned char *p=bytes;
    while(length) { struct pollfd q={fd,POLLIN,0};CHECK(poll(&q,1,2000)==1);ssize_t n=recv(fd,p,length,0);CHECK(n>0);p+=n;length-=(size_t)n; }
}
static void tcp_fragment(int fd,const void *bytes,size_t length,int last) {
    uint32_t marker=htonl((uint32_t)length|(last?0x80000000u:0));
    tcp_write(fd,&marker,4);if(length)tcp_write(fd,bytes,length);
}
static size_t tcp_record(int fd,unsigned char *bytes,size_t capacity) {
    size_t used=0;unsigned fragments=0;
    for(;;) {
        uint32_t marker;tcp_read(fd,&marker,4);marker=ntohl(marker);
        size_t n=marker&0x7fffffffu;CHECK(n<=capacity-used && ++fragments<8192);
        tcp_read(fd,bytes+used,n);used+=n;if(marker&0x80000000u)return used;
    }
}
static void tcp_expect(int fd,unsigned xid,unsigned status,int value) {
    unsigned char bytes[128];size_t n=tcp_record(fd,bytes,sizeof(bytes));
    CHECK(n>=24 && readword(bytes,0)==xid && readword(bytes,4)==1 && readword(bytes,8)==0);
    CHECK(readword(bytes,12)==0 && readword(bytes,16)==0 && readword(bytes,20)==status);
    if(value>=0){CHECK(n==(status==2?32u:28u) && readword(bytes,24)==(unsigned)value);if(status==2)CHECK(readword(bytes,28)==(unsigned)value);}
}
static size_t tcp_call(unsigned char *bytes,unsigned xid,unsigned procedure) {
    size_t n=request(bytes,xid,PROGRAM,1,procedure);
    if(procedure==1){word(bytes,n,35);n+=4;}return n;
}
static void tcp_drive(int fd) {
    struct pollfd p={fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
    if(!strcmp(scenario,"tcp-poll")) {
        int count=*(int *)count_slot();struct pollfd *fds=*(struct pollfd **)poll_slot();
        int ready=poll(fds,(nfds_t)count,1000);CHECK(ready>0);getpoll(fds,ready);
    } else if(!strcmp(scenario,"tcp-fdset")) {
        fd_set set;FD_ZERO(&set);FD_SET(fd,&set);getset(&set);
    } else common(fd);
}
static int tcp_accepted(int listener,int previous) {
    tcp_drive(listener);fd_set set=*(fd_set *)fdset_slot();int result=-1;
    for(int i=0;i<FD_SETSIZE;++i)if(i!=listener && i!=previous && FD_ISSET(i,&set)) {CHECK(result==-1);result=i;}
    CHECK(result>=0);return result;
}
static int tcp_connect(unsigned short port) {
    int fd=socket(AF_INET,SOCK_STREAM,0);CHECK(fd>=0);
    int one=1;CHECK(!setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one)));
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(!connect(fd,(void *)&a,sizeof(a)));return fd;
}
static void tcp_exchange(unsigned xid,unsigned procedure) {
    unsigned char bytes[128];size_t n=tcp_call(bytes,xid,procedure);
    tcp_fragment(client,bytes,n,1);tcp_drive(tcp_fd);tcp_expect(client,xid,0,procedure==1?42:-1);
}
static void *tcp_reader(void *unused) {
    (void)unused;size_t capacity=tcp_bulk_length+24;unsigned char *bytes=malloc(capacity);CHECK(bytes);
    CHECK(tcp_record(client,bytes,capacity)==capacity && readword(bytes,20)==0);
    for(size_t i=0;i<tcp_bulk_length;++i)CHECK(bytes[24+i]==(unsigned char)(i*31+7));
    free(bytes);atomic_store_explicit(&tcp_reader_done,1,memory_order_release);return NULL;
}
static void *tcp_serve(void *p) { common(*(int *)p);return NULL; }
static void *tcp_run_client(void *unused) {
    (void)unused;
    if(!strcmp(scenario,"tcp-client")) {
        RpcClient *(*constructor)(struct sockaddr_in *,unsigned long,unsigned long,int *,unsigned,unsigned);
        LOAD(constructor,"clnttcp_create");
        struct sockaddr_in dest={.sin_family=AF_INET,.sin_port=htons(tcp_listener->port),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
        int fd=-1;RpcClient *c=constructor(&dest,PROGRAM,1,&fd,128,128);CHECK(c && fd>=0);
        unsigned groups[]={11,12};ClientAuth *a=unixauth("host",1001,1002,2,groups);CHECK(a);c->auth=a;
        for(unsigned i=0;i<2;++i){unsigned result=0;CHECK(c->ops->call(c,15,xvoid,NULL,xu32,&result,(struct timeval){3,0})==0 && result==2026);}
        c->ops->destroy(c);a->ops->destroy(a);CHECK(fcntl(fd,F_GETFD)==-1);return NULL;
    }
    unsigned char bytes[128];size_t n=tcp_call(bytes,201,1);tcp_fragment(client,bytes,n,1);tcp_expect(client,201,0,42);
    n=tcp_call(bytes,202,13);tcp_fragment(client,bytes,n,1);tcp_expect(client,202,0,-1);return NULL;
}
static void tcp_services(void) {
    if(!strcmp(scenario,"tcp-invalid")) {
        CHECK(!fdcreate(-1,0,0) && !tcpcreate(-2,0,0));
        int d=socket(AF_INET,SOCK_DGRAM,0);CHECK(d>=0);
        CHECK(!fdcreate(d,0,0) && !tcpcreate(d,0,0) && fcntl(d,F_GETFD)>=0);close(d);
        d=socket(AF_INET,SOCK_STREAM,0);CHECK(d>=0);CHECK(!fdcreate(d,0,0) && fcntl(d,F_GETFD)>=0);close(d);return;
    }
    int connected=!strcmp(scenario,"tcp-fd") || !strcmp(scenario,"tcp-unix-fd") || !strcmp(scenario,"tcp-direct") || !strcmp(scenario,"tcp-backpressure");
    if(connected) {
        int service_fd;
        if(!strcmp(scenario,"tcp-unix-fd") || !strcmp(scenario,"tcp-backpressure")) {
            int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));service_fd=pair[0];client=pair[1];
        } else {
            int listener=socket(AF_INET,SOCK_STREAM,0);CHECK(listener>=0);
            struct sockaddr_in a={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};socklen_t length=sizeof(a);
            CHECK(!bind(listener,(void *)&a,length) && !listen(listener,4) && !getsockname(listener,(void *)&a,&length));
            client=tcp_connect(ntohs(a.sin_port));service_fd=accept(listener,NULL,NULL);CHECK(service_fd>=0);close(listener);
        }
        int flags=fcntl(service_fd,F_GETFL);tcp_connection=fdcreate(service_fd,128,128);
        CHECK(tcp_connection && tcp_connection->fd==service_fd && !tcp_connection->port && fcntl(service_fd,F_GETFL)==flags);
        tcp_fd=service_fd;CHECK(reg(tcp_connection,PROGRAM,1,tcp_handler,0));
    } else {
        int supplied=-1;
        if(!strcmp(scenario,"tcp-supplied"))supplied=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK,0);
        tcp_listener=tcpcreate(supplied,128,128);CHECK(tcp_listener && tcp_listener->port && tcp_listener->ops && tcp_listener->fd>=0);
        if(supplied>=0)CHECK(tcp_listener->fd==supplied);
        CHECK(reg(tcp_listener,PROGRAM,1,tcp_handler,!strcmp(scenario,"tcp-publish")?IPPROTO_TCP:0));
        if(!strcmp(scenario,"tcp-publish"))mapping_lookup(tcp_listener->port,6);
        if(!strcmp(scenario,"tcp-client")) {
            pthread_t t;CHECK(!pthread_create(&t,NULL,tcp_run_client,NULL));run();CHECK(!pthread_join(t,NULL) && calls==2);
            CHECK(tcp_connection);tcp_fd=tcp_connection->fd;client=-1;
        } else { client=tcp_connect(tcp_listener->port);tcp_fd=tcp_accepted(tcp_listener->fd,-1); }
    }
    int retired=0;
    if(!strcmp(scenario,"tcp-client")) { /* real native CLIENT exchange completed above */ }
    else if(!strcmp(scenario,"tcp-direct")) {
        unsigned char bytes[128];size_t n=tcp_call(bytes,203,1);tcp_fragment(client,bytes,n,1);
        struct pollfd p={tcp_fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
        Call msg={0};char cred[400],verifier[400];msg.cred.base=cred;msg.verifier.base=verifier;
        CHECK(tcp_connection->ops->recv(tcp_connection,&msg) && msg.xid==203 && msg.procedure==1);
        unsigned value=0;CHECK(tcp_connection->ops->getargs(tcp_connection,xu32,&value) && value==35);value+=7;
        unsigned long reply[12]={0};*(int *)((char *)reply+8)=1;*(void **)((char *)reply+56)=&value;*(Proc *)((char *)reply+64)=xu32;
        CHECK(tcp_connection->ops->reply(tcp_connection,reply));tcp_expect(client,203,0,42);CHECK(tcp_connection->ops->freeargs(tcp_connection,xu32,&value));
    } else if(!strcmp(scenario,"tcp-fragments") || !strcmp(scenario,"tcp-empty-fragment") || !strcmp(scenario,"tcp-empty-final")) {
        unsigned char bytes[128];size_t n=tcp_call(bytes,204,1);
        tcp_fragment(client,bytes,2,0);
        if(!strcmp(scenario,"tcp-empty-fragment"))tcp_fragment(client,NULL,0,0);
        int final=!strcmp(scenario,"tcp-empty-final");
        tcp_fragment(client,bytes+2,n-2,!final);if(final)tcp_fragment(client,NULL,0,1);
        tcp_drive(tcp_fd);tcp_expect(client,204,0,42);CHECK(calls==1);
    } else if(!strcmp(scenario,"tcp-partial")) {
        unsigned char bytes[128];size_t n=tcp_call(bytes+4,205,1);word(bytes,0,0x80000000u|(unsigned)n);
        for(size_t i=0;i<n+3;++i){tcp_write(client,bytes+i,1);common(tcp_fd);CHECK(!calls);}
        tcp_write(client,bytes+n+3,1);tcp_drive(tcp_fd);tcp_expect(client,205,0,42);CHECK(calls==1);
    } else if(!strcmp(scenario,"tcp-pipeline")) {
        for(unsigned i=0;i<3;++i){unsigned char bytes[128];size_t n=tcp_call(bytes,206+i,1);tcp_fragment(client,bytes,n,1);}
        tcp_drive(tcp_fd);for(unsigned i=0;i<3;++i)tcp_expect(client,206+i,0,42);CHECK(calls==3);
    } else if(!strcmp(scenario,"tcp-string")) {
        unsigned char bytes[128];size_t n=tcp_call(bytes,210,2);word(bytes,n,10);memcpy(bytes+n+4,"native-rpc",10);memset(bytes+n+14,0,2);
        tcp_fragment(client,bytes,n+16,1);tcp_drive(tcp_fd);n=tcp_record(client,bytes,sizeof(bytes));CHECK(n==40 && readword(bytes,24)==10 && !memcmp(bytes+28,"native-rpc",10));
    } else if(!strcmp(scenario,"tcp-large")) {
        tcp_bulk_length=256*1024;size_t n=tcp_bulk_length+40;unsigned char *bytes=malloc(n);CHECK(bytes);request(bytes,211,PROGRAM,1,16);
        for(size_t i=0;i<tcp_bulk_length;++i)bytes[40+i]=(unsigned char)(i*31+7);
        tcp_fragment(client,bytes,57,0);tcp_fragment(client,bytes+57,n-57,1);
        /* Bounded native turns need not consume a large record in one call. */
        for(unsigned i=0;i<100 && !calls;++i)tcp_drive(tcp_fd);
        CHECK(calls==1 && tcp_encodes==1);CHECK(tcp_record(client,bytes,n)==tcp_bulk_length+24);
        for(size_t i=0;i<tcp_bulk_length;++i)CHECK(bytes[24+i]==(unsigned char)(i*31+7));
        free(bytes);
    } else if(!strcmp(scenario,"tcp-errors")) {
        unsigned char bytes[128];size_t n=request(bytes,212,PROGRAM+1,1,0);tcp_fragment(client,bytes,n,1);tcp_drive(tcp_fd);tcp_expect(client,212,1,-1);
        n=request(bytes,213,PROGRAM,2,0);tcp_fragment(client,bytes,n,1);tcp_drive(tcp_fd);tcp_expect(client,213,2,1);
        n=tcp_call(bytes,214,3);tcp_fragment(client,bytes,n,1);tcp_drive(tcp_fd);tcp_expect(client,214,3,-1);
    } else if(!strcmp(scenario,"tcp-auth")) {
        unsigned char bytes[128];request(bytes,215,PROGRAM,1,9);word(bytes,24,1);word(bytes,28,32);
        unsigned body[]={1234,4,0x686f7374,1001,1002,2,11,12};for(unsigned i=0;i<8;++i)word(bytes,32+4*i,body[i]);word(bytes,64,0);word(bytes,68,0);
        tcp_fragment(client,bytes,72,1);tcp_drive(tcp_fd);tcp_expect(client,215,0,-1);
    } else if(!strcmp(scenario,"tcp-run")) {
        pthread_t t;CHECK(!pthread_create(&t,NULL,tcp_run_client,NULL));run();CHECK(!pthread_join(t,NULL) && calls==2);
    } else if(!strcmp(scenario,"tcp-fairness")) {
        int other=tcp_connect(tcp_listener->port);int second=tcp_accepted(tcp_listener->fd,tcp_fd);
        unsigned char bytes[128];
        for(unsigned i=0;i<40;++i){size_t n=tcp_call(bytes,300+i,1);tcp_fragment(client,bytes,n,1);}
        size_t n=tcp_call(bytes,340,13);tcp_fragment(other,bytes,n,1);run();
        CHECK(tcp_stop_count<=33);tcp_expect(other,340,0,-1);
        for(unsigned i=0;i<100 && calls<41;++i)common(tcp_fd);
        CHECK(calls==41);for(unsigned i=0;i<40;++i)tcp_expect(client,300+i,0,42);
        close(other);common(second);CHECK(fcntl(second,F_GETFD)==-1);
    } else if(!strcmp(scenario,"tcp-backpressure")) {
        int small=4096;CHECK(!setsockopt(tcp_fd,SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));
        tcp_bulk_length=sizeof(tcp_bulk);for(size_t i=0;i<tcp_bulk_length;++i)tcp_bulk[i]=(unsigned char)(i*31+7);
        unsigned char bytes[128];size_t n=tcp_call(bytes,216,18);tcp_fragment(client,bytes,n,1);tcp_drive(tcp_fd);CHECK(calls==1 && tcp_encodes==1);
        int count=*(int *)count_slot();struct pollfd *fds=*(struct pollfd **)poll_slot();int writing=0;
        for(int i=0;i<count;++i)if(fds[i].fd==tcp_fd)writing=!!(fds[i].events&POLLOUT);
        CHECK(writing);
        pthread_t t;CHECK(!pthread_create(&t,NULL,tcp_reader,NULL));
        for(unsigned i=0;i<2000 && !atomic_load_explicit(&tcp_reader_done,memory_order_acquire);++i){int ready=poll(fds,(nfds_t)count,5);CHECK(ready>=0);if(ready)getpoll(fds,ready);}
        CHECK(atomic_load_explicit(&tcp_reader_done,memory_order_acquire) && !pthread_join(t,NULL));CHECK(calls==1 && tcp_encodes==1);tcp_exchange(217,1);
    } else if(!strcmp(scenario,"tcp-child")) {
        tcp_exchange(218,1);CHECK(tcp_connection && tcp_listener);int fd=tcp_listener->fd;
        tcp_listener->ops->destroy(tcp_listener);tcp_listener=NULL;CHECK(fcntl(fd,F_GETFD)==-1);tcp_exchange(219,1);
    } else if(!strcmp(scenario,"tcp-destroy")) {
        tcp_exchange(220,10);CHECK(fcntl(tcp_fd,F_GETFD)==-1);retired=1;tcp_connection=NULL;
    } else if(!strcmp(scenario,"tcp-callback-exit")) {
        unsigned char bytes[128];size_t n=tcp_call(bytes,221,12);tcp_fragment(client,bytes,n,1);
        struct pollfd p={tcp_fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);pthread_t t;void *result;
        CHECK(!pthread_create(&t,NULL,tcp_serve,&tcp_fd));CHECK(!pthread_join(t,&result));CHECK(result==(void *)19 && cleaned==1);
        tcp_expect(client,221,0,-1);tcp_exchange(222,1);
    } else if(!strcmp(scenario,"tcp-encode-failure")) {
        unsigned char bytes[128];size_t n=tcp_call(bytes,223,17);tcp_fragment(client,bytes,n,1);tcp_drive(tcp_fd);tcp_expect(client,223,5,-1);CHECK(tcp_encodes==1);tcp_exchange(224,1);
    } else if(!strcmp(scenario,"tcp-malformed") || !strcmp(scenario,"tcp-limit") || !strcmp(scenario,"tcp-truncated") || !strcmp(scenario,"tcp-fragment-limit")) {
        unsigned char bytes[128]={0};
        if(!strcmp(scenario,"tcp-malformed"))tcp_fragment(client,bytes,11,1);
        else if(!strcmp(scenario,"tcp-limit")){word(bytes,0,0x81000001u);tcp_write(client,bytes,4);}
        else if(!strcmp(scenario,"tcp-truncated")){tcp_write(client,bytes,2);CHECK(!shutdown(client,SHUT_WR));}
        else for(unsigned i=0;i<4097;++i)tcp_fragment(client,NULL,0,0);
        for(unsigned i=0;i<100 && fcntl(tcp_fd,F_GETFD)>=0;++i)tcp_drive(tcp_fd);
        CHECK(!calls && fcntl(tcp_fd,F_GETFD)==-1);retired=1;tcp_connection=NULL;
    } else { tcp_exchange(225,1);tcp_exchange(226,1);CHECK(calls==2); }
    if(client>=0)close(client);
    if(!retired){common(tcp_fd);CHECK(fcntl(tcp_fd,F_GETFD)==-1);}
    if(tcp_listener){int fd=tcp_listener->fd;tcp_listener->ops->destroy(tcp_listener);CHECK(fcntl(fd,F_GETFD)==-1);tcp_listener=NULL;}
    unreg(PROGRAM,1);
    if(!strcmp(scenario,"tcp-publish"))mapping_lookup(0,6);
}
int main(int argc,char **argv) {
    CHECK(argc==2);scenario=argv[1];load();
    if (!strncmp(scenario,"tcp-",4)) { tcp_services();printf("PASS %s\n",scenario);return 0; }
    if (!strncmp(scenario,"register-",9)) { simple_services();printf("PASS %s\n",scenario);return 0; }
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
    if (!strncmp(scenario,"authenticate-",13) || !strcmp(scenario,"auth-bounds")) direct_authentication();
    else if (!strcmp(scenario,"auth-client")) {
        pthread_t t;CHECK(!pthread_create(&t,NULL,authenticated_client,NULL));drive();CHECK(!pthread_join(t,NULL));CHECK(calls==1);
    } else if (!strcmp(scenario,"transport")) transport();
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
    } else if (!strcmp(scenario,"auth-none-opaque") || !strcmp(scenario,"auth-verifier")) {
        unsigned char data[2048];request(data,42,PROGRAM,1,!strcmp(scenario,"auth-verifier")?9:0);
        size_t at;
        if (!strcmp(scenario,"auth-verifier")) {
            word(data,24,1);word(data,28,32);
            unsigned body[]={1234,4,0x686f7374,1001,1002,2,11,12};
            for(unsigned i=0;i<8;++i)word(data,32+4*i,body[i]);
            at=64;
        } else { word(data,28,3);word(data,32,0x01020300);at=36; }
        word(data,at,99);word(data,at+4,3);word(data,at+8,0x04050600);
        send_packet(data,at+12);drive();size_t n=response(data);
        CHECK(readword(data,0)==42 && readword(data,4)==1 && readword(data,8)==0);
        if (!strcmp(scenario,"auth-verifier")) CHECK(n==28 && readword(data,12)==99 && readword(data,16)==3 && readword(data,20)==0x04050600 && readword(data,24)==0);
        else CHECK(n==24 && readword(data,12)==0 && readword(data,16)==0 && readword(data,20)==0);
        exchange(1,43); /* verifier must reset on the next AUTH_NONE request */
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
