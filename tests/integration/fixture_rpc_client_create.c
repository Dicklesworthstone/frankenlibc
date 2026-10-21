#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __cplusplus
#include <pthread.h>
#define STATIC_ASSERT static_assert
#else
#define STATIC_ASSERT _Static_assert
#endif

/* glibc's public LP64 Sun RPC client prefix. Do not substitute libtirpc's
   SVC transport layout. A wire peer below is independent of this ABI. */
typedef int (*Xdr)(void *, void *);
typedef struct Client Client;
typedef struct Ops {
    int (*call)(Client *, unsigned long, Xdr, void *, Xdr, void *, struct timeval);
    void (*abort)(Client *);
    void (*geterr)(Client *, void *);
    int (*freeres)(Client *, Xdr, void *);
    void (*destroy)(Client *);
    int (*control)(Client *, int, void *);
} Ops;
struct Client { void *auth; const Ops *ops; void *private_state; };
STATIC_ASSERT(sizeof(Client)==24 && offsetof(Client,ops)==8,"glibc LP64 CLIENT");
STATIC_ASSERT(sizeof(Ops)==48,"glibc LP64 CLIENT operations");
typedef Client *(*Create)(const char *, unsigned long, unsigned long, const char *);
typedef int (*CallRpc)(const char *, unsigned long, unsigned long, unsigned long, Xdr, void *, Xdr, void *);
static Create create;
static CallRpc call_rpc;
static Xdr xdr_uint;
static void *(*create_error)(void);
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while(0)
static void wrong_provider(void) {
    static const char message[]="WRONG RPC PROVIDER\n";
    if (write(STDERR_FILENO,message,sizeof(message)-1)!=(ssize_t)(sizeof(message)-1)) _Exit(114);
    _Exit(113);
}
static void *symbol(const char *name) {
    const char *candidate = getenv("FRANKENLIBC_TEST_LIBRARY");
    void *p;
    if (candidate) {
        if (getenv("RPC_TEST_FORCE_HOST")) {
            void *host=dlopen("libc.so.6",RTLD_NOW|RTLD_LOCAL); CHECK(host);
            p=dlvsym(host,name,"GLIBC_2.2.5");
        } else p = dlsym(RTLD_DEFAULT,name);
        Dl_info info; struct stat a,b;
        if (!p || !dladdr(p,&info) || !info.dli_fname || stat(candidate,&a)
            || stat(info.dli_fname,&b) || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino)
            wrong_provider();
    } else {
        void *host=dlopen("libc.so.6",RTLD_NOW|RTLD_LOCAL); CHECK(host);
        p=dlvsym(host,name,"GLIBC_2.2.5"); CHECK(p);
    }
    return p;
}
static unsigned long program=0x34567001UL;
static int fail_xdr(void *x,void *data) { (void)x;(void)data;return 0; }
static int reenter_xdr(void *x,void *data) {
    uint32_t in=19,out=0;
    CHECK(call_rpc("127.0.0.1",program,1,7,xdr_uint,&in,xdr_uint,&out)==0);
    CHECK(out==(in^0x55aa55aaU));
    return xdr_uint(x,data);
}
static int descriptor_count(void) {
    int count=0; DIR *directory=opendir("/proc/self/fd"); CHECK(directory);
    struct dirent *entry;
    while ((entry=readdir(directory))!=NULL) if(entry->d_name[0]!='.') count++;
    CHECK(closedir(directory)==0);
    return count;
}
static void destroy_owned(Client *client) {
    int fd=-1; CHECK(client->ops->control(client,6,&fd)); CHECK(fd>=0);
    client->ops->destroy(client); errno=0; CHECK(fcntl(fd,F_GETFD)==-1&&errno==EBADF);
}
#ifdef __cplusplus
static const char *scenario;
static int destructors;
struct Marker { ~Marker() { ++destructors; } };
struct CodecException {};
static void interrupt_now(void) {
    if (strstr(scenario,"exit")) pthread_exit((void *)19);
    throw CodecException{};
}
static int interrupt_xdr(void *x,void *data) {
    Marker marker;
    CHECK(xdr_uint(x,data));
    interrupt_now(); return 0;
}
struct OpaqueAuth { int flavor; char *bytes; unsigned size; };
struct Auth;
struct AuthOps {
    void (*next)(Auth *);
    int (*marshal)(Auth *,void *);
    int (*validate)(Auth *,OpaqueAuth *);
    int (*refresh)(Auth *);
    void (*destroy)(Auth *);
};
struct Auth { OpaqueAuth cred,verifier; char key[8]; const AuthOps *ops; void *private_state; };
STATIC_ASSERT(sizeof(Auth)==72 && offsetof(Auth,ops)==56,"glibc LP64 AUTH");
static int interrupt_marshal(Auth *a,void *x) { (void)a;(void)x;Marker m;interrupt_now();return 0; }
static int interrupt_validate(Auth *a,OpaqueAuth *v) { (void)a;(void)v;Marker m;interrupt_now();return 0; }
static int interrupt_refresh(Auth *a) { (void)a;Marker m;interrupt_now();return 0; }
static void *interrupted_call(void *unused) {
    (void)unused;
    uint32_t in=31,out=0;
    Xdr encode=strstr(scenario,"encode")?interrupt_xdr:xdr_uint;
    Xdr decode=strstr(scenario,"decode")?interrupt_xdr:xdr_uint;
    (void)call_rpc("127.0.0.1",program,1,7,encode,&in,decode,&out);
    CHECK(0); return NULL;
}
static void unwind_case(const char *name) {
    scenario=name;
    int before=descriptor_count();
    if (strstr(name,"client-")) {
        Client *client=create("127.0.0.1",program,1,"udp"); CHECK(client);
        uint32_t in=31,out=0; struct timeval timeout={2,0}; int caught=0;
        Auth *original=(Auth *)client->auth;
        Auth replacement=*original; AuthOps operations=*original->ops;
        replacement.ops=&operations;
        if (strstr(name,"marshal")) operations.marshal=interrupt_marshal;
        if (strstr(name,"validate")) operations.validate=interrupt_validate;
        if (strstr(name,"refresh")) operations.refresh=interrupt_refresh;
        client->auth=&replacement;
        try {
            if (strstr(name,"free")) client->ops->freeres(client,interrupt_xdr,&out);
            else client->ops->call(client,strstr(name,"refresh")?9:7,
                strstr(name,"encode")?interrupt_xdr:xdr_uint,&in,
                strstr(name,"decode")?interrupt_xdr:xdr_uint,&out,timeout);
        } catch (const CodecException &) { caught=1; }
        client->auth=original;
        CHECK(caught && destructors==1);
        CHECK(client->ops->call(client,7,xdr_uint,&in,xdr_uint,&out,timeout)==0);
        CHECK(out==(in^0x55aa55aaU)); destroy_owned(client);
    } else if (strstr(name,"exit")) {
        pthread_t worker; void *result=NULL;
        CHECK(!pthread_create(&worker,NULL,interrupted_call,NULL));
        CHECK(!pthread_join(worker,&result) && result==(void *)19);
        CHECK(destructors==1);
    } else {
        int caught=0;
        try { interrupted_call(NULL); } catch (const CodecException &) { caught=1; }
        CHECK(caught && destructors==1);
    }
    CHECK(descriptor_count()==before);
    uint32_t in=41,out=0;
    CHECK(call_rpc("127.0.0.1",program,1,7,xdr_uint,&in,xdr_uint,&out)==0);
    CHECK(out==(in^0x55aa55aaU) && descriptor_count()==before);
}
#endif
int main(int argc,char **argv) {
    CHECK(argc==2); alarm(8);
    create=(Create)symbol("clnt_create");
    xdr_uint=(Xdr)symbol("xdr_u_int");
    create_error=(void *(*)(void))symbol("__rpc_thread_createerr");
    call_rpc=(CallRpc)symbol("callrpc");
#ifdef __cplusplus
    if (strstr(argv[1],"throw") || strstr(argv[1],"exit")) {
        unwind_case(argv[1]); printf("PASS %s\n",argv[1]); return 0;
    }
#endif
    if (!strncmp(argv[1],"callrpc-",8)) {
        const char *host=strstr(argv[1],"name")?"localhost":"127.0.0.1";
        unsigned long p=program,v=1,procedure=7; int expected=0;
        Xdr encode=xdr_uint,decode=xdr_uint;
        if(strstr(argv[1],"unregistered")) { p++;expected=15; }
        if(strstr(argv[1],"encode-error")) { encode=fail_xdr;expected=1; }
        if(strstr(argv[1],"decode-error")) { decode=fail_xdr;expected=2; }
        if(strstr(argv[1],"procedure-error")) { procedure=8;expected=10; }
        if(strstr(argv[1],"high-ids")) { p=0x12345678f4567001UL;v=0xabcdef01fffffffeUL;procedure=0xffffffff80000007UL;expected=14; }
        if(strstr(argv[1],"high-wire-ids")) { p=0xf4567001UL;v=0xfffffffeUL;procedure=0x80000007UL; }
        if(strstr(argv[1],"version-overflow")) { v=0x100000001UL;expected=14; }
        if(strstr(argv[1],"procedure-overflow")) procedure=0xffffffff00000007UL;
        if(strstr(argv[1],"reentrant")) encode=reenter_xdr;
        if(strstr(argv[1],"null-host")) { host=NULL;expected=13; }
        if(strstr(argv[1],"null-encode")) { encode=NULL;expected=1; }
        if(strstr(argv[1],"null-decode")) { decode=NULL;expected=2; }
        int before=descriptor_count();
        for(int i=0;i<(strstr(argv[1],"repeat")?64:1);i++) {
            uint32_t in=0x87340000U+(unsigned)i,out=0;
            int status=call_rpc(host,p,v,procedure,encode,&in,decode,&out);
            if (status!=expected) fprintf(stderr,"RPC_STATUS actual=%d expected=%d\n",status,expected);
            CHECK(status==expected);
            if (expected==14) {
                CHECK(*(int *)create_error()==14);
                CHECK(*(int *)((char *)create_error()+8)==1);
            }
            if(!expected) CHECK(out==(in^0x55aa55aaU));
        }
        /* A reference implementation may retain one cached UDP descriptor. */
        if(getenv("FRANKENLIBC_TEST_LIBRARY")) CHECK(descriptor_count()==before);
        else CHECK(descriptor_count()<=before+1);
    } else if (!strcmp(argv[1],"unknown-protocol")) {
        CHECK(create("127.0.0.1",program,1,"not-a-protocol")==NULL);
        CHECK(*(int *)create_error()==17);
        CHECK(*(int *)((char *)create_error()+16)==EPFNOSUPPORT);
    } else if (!strcmp(argv[1],"unregistered")) {
        CHECK(create("127.0.0.1",program+1,1,"udp")==NULL);
        CHECK(*(int *)create_error()==15);
    } else if (!strcmp(argv[1],"portmapper-error")) {
        CHECK(create("127.0.0.1",program+2,1,"udp")==NULL);
        CHECK(*(int *)create_error()==14);
    } else {
        const char *proto=strstr(argv[1],"tcp")?"tcp":"udp";
        const char *host=strstr(argv[1],"name")?"localhost":"127.0.0.1";
        for(int i=0;i<(strstr(argv[1],"repeat")?32:1);i++) {
            Client *client=create(host,program,1,proto); CHECK(client);
            uint32_t in=0x12340000U+(unsigned)i,out=0;
            struct timeval timeout={2,0};
            CHECK(client->ops->call(client,7,xdr_uint,&in,xdr_uint,&out,timeout)==0);
            CHECK(out==(in^0x55aa55aaU));
            in=91;out=0;
            CHECK(client->ops->call(client,7,xdr_uint,&in,xdr_uint,&out,timeout)==0);
            CHECK(out==(in^0x55aa55aaU));
            destroy_owned(client);
        }
    }
    printf("PASS %s\n",argv[1]); return 0;
}
