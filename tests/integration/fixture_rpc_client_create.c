#define _GNU_SOURCE
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
struct Client { void *auth; const Ops *ops; void *private; };
_Static_assert(sizeof(Client)==24 && offsetof(Client,ops)==8,"glibc LP64 CLIENT");
_Static_assert(sizeof(Ops)==48,"glibc LP64 CLIENT operations");
typedef Client *(*Create)(const char *, unsigned long, unsigned long, const char *);
typedef int (*CallRpc)(const char *, int, int, int, Xdr, void *, Xdr, void *);
static Create create;
static Xdr xdr_uint;
static void *(*create_error)(void);
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while(0)
static void wrong_provider(void) {
    static const char message[]="WRONG RPC PROVIDER\n";
    (void)write(STDERR_FILENO,message,sizeof(message)-1);
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
int main(int argc,char **argv) {
    CHECK(argc==2); alarm(8);
    create=(Create)symbol("clnt_create");
    xdr_uint=(Xdr)symbol("xdr_u_int");
    create_error=(void *(*)(void))symbol("__rpc_thread_createerr");
    if (!strncmp(argv[1],"callrpc-",8)) {
        CallRpc call=(CallRpc)symbol("callrpc");
        const char *host=strstr(argv[1],"name")?"localhost":"127.0.0.1";
        int p=(int)program,v=1,procedure=7,expected=0;
        Xdr encode=xdr_uint,decode=xdr_uint;
        if(strstr(argv[1],"unregistered")) { p++;expected=15; }
        if(strstr(argv[1],"encode-error")) { encode=fail_xdr;expected=1; }
        if(strstr(argv[1],"decode-error")) { decode=fail_xdr;expected=2; }
        if(strstr(argv[1],"procedure-error")) { procedure=8;expected=10; }
        if(strstr(argv[1],"high-ids")) { p=(int)0xf4567001U;v=(int)0xfffffffeU;procedure=(int)0x80000007U; }
        int before=descriptor_count();
        for(int i=0;i<(strstr(argv[1],"repeat")?64:1);i++) {
            uint32_t in=0x87340000U+(unsigned)i,out=0;
            CHECK(call(host,p,v,procedure,encode,&in,decode,&out)==expected);
            if(!expected) CHECK(out==(in^0x55aa55aaU));
        }
        /* A reference implementation may retain one cached UDP descriptor. */
        if(getenv("FRANKENLIBC_TEST_LIBRARY")) CHECK(descriptor_count()==before);
        else CHECK(descriptor_count()<=before+1);
    } else if (!strcmp(argv[1],"unknown-protocol")) {
        CHECK(create("127.0.0.1",program,1,"not-a-protocol")==NULL);
        CHECK(*(int *)create_error()==17);
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
