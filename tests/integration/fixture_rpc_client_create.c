#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <arpa/inet.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#ifdef __cplusplus
#define STATIC_ASSERT static_assert
#define THREAD_LOCAL thread_local
#else
#define STATIC_ASSERT _Static_assert
#define THREAD_LOCAL _Thread_local
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
/* These are caller-owned char[256] buffers, not allocated char ** results.
   The clean host process and each candidate process serialize the same rows. */
typedef int (*UserToNetname)(char *, uid_t, const char *);
typedef int (*HostToNetname)(char *, const char *, const char *);
typedef int (*GetNetname)(char *);
STATIC_ASSERT(sizeof(uid_t)==4,"GNU RPC uid_t is 32 bits");
typedef struct NetnameOutput {
    unsigned char before[16];
    char name[256];
    unsigned char after[16];
} NetnameOutput;
static void netname_record(const NetnameOutput *output,int result,int saved_errno,unsigned *row) {
    CHECK(result==0 || result==1);
    for(size_t i=0;i<sizeof(output->before);i++) CHECK(output->before[i]==0xa5);
    for(size_t i=0;i<sizeof(output->after);i++) CHECK(output->after[i]==0xa5);
    size_t used=sizeof(output->name);
    if(result) {
        const char *end=(const char *)memchr(output->name,0,sizeof(output->name));
        CHECK(end);
        used=(size_t)(end-output->name)+1;
    }
    static const char digits[]="0123456789abcdef";
    char encoded[sizeof(output->name)*2+1];
    for(size_t i=0;i<used;i++) {
        unsigned byte=(unsigned char)output->name[i];
        encoded[2*i]=digits[byte>>4];encoded[2*i+1]=digits[byte&15];
    }
    encoded[2*used]=0;
    printf("NETNAME %u %d %d %s\n",(*row)++,result,saved_errno,encoded);
}
static void netname_user_row(UserToNetname function,unsigned *row,uid_t uid,const char *domain) {
    NetnameOutput output;memset(&output,0xa5,sizeof(output));errno=EDOM;
    int result=function(output.name,uid,domain),saved_errno=errno;
    netname_record(&output,result,saved_errno,row);
}
static void netname_host_row(HostToNetname function,unsigned *row,const char *host,const char *domain) {
    NetnameOutput output;memset(&output,0xa5,sizeof(output));errno=EDOM;
    int result=function(output.name,host,domain),saved_errno=errno;
    netname_record(&output,result,saved_errno,row);
}
static void netname_case(const char *name) {
    unsigned row=0;
    if(!strcmp(name,"netname-user")) {
        UserToNetname function=(UserToNetname)symbol("user2netname");
        const uid_t ids[]={0,1,42,(uid_t)UINT32_C(0x7fffffff),
                           (uid_t)UINT32_C(0x80000000),(uid_t)UINT32_MAX};
        const char *domains[]={"example.org","example.org.","",".","..",
                               "domain..","\xff\x80.example",NULL};
        for(size_t i=0;i<sizeof(ids)/sizeof(ids[0]);i++)
            for(size_t j=0;j<sizeof(domains)/sizeof(domains[0]);j++)
                netname_user_row(function,&row,ids[i],domains[j]);
        const size_t lengths[]={236,237,238,254,255,256,260};
        char domain[261];
        for(size_t i=0;i<sizeof(lengths)/sizeof(lengths[0]);i++) {
            size_t length=lengths[i];
            memset(domain,'d',length);domain[length]=0;
            netname_user_row(function,&row,42,domain);
            netname_user_row(function,&row,(uid_t)UINT32_MAX,domain);
            domain[length-1]='.';
            netname_user_row(function,&row,42,domain);
            netname_user_row(function,&row,(uid_t)UINT32_MAX,domain);
        }
        CHECK(row==76);return;
    }
    if(!strcmp(name,"netname-host")) {
        HostToNetname function=(HostToNetname)symbol("host2netname");
        const char *hosts[]={"short","host.example.org","","a.","a..",
                             ".example.org","first.second.third","\xff\x80host.example",NULL};
        const char *domains[]={"example.net","example.net.","",".","..",
                               "domain..","\xff\x80.example",NULL};
        for(size_t i=0;i<sizeof(hosts)/sizeof(hosts[0]);i++)
            for(size_t j=0;j<sizeof(domains)/sizeof(domains[0]);j++)
                netname_host_row(function,&row,hosts[i],domains[j]);
        const size_t lengths[]={63,64,65,127,260};
        char host[280],domain[261];
        for(size_t i=0;i<sizeof(lengths)/sizeof(lengths[0]);i++) {
            size_t host_length=lengths[i];
            memset(host,'h',host_length);host[host_length]=0;
            for(size_t j=0;j<sizeof(lengths)/sizeof(lengths[0]);j++) {
                size_t domain_length=lengths[j];
                memset(domain,'d',domain_length);domain[domain_length]=0;
                netname_host_row(function,&row,host,domain);
                domain[domain_length-1]='.';
                netname_host_row(function,&row,host,domain);
                if(domain_length>=64) {
                    memset(domain,'d',domain_length);domain[63]='.';domain[domain_length]=0;
                    netname_host_row(function,&row,host,domain);
                }
            }
            host[host_length]='.';
            memcpy(host+host_length+1,"example.org",sizeof("example.org"));
            netname_host_row(function,&row,host,NULL);
            netname_host_row(function,&row,host,"explicit.example");
        }
        CHECK(row==152);return;
    }
    CHECK(!strcmp(name,"netname-default"));
    GetNetname get=(GetNetname)symbol("getnetname");
    HostToNetname host=(HostToNetname)symbol("host2netname");
    UserToNetname user=(UserToNetname)symbol("user2netname");
    NetnameOutput output;memset(&output,0xa5,sizeof(output));errno=EDOM;
    int result=get(output.name),saved_errno=errno;
    netname_record(&output,result,saved_errno,&row);
    netname_host_row(host,&row,NULL,NULL);
    netname_host_row(host,&row,NULL,"example.org.");
    netname_host_row(host,&row,"machine",NULL);
    netname_user_row(user,&row,0,NULL);
    netname_user_row(user,&row,(uid_t)UINT32_MAX,NULL);
    netname_user_row(user,&row,geteuid(),NULL);
    CHECK(row==7);
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

/* Diagnostics accept the public CLIENT operation table, including a caller's
   own geterr callback. Expected bytes use host snprintf/strerror explicitly,
   never the candidate formatter or candidate's error-name table. */
typedef struct RpcError { int status; unsigned padding; unsigned long first,second; } RpcError;
typedef struct CreateError { int status; unsigned padding; RpcError error; } CreateError;
STATIC_ASSERT(sizeof(RpcError)==24 && sizeof(CreateError)==32,"glibc LP64 RPC errors");
static char *(*diagnostic)(Client *,const char *), *(*creation_diagnostic)(const char *), *(*status_name)(int);
static void (*print_diagnostic)(Client *,const char *), (*print_creation)(const char *), (*print_status)(int);
static int (*host_format)(char *,size_t,const char *,...);
static char *(*host_error)(int);
static THREAD_LOCAL int diagnostic_depth, diagnostic_reentry;
static void (*diagnostic_hook)(void);
static const char *error_name(int status) {
    static const char *names[]={"RPC: Success","RPC: Can't encode arguments","RPC: Can't decode result",
        "RPC: Unable to send","RPC: Unable to receive","RPC: Timed out","RPC: Incompatible versions of RPC",
        "RPC: Authentication error","RPC: Program unavailable","RPC: Program/version mismatch",
        "RPC: Procedure unavailable","RPC: Server can't decode arguments","RPC: Remote system error",
        "RPC: Unknown host","RPC: Port mapper failure","RPC: Program not registered",
        "RPC: Failed (unspecified error)","RPC: Unknown protocol"};
    return status>=0 && status<18?names[status]:"RPC: (unknown error code)";
}
static const char *auth_name(int why) {
    static const char *names[]={"Authentication OK","Invalid client credential","Server rejected credential",
        "Invalid client verifier","Server rejected verifier","Client credential too weak",
        "Invalid server verifier","Failed (unspecified error)"};
    return why>=0 && why<8?names[why]:NULL;
}
static void diagnostic_geterr(Client *client,void *output);
static const Ops diagnostic_ops={NULL,NULL,diagnostic_geterr,NULL,NULL,NULL};
static void diagnostic_geterr(Client *client,void *output) {
    if (diagnostic_hook) diagnostic_hook();
    if (diagnostic_reentry && !diagnostic_depth) {
        diagnostic_depth=1;
        RpcError nested={5,0,0,0}; Client inner={NULL,&diagnostic_ops,&nested};
        CHECK(!strcmp(diagnostic(&inner,"inner"),"inner: RPC: Timed out\n"));
        diagnostic_depth=0;
    }
    memcpy(output,client->private_state,sizeof(RpcError));
}
static void expected_diagnostic(char *out,size_t size,const char *prefix,const RpcError *error) {
    const char *name=error_name(error->status);
    int status=error->status, why=(int)error->first;
    if(status==3 || status==4) host_format(out,size,"%s: %s; errno = %s\n",prefix,name,host_error(why));
    else if(status==6 || status==9) host_format(out,size,"%s: %s; low version = %lu, high version = %lu",prefix,name,error->first,error->second);
    else if(status==7 && auth_name(why)) host_format(out,size,"%s: %s; why = %s\n",prefix,name,auth_name(why));
    else if(status==7) host_format(out,size,"%s: %s; why = (unknown authentication error - %d)\n",prefix,name,why);
    else if(status<0 || status>17) host_format(out,size,"%s: %s; s1 = %lu, s2 = %lu",prefix,name,error->first,error->second);
    else host_format(out,size,"%s: %s\n",prefix,name);
}
static void expect_diagnostic(Client *client,const char *prefix,const RpcError *error) {
    char expected[131072]; expected_diagnostic(expected,sizeof(expected),prefix,error);
    char *actual=diagnostic(client,prefix); CHECK(actual);
    if(strcmp(actual,expected)) fprintf(stderr,"DIAGNOSTIC expected=[%s] actual=[%s]\n",expected,actual);
    CHECK(!strcmp(actual,expected));
}
static void expect_print(Client *client,const char *expected,int kind) {
    int fds[2]; CHECK(!pipe(fds)); CHECK(!fflush(stderr));
    int original=dup(2); CHECK(original>=0 && dup2(fds[1],2)==2); CHECK(!close(fds[1]));
    if(kind==0) print_diagnostic(client,"print");
    else if(kind==1) print_creation("print");
    else print_status(((RpcError *)client->private_state)->status);
    CHECK(!fflush(stderr)); CHECK(dup2(original,2)==2 && !close(original));
    char output[4096]; size_t used=0; ssize_t n;
    while((n=read(fds[0],output+used,sizeof(output)-1-used))>0) used+=(size_t)n;
    CHECK(n==0 && !close(fds[0])); output[used]=0; CHECK(!strcmp(output,expected));
}
static void load_diagnostics(void) {
    diagnostic=(char *(*)(Client *,const char *))symbol("clnt_sperror");
    print_diagnostic=(void (*)(Client *,const char *))symbol("clnt_perror");
    creation_diagnostic=(char *(*)(const char *))symbol("clnt_spcreateerror");
    print_creation=(void (*)(const char *))symbol("clnt_pcreateerror");
    status_name=(char *(*)(int))symbol("clnt_sperrno");
    print_status=(void (*)(int))symbol("clnt_perrno");
    void *host=dlopen("libc.so.6",RTLD_NOW|RTLD_LOCAL); CHECK(host);
    host_format=(int (*)(char *,size_t,const char *,...))dlvsym(host,"snprintf","GLIBC_2.2.5");
    host_error=(char *(*)(int))dlvsym(host,"strerror","GLIBC_2.2.5"); CHECK(host_format && host_error);
}
static pthread_barrier_t diagnostic_barrier;
static void *diagnostic_thread(void *value) {
    int index=(int)(intptr_t)value;
    RpcError error={index?9:7,0,index?ULONG_MAX:5,1}; Client client={NULL,&diagnostic_ops,&error};
    char expected[1024]; const char *prefix=index?"thread-b":"thread-a";
    expected_diagnostic(expected,sizeof(expected),prefix,&error);
    char *actual=diagnostic(&client,prefix); CHECK(actual);
    int rc=pthread_barrier_wait(&diagnostic_barrier); CHECK(rc==0 || rc==PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(!strcmp(actual,expected)); return NULL;
}
#ifdef __cplusplus
static void diagnostic_unwind_case(const char *name);
#endif
static void diagnostic_case(const char *name) {
    load_diagnostics();
#ifdef __cplusplus
    if(strstr(name,"throw") || strstr(name,"exit")) { diagnostic_unwind_case(name);return; }
#endif
    RpcError error={0,0,ULONG_MAX,0x1234567887654321UL}; Client client={NULL,&diagnostic_ops,&error};
    if(!strcmp(name,"diag-native-initial")) {
        Client *native=create("127.0.0.1",program,1,"udp");CHECK(native);
        expect_diagnostic(native,"initial",&error);destroy_owned(native);
    } else if(!strcmp(name,"diag-native-udp") || !strcmp(name,"diag-native-tcp")) {
        Client *native=create("127.0.0.1",program,1,strstr(name,"tcp")?"tcp":"udp"); CHECK(native);
        /* GNU's last-error storage is not initialized by these constructors;
           compare it only after a real call has supplied the last status. */
        const unsigned long procedures[]={7,8,9,10,11}; const int statuses[]={0,10,7,9,6};
        for(unsigned i=0;i<5;i++) {
            uint32_t in=31,out=0; struct timeval timeout={2,0};
            CHECK(native->ops->call(native,procedures[i],xdr_uint,&in,xdr_uint,&out,timeout)==statuses[i]);
            error.status=statuses[i]; error.first=i==2?2:i==3?1:i==4?2:0;error.second=i==3?5:i==4?2:0;
            expect_diagnostic(native,"native",&error);
        }
        destroy_owned(native);
    } else if(!strcmp(name,"diag-thread")) {
        CHECK(!pthread_barrier_init(&diagnostic_barrier,NULL,2)); pthread_t workers[2];
        for(int i=0;i<2;i++) CHECK(!pthread_create(&workers[i],NULL,diagnostic_thread,(void *)(intptr_t)i));
        for(int i=0;i<2;i++) { CHECK(!pthread_join(workers[i],NULL)); }
        CHECK(!pthread_barrier_destroy(&diagnostic_barrier));
    } else if(!strcmp(name,"diag-reentry")) {
        diagnostic_reentry=1; error.status=9; expect_diagnostic(&client,"outer",&error);
    } else if(!strcmp(name,"diag-prefix")) {
        char *prefix=(char *)malloc(100001); CHECK(prefix); memset(prefix,'q',100000);prefix[100000]=0;
        expect_diagnostic(&client,prefix,&error);free(prefix);
        expect_diagnostic(&client,"\xff\x80%s%n",&error); expect_diagnostic(&client,"",&error);
        expect_diagnostic(&client,NULL,&error);
        char saved[1024]; char *previous=diagnostic(&client,"alias"); CHECK(previous); strcpy(saved,previous);
        expected_diagnostic(saved+strlen(saved)+1,sizeof(saved)/2,previous,&error);
        CHECK(!strcmp(diagnostic(&client,previous),saved+strlen(saved)+1));
    } else if(!strcmp(name,"diag-static")) {
        char *first=status_name(0);CHECK(first && !strcmp(first,error_name(0)));
        CHECK(!strcmp(status_name(5),error_name(5)));CHECK(!strcmp(first,error_name(0)));
        expect_diagnostic(&client,"client",&error);CHECK(!strcmp(first,error_name(0)));
        (void)creation_diagnostic("creation");CHECK(!strcmp(first,error_name(0)));
    } else if(!strcmp(name,"diag-create")) {
        CreateError *creation=(CreateError *)create_error();
        for(int i=0;i<18;i++) {
            creation->status=i; creation->error.status=5; creation->error.first=EACCES;
            char expected[1024];
            host_format(expected,sizeof(expected),"print: %s%s%s\n",error_name(i),i==12 || i==14?" - ":"",i==12?host_error(EACCES):i==14?error_name(5):"");
            CHECK(!strcmp(creation_diagnostic("print"),expected));expect_print(&client,expected,1);
        }
    } else {
        const int statuses[]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,-1,INT_MAX,INT_MIN};
        for(unsigned i=0;i<sizeof(statuses)/sizeof(statuses[0]);i++) {
            error.status=statuses[i];
            if(!strcmp(name,"diag-status")) CHECK(!strcmp(status_name(error.status),error_name(error.status)));
            else if(!strcmp(name,"diag-print")) {
                char expected[1024];expected_diagnostic(expected,sizeof(expected),"print",&error);expect_print(&client,expected,0);expect_print(&client,error_name(error.status),2);
            } else expect_diagnostic(&client,"diagnostic",&error);
        }
        if(!strcmp(name,"diag-errno")) {
            const int errors[]={0,EACCES,EBADF,ECONNRESET,99999,-17,INT_MIN};
            for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++) {error.status=3;error.first=(unsigned)errors[i];expect_diagnostic(&client,"errno",&error);}
        }
        if(!strcmp(name,"diag-auth")) for(int i=-1;i<=8;i++) {error.status=7;error.first=(unsigned)i;expect_diagnostic(&client,"auth",&error);}
    }
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
static void interrupt_geterr(void) { Marker marker;interrupt_now(); }
static void *diagnostic_interrupted_thread(void *raw) {
    Client *client=(Client *)raw;
    if(strstr(scenario,"print")) print_diagnostic(client,"interrupted");
    else (void)diagnostic(client,"interrupted");
    CHECK(0);return NULL;
}
static void diagnostic_unwind_case(const char *name) {
    scenario=name;diagnostic_hook=interrupt_geterr;
    RpcError error={5,0,0,0};Client client={NULL,&diagnostic_ops,&error};
    if(strstr(name,"exit")) {
        pthread_t worker;void *result=NULL;
        CHECK(!pthread_create(&worker,NULL,diagnostic_interrupted_thread,&client));
        CHECK(!pthread_join(worker,&result) && result==(void *)19);
    } else {
        int caught=0;
        try { diagnostic_interrupted_thread(&client); } catch(const CodecException &) { caught=1; }
        CHECK(caught);
    }
    CHECK(destructors==1);diagnostic_hook=NULL;expect_diagnostic(&client,"after",&error);
}
#endif
typedef int (*Broadcast)(unsigned long,unsigned long,unsigned long,Xdr,void *,Xdr,void *,int (*)(void *,struct sockaddr_in *));
static Broadcast broadcast_rpc;
static int (*broadcast_string)(void *,char **,unsigned);
static int (*broadcast_opaque)(void *,void *,unsigned);
static const char *broadcast_scenario;
static unsigned broadcast_encodes,broadcast_decodes,broadcast_frees,broadcast_results;
static unsigned broadcast_cleanups;
static struct { unsigned value; char *text; } broadcast_output;
static int broadcast_text_result(void) {
    return strstr(broadcast_scenario,"string") || strstr(broadcast_scenario,"decode-throw")
        || strstr(broadcast_scenario,"decode-exit") || strstr(broadcast_scenario,"result-throw")
        || strstr(broadcast_scenario,"result-exit");
}
static int broadcast_encode(void *stream,void *value) {
    ++broadcast_encodes;
    if(strstr(broadcast_scenario,"encode-error")) return 0;
    if(strstr(broadcast_scenario,"large-args")) {
        char bytes[2048]={0};return broadcast_opaque(stream,bytes,sizeof(bytes));
    }
#ifdef __cplusplus
    if(strstr(broadcast_scenario,"encode-throw") || strstr(broadcast_scenario,"encode-exit")) {
        Marker marker;interrupt_now();
    }
#endif
    return xdr_uint(stream,value);
}
static int broadcast_decode(void *stream,void *value) {
    (void)value;
    int operation=*(int *)stream;
    if(operation==1) ++broadcast_decodes;
    if(operation==2) ++broadcast_frees;
    int ok=broadcast_text_result()?broadcast_string(stream,&broadcast_output.text,128)
                                  :xdr_uint(stream,&broadcast_output.value);
#ifdef __cplusplus
    if(operation==1 && (strstr(broadcast_scenario,"decode-throw") || strstr(broadcast_scenario,"decode-exit"))) {
        CHECK(ok && broadcast_output.text);Marker marker;interrupt_now();
    }
#endif
    if(operation==1 && strstr(broadcast_scenario,"decode-error") && broadcast_decodes==1) return 0;
    return ok;
}
static int broadcast_result(void *value,struct sockaddr_in *peer) {
    CHECK(value==&broadcast_output && peer->sin_family==AF_INET);
    CHECK(peer->sin_addr.s_addr==inet_addr("192.0.2.1"));
    ++broadcast_results;
    unsigned expected=strstr(broadcast_scenario,"multiple")?46+broadcast_results:47;
    unsigned port=strstr(broadcast_scenario,"port-width")?65535:33333;
    CHECK(ntohs(peer->sin_port)==port);
    if(broadcast_text_result()) CHECK(broadcast_output.text && !strcmp(broadcast_output.text,"native-broadcast"));
    else CHECK(broadcast_output.value==expected);
    if(strstr(broadcast_scenario,"reentry")) {
        unsigned nested=41;
        CHECK(broadcast_rpc(program,1,7,broadcast_encode,&nested,broadcast_decode,&broadcast_output,NULL)==0);
    }
#ifdef __cplusplus
    if(strstr(broadcast_scenario,"result-throw") || strstr(broadcast_scenario,"result-exit")) {
        Marker marker;interrupt_now();
    }
#endif
    return !strstr(broadcast_scenario,"multiple") || broadcast_results==2;
}
static void *broadcast_invoke(void *unused) {
    (void)unused;unsigned input=40;
    unsigned long p=program,v=1,procedure=7;
    if(strstr(broadcast_scenario,"high-ids")) {
        p|=0x1234567800000000UL;v|=0xabcdef0000000000UL;procedure|=0xffffffff00000000UL;
    }
    int status=broadcast_rpc(p,v,procedure,broadcast_encode,&input,broadcast_decode,&broadcast_output,
                            strstr(broadcast_scenario,"send-only")?NULL:broadcast_result);
    int expected=strstr(broadcast_scenario,"encode-error") || strstr(broadcast_scenario,"large-args")
                 || strstr(broadcast_scenario,"high-ids")?1
                 :strstr(broadcast_scenario,"timeout")?5:0;
    if(status!=expected) fprintf(stderr,"BROADCAST_STATUS actual=%d expected=%d\n",status,expected);
    CHECK(status==expected);
    return NULL;
}
static void broadcast_cleanup(void *unused) { (void)unused;++broadcast_cleanups; }
static void *broadcast_cancellable(void *unused) {
    pthread_cleanup_push(broadcast_cleanup,NULL);
    broadcast_invoke(unused);
    pthread_cleanup_pop(1);
    return NULL;
}
static void broadcast_case(const char *name) {
    broadcast_scenario=name;
    broadcast_rpc=(Broadcast)symbol("clnt_broadcast");
    xdr_uint=(Xdr)symbol("xdr_u_int");
    broadcast_string=(int (*)(void *,char **,unsigned))symbol("xdr_string");
    broadcast_opaque=(int (*)(void *,void *,unsigned))symbol("xdr_opaque");
    int before=descriptor_count();
    if(strstr(name,"timeout")) alarm(70);
    if(!strcmp(name,"broadcast-cancel")) {
        const char *descriptor=getenv("RPC_BROADCAST_ACK_FD");CHECK(descriptor);
        pthread_t worker;void *returned=NULL;char acknowledged=0;
        CHECK(!pthread_create(&worker,NULL,broadcast_cancellable,NULL));
        /* The independent wire peer acknowledges receipt before cancellation;
           no sleep is used to guess whether the worker reached its wait. */
        CHECK(read(atoi(descriptor),&acknowledged,1)==1 && acknowledged=='R');
        CHECK(!pthread_cancel(worker));
        CHECK(!pthread_join(worker,&returned) && returned==PTHREAD_CANCELED);
        CHECK(broadcast_encodes==1 && broadcast_decodes==0 && broadcast_results==0);
        CHECK(broadcast_cleanups==1 && descriptor_count()==before);
        return;
    }
#ifdef __cplusplus
    if(strstr(name,"throw") || strstr(name,"exit")) {
        scenario=name;
        if(strstr(name,"exit")) {
            pthread_t worker;void *returned=NULL;
            CHECK(!pthread_create(&worker,NULL,broadcast_invoke,NULL));
            CHECK(!pthread_join(worker,&returned) && returned==(void *)19);
        } else {
            int caught=0;
            try { broadcast_invoke(NULL); } catch(const CodecException &) { caught=1; }
            CHECK(caught);
        }
        CHECK(destructors==1 && broadcast_output.text==NULL);
        CHECK(broadcast_frees==(strstr(name,"encode-")?0U:1U));
        CHECK(descriptor_count()==before);
        return;
    }
#endif
    broadcast_invoke(NULL);
    CHECK(broadcast_encodes==(strstr(name,"reentry")?2U:strstr(name,"high-ids")?0U:1U));
    unsigned expected_results=strstr(name,"send-only") || strstr(name,"encode-error")
        || strstr(name,"large-args") || strstr(name,"high-ids") || strstr(name,"timeout")?0:strstr(name,"multiple")?2:1;
    CHECK(broadcast_results==expected_results);
    CHECK(broadcast_decodes==expected_results+(strstr(name,"decode-error") || strstr(name,"stale")?1U:0U));
    CHECK(broadcast_frees>=broadcast_decodes);
    CHECK(broadcast_output.text==NULL && descriptor_count()==before);
}
int main(int argc,char **argv) {
    CHECK(argc==2); alarm(8);
    if(!strncmp(argv[1],"netname-",8)) {
        netname_case(argv[1]);printf("PASS %s\n",argv[1]);return 0;
    }
    if(!strncmp(argv[1],"broadcast-",10)) {
        broadcast_case(argv[1]);printf("PASS %s\n",argv[1]);return 0;
    }
    create=(Create)symbol("clnt_create");
    xdr_uint=(Xdr)symbol("xdr_u_int");
    create_error=(void *(*)(void))symbol("__rpc_thread_createerr");
    call_rpc=(CallRpc)symbol("callrpc");
    if(!strncmp(argv[1],"diag-",5)) {
        diagnostic_case(argv[1]);printf("PASS %s\n",argv[1]);return 0;
    }
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
