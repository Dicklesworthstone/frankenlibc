/* Native EDNS request conformance through owner-pinned exported res_n* APIs.
 * cc -std=c11 -O2 -Wall -Wextra -Werror edns_resolver_abi.c -pthread -lresolv -ldl -o edns-resolver
 * timeout 60 ./edns-resolver --host   (or an absolute candidate .so path)
 * This requests DNSSEC records; it does not perform cryptographic validation.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

typedef int (*init_fn)(res_state);
typedef void (*close_fn)(res_state);
typedef int (*mk_fn)(res_state,int,const char*,int,int,const unsigned char*,int,const unsigned char*,unsigned char*,int);
typedef int (*query_fn)(res_state,const char*,int,int,unsigned char*,int);
typedef int (*domain_fn)(res_state,const char*,const char*,int,int,unsigned char*,int);
typedef int (*send_fn)(res_state,const unsigned char*,int,unsigned char*,int);
static init_fn ninit;
static close_fn nclose;
static mk_fn nmkquery;
static query_fn nquery, nsearch;
static domain_fn nquerydomain;
static send_fn nsend;
static unsigned cases;

static void *symbol(void *handle, const char *name, const char *candidate) {
    void *p=dlsym(handle,name);
    assert(p);
    Dl_info info;
    assert(dladdr(p,&info));
    if(candidate) {
        struct stat a,b;
        assert(stat(candidate,&a)==0 && stat(info.dli_fname,&b)==0);
        assert(a.st_dev==b.st_dev && a.st_ino==b.st_ino);
    } else {
        assert(strstr(info.dli_fname,"libc.so") || strstr(info.dli_fname,"libresolv.so"));
    }
    return p;
}
static void timeout_socket(int fd) {
    struct timeval timeout={.tv_sec=3};
    assert(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
    assert(setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))==0);
}
static int bound_socket(struct sockaddr_in *address, int tcp, int reuse_port) {
    int fd=socket(AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0);
    assert(fd>=0);
    if(!reuse_port) *address=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    assert(bind(fd,(const void*)address,sizeof(*address))==0);
    socklen_t size=sizeof(*address);
    assert(getsockname(fd,(void*)address,&size)==0);
    timeout_socket(fd);
    if(tcp) assert(listen(fd,1)==0);
    return fd;
}
static void configure(res_state s, struct sockaddr_in address, unsigned long options) {
    memset(s,0,sizeof(*s));
    s->options=RES_INIT|RES_RECURSE|RES_DEFNAMES|RES_DNSRCH|options;
    s->nscount=1;
    s->nsaddr_list[0]=address;
    s->retrans=1;
    s->retry=1;
    s->ndots=1;
    s->_vcsock=-1;
}
static void read_all(int fd, void *pointer, size_t size) {
    unsigned char *out=pointer;
    while(size) { ssize_t n=read(fd,out,size); assert(n>0); out+=n; size-=(size_t)n; }
}
static void write_all(int fd, const void *pointer, size_t size) {
    const unsigned char *in=pointer;
    while(size) { ssize_t n=write(fd,in,size); assert(n>0); in+=n; size-=(size_t)n; }
}
static size_t question_end(const unsigned char *packet, size_t length) {
    size_t end=12;
    while(end<length && packet[end]) end+=(size_t)packet[end]+1;
    end+=5;
    assert(end<=length);
    return end;
}
struct fixture {
    int fd, tcp_fd, tcp, fallback, search, raw, formerr;
    unsigned long options;
    int capacity;
    const char *name;
    unsigned calls;
    unsigned char response[2048];
    size_t response_length;
};
static void check_query(const struct fixture *f, const unsigned char *packet, size_t length, unsigned call) {
    ns_msg message;
    assert(ns_initparse(packet,(int)length,&message)==0);
    assert(ns_msg_count(message,ns_s_qd)==1);
    ns_rr question;
    assert(ns_parserr(&message,ns_s_qd,0,&question)==0);
    const char *name=f->search?(call==0?"host.first.test":"host.second.test"):f->name;
    assert(strcmp(ns_rr_name(question),name)==0);
    assert(ns_rr_type(question)==ns_t_a && ns_rr_class(question)==ns_c_in);
    int enabled=!f->raw && !!(f->options&(RES_USE_EDNS0|RES_USE_DNSSEC));
    assert(ns_msg_count(message,ns_s_ar)==enabled);
    assert(!!(packet[3]&0x20)==!!(f->options&RES_TRUSTAD));
    if(enabled) {
        ns_rr opt;
        assert(ns_parserr(&message,ns_s_ar,0,&opt)==0);
        int payload=f->capacity<512?512:f->capacity>1200?1200:f->capacity;
        assert(strcmp(ns_rr_name(opt),".")==0);
        assert(ns_rr_type(opt)==ns_t_opt);
        assert((int)ns_rr_class(opt)==payload);
        assert(ns_rr_ttl(opt)==((f->options&RES_USE_DNSSEC)?0x8000u:0u));
        assert(ns_rr_rdlen(opt)==0);
        assert(length==question_end(packet,length)+11);
    }
}
static size_t reply(struct fixture *f, const unsigned char *packet, size_t length, int code, int tc, int large) {
    size_t end=question_end(packet,length);
    memcpy(f->response,packet,end);
    f->response[2]|=0x80|(tc?2:0);
    f->response[3]=0x80|(unsigned char)code;
    // Avoid the host's separate short-question AD-copy behavior; test AD on
    // complete responses instead of conflating it with short-buffer parity.
    if(f->capacity>=46) f->response[3]|=0x20;
    memset(f->response+6,0,6);
    if(!code && !tc) {
        f->response[7]=large?2:1;
        const unsigned char rr[]={0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,85};
        memcpy(f->response+end,rr,sizeof(rr));end+=sizeof(rr);
        if(large) {
            const unsigned char signature[]={0xc0,12,0,46,0,1,0,0,0,60,3,32};
            memcpy(f->response+end,signature,sizeof(signature));end+=sizeof(signature);
            memset(f->response+end,0x5a,800);end+=800;
        }
    }
    f->response_length=end;
    return end;
}
static void *serve(void *pointer) {
    struct fixture *f=pointer;
    for(unsigned attempt=0;attempt<(f->search?2u:1u);attempt++) {
        unsigned char packet[1024];
        struct sockaddr_in peer;
        socklen_t size=sizeof(peer);
        size_t length;
        int connection=-1;
        if(f->tcp) {
            connection=accept(f->fd,NULL,NULL);assert(connection>=0);timeout_socket(connection);
            unsigned char prefix[2];read_all(connection,prefix,2);
            length=((size_t)prefix[0]<<8)|prefix[1];assert(length<=sizeof(packet));
            read_all(connection,packet,length);
        } else {
            ssize_t n=recvfrom(f->fd,packet,sizeof(packet),0,(void*)&peer,&size);assert(n>=17);length=(size_t)n;
        }
        check_query(f,packet,length,attempt);f->calls++;
        int code=f->formerr?1:f->search&&attempt==0?3:0;
        size_t n=reply(f,packet,length,code,f->fallback,0);
        if(f->tcp) {
            unsigned char prefix[]={(unsigned char)(n>>8),(unsigned char)n};write_all(connection,prefix,2);
            write_all(connection,f->response,n);assert(close(connection)==0);
        } else assert(sendto(f->fd,f->response,n,0,(void*)&peer,size)==(ssize_t)n);
        if(f->fallback) {
            connection=accept(f->tcp_fd,NULL,NULL);assert(connection>=0);timeout_socket(connection);
            unsigned char prefix[2], tcp_query[1024];read_all(connection,prefix,2);
            size_t tcp_length=((size_t)prefix[0]<<8)|prefix[1];assert(tcp_length==length);
            read_all(connection,tcp_query,tcp_length);assert(memcmp(packet,tcp_query,length)==0);
            f->calls++;
            n=reply(f,packet,length,0,0,1);
            prefix[0]=(unsigned char)(n>>8);prefix[1]=(unsigned char)n;
            write_all(connection,prefix,2);
            for(size_t offset=0;offset<n;offset+=7) write_all(connection,f->response+offset,n-offset<7?n-offset:7);
            assert(close(connection)==0);
        }
    }
    return NULL;
}
static void run_case(unsigned long options,int capacity,int mode) {
    // 0=query, 1=querydomain, 2=search, 3=raw, 4=FORMERR, 5=TCP fallback.
    struct fixture f={.options=options,.capacity=capacity,.tcp=!!(options&RES_USEVC),
        .fallback=mode==5,.search=mode==2,.raw=mode==3,.formerr=mode==4,
        .name=mode==1?"host.suffix.test":"example.test"};
    struct sockaddr_in address;
    f.fd=bound_socket(&address,f.tcp,0);
    if(f.fallback) f.tcp_fd=bound_socket(&address,1,1);
    struct __res_state state;configure(&state,address,options);
    if(f.search) {state.dnsrch[0]="first.test";state.dnsrch[1]="second.test";}
    unsigned char built[512];memset(built,0xa5,sizeof(built));
    int built_length=nmkquery(&state,QUERY,"example.test",C_IN,T_A,NULL,0,NULL,built,sizeof(built));
    assert(built_length==30 && built[11]==0 && built[30]==0xa5);
    pthread_t thread;assert(pthread_create(&thread,NULL,serve,&f)==0);
    unsigned char *output=malloc((size_t)capacity+2);assert(output);memset(output,0xa5,(size_t)capacity+2);
    int n=mode==1?nquerydomain(&state,"host","suffix.test",C_IN,T_A,output+1,capacity)
        :mode==2?nsearch(&state,"host",C_IN,T_A,output+1,capacity)
        :mode==3?nsend(&state,built,built_length,output+1,capacity)
        :nquery(&state,"example.test",C_IN,T_A,output+1,capacity);
    assert(pthread_join(thread,NULL)==0);
    size_t copied=f.response_length<(size_t)capacity?f.response_length:(size_t)capacity;
    if(f.formerr) assert(n==-1 && state.res_h_errno==NO_RECOVERY);
    else assert(n==(int)((f.tcp||f.fallback)?f.response_length:copied));
    if(!(options&RES_TRUSTAD)) f.response[3]&=~0x20;
    if((f.tcp||f.fallback)&&copied<f.response_length) f.response[2]|=2;
    assert(memcmp(output+1,f.response,copied)==0);
    assert(output[0]==0xa5);
    for(size_t i=1+copied;i<(size_t)capacity+2;i++) assert(output[i]==0xa5);
    assert(f.calls==(f.fallback||f.search?2u:1u));
    if(f.formerr) {unsigned char byte;assert(recv(f.fd,&byte,1,MSG_DONTWAIT)==-1 && (errno==EAGAIN||errno==EWOULDBLOCK));}
    nclose(&state);assert(close(f.fd)==0);if(f.fallback) assert(close(f.tcp_fd)==0);free(output);
    printf("PASS: flags=%08lx capacity=%d mode=%d\n",options,capacity,mode);cases++;
}
static void init_case(const char *option) {
    assert(setenv("RES_OPTIONS",option,1)==0);
    struct __res_state a={0}, b={0};assert(ninit(&a)==0 && ninit(&b)==0);
    assert((a.options&RES_USE_EDNS0) && !(a.options&RES_USE_DNSSEC));
    a.options&=~RES_USE_EDNS0;assert(b.options&RES_USE_EDNS0);
    assert(ninit(&a)==0 && (a.options&RES_USE_EDNS0));
    nclose(&a);nclose(&b);assert(unsetenv("RES_OPTIONS")==0);
    printf("PASS: independent EDNS initialization %s\n",option);cases++;
}
int main(int argc,char **argv) {
    assert(argc==2);
    const char *candidate=strcmp(argv[1],"--host")?argv[1]:NULL;
    void *handle=dlopen(candidate?candidate:"libc.so.6",RTLD_NOW|RTLD_LOCAL);assert(handle);
    ninit=(init_fn)symbol(handle,"__res_ninit",candidate);
    nclose=(close_fn)symbol(handle,"__res_nclose",candidate);
    nmkquery=(mk_fn)symbol(handle,"res_nmkquery",candidate);
    nquery=(query_fn)symbol(handle,"res_nquery",candidate);
    nquerydomain=(domain_fn)symbol(handle,"res_nquerydomain",candidate);
    nsearch=(query_fn)symbol(handle,"res_nsearch",candidate);
    nsend=(send_fn)symbol(handle,"res_nsend",candidate);
    const unsigned long modes[]={0,RES_USE_EDNS0,RES_USE_DNSSEC,RES_USE_EDNS0|RES_USE_DNSSEC|RES_TRUSTAD};
    const int capacities[]={12,512,900,1200,65535};
    for(size_t i=0;i<4;i++) for(size_t j=0;j<5;j++) run_case(modes[i],capacities[j],0);
    run_case(RES_USE_DNSSEC|RES_USEVC,12,0);
    run_case(RES_USE_DNSSEC,700,5);
    run_case(RES_USE_EDNS0,900,1);
    run_case(RES_USE_DNSSEC,900,2);
    run_case(RES_USE_EDNS0|RES_USE_DNSSEC|RES_TRUSTAD,512,3);
    run_case(RES_USE_DNSSEC,512,4);
    init_case("edns0 timeout:1 attempts:1");
    init_case("edns0:0 no-edns0");
    assert(cases==28);
    printf("%u %s EDNS resolver cases passed\n",cases,candidate?"candidate":"host-glibc");
}
