/* Reentrant resolver conformance: actual exported functions, loopback only.
 * cc -std=c11 -O2 -Wall -Wextra -Werror stateful_resolver_abi.c -pthread -lresolv -ldl -o stateful-resolver
 * timeout 40 ./stateful-resolver --host    (or an absolute candidate .so path)
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
#include <unistd.h>

typedef int (*init_fn)(res_state);
typedef void (*close_fn)(res_state);
typedef int (*mk_fn)(res_state,int,const char*,int,int,const unsigned char*,int,const unsigned char*,unsigned char*,int);
typedef int (*send_fn)(res_state,const unsigned char*,int,unsigned char*,int);
typedef int (*query_fn)(res_state,const char*,int,int,unsigned char*,int);
typedef int (*domain_fn)(res_state,const char*,const char*,int,int,unsigned char*,int);
static init_fn ninit;
static close_fn nclose;
static mk_fn nmkquery;
static send_fn nsend;
static query_fn nquery,nsearch;
static domain_fn nquerydomain;
static unsigned cases;
static void pass(const char *name) { printf("PASS: %s\n",name); cases++; }
static void *symbol(void *handle,const char *name,const char *candidate) {
 void *p=dlsym(handle,name); assert(p); Dl_info info; assert(dladdr(p,&info));
 if(candidate) { struct stat a,b; assert(stat(candidate,&a)==0);assert(stat(info.dli_fname,&b)==0);assert(a.st_dev==b.st_dev&&a.st_ino==b.st_ino); }
 else { assert(strstr(info.dli_fname,"libc.so")||strstr(info.dli_fname,"libresolv.so")); }
 return p;
}
static int bind_socket(int family,int tcp,struct sockaddr_storage *addr,socklen_t *len) {
 int fd=socket(family,tcp?SOCK_STREAM:SOCK_DGRAM,0);assert(fd>=0);
 memset(addr,0,sizeof(*addr));
 if(family==AF_INET) { struct sockaddr_in *a=(void*)addr; a->sin_family=AF_INET;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);*len=sizeof(*a); }
 else { struct sockaddr_in6 *a=(void*)addr;a->sin6_family=AF_INET6;a->sin6_addr=in6addr_loopback;*len=sizeof(*a); }
 assert(bind(fd,(void*)addr,*len)==0);assert(getsockname(fd,(void*)addr,len)==0);
 struct timeval t={.tv_sec=4};assert(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t))==0);assert(setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t))==0);
 if(tcp) assert(listen(fd,1)==0);
 return fd;
}
static void configure(res_state s,struct sockaddr_storage *addr,int tcp) {
 memset(s,0,sizeof(*s));s->options=RES_INIT|RES_RECURSE|RES_DEFNAMES|RES_DNSRCH|(tcp?RES_USEVC:0);s->retrans=1;s->retry=1;s->nscount=1;s->ndots=1;s->_vcsock=-1;
 if(addr->ss_family==AF_INET) memcpy(&s->nsaddr_list[0],addr,sizeof(struct sockaddr_in));
 else { s->_u._ext.nsaddrs[0]=(void*)addr;s->_u._ext.nscount6=1; }
}
static const unsigned char wire[]={0x31,0x29,1,0,0,1,0,0,0,0,0,0,7,'e','x','a','m','p','l','e',4,'t','e','s','t',0,0,1,0,1};
struct server { int fd,tcp,tc,code,marker,number;const char *names[4]; int codes[4]; };
static void full_read(int fd,void *p,size_t n) { unsigned char *b=p;while(n){ssize_t k=read(fd,b,n);assert(k>0);b+=k;n-=(size_t)k;} }
static void full_write(int fd,const void *p,size_t n) { const unsigned char *b=p;while(n){ssize_t k=write(fd,b,n);assert(k>0);b+=k;n-=(size_t)k;} }
static void *serve(void *p) {
 struct server *s=p;
 for(int i=0;i<s->number;i++) {
  unsigned char b[2048];struct sockaddr_storage peer;socklen_t len=sizeof(peer);int connection=-1;size_t n;
  if(s->tcp){ connection=accept(s->fd,NULL,NULL);assert(connection>=0);struct timeval t={.tv_sec=4};assert(setsockopt(connection,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t))==0);unsigned char prefix[2];full_read(connection,prefix,2);n=((size_t)prefix[0]<<8)|prefix[1];assert(n>=17&&n<sizeof(b)-16);full_read(connection,b,n); }
  else {ssize_t k=recvfrom(s->fd,b,sizeof(b)-16,0,(void*)&peer,&len);assert(k>=17);n=(size_t)k;}
  if(s->names[i]){char name[1025];assert(dn_expand(b,b+n,b+12,name,sizeof(name))>=0);assert(strcmp(name,s->names[i])==0);}
  int code=s->names[i]?s->codes[i]:s->code;
  b[2]|=0x80|(s->tc?2:0);b[3]=0xa0|(unsigned char)code;memset(b+6,0,6);
  if(code==0&&s->marker&&!s->tc){b[7]=1;unsigned char rr[]={0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,(unsigned char)s->marker};memcpy(b+n,rr,sizeof(rr));n+=sizeof(rr);}
  if(s->tcp){unsigned char prefix[]={(unsigned char)(n>>8),(unsigned char)n};full_write(connection,prefix,2);full_write(connection,b,n);assert(close(connection)==0);}
  else assert(sendto(s->fd,b,n,0,(void*)&peer,len)==(ssize_t)n);
 }
 return NULL;
}
static void init_case(void){
 struct __res_state a={0},b={0};assert(setenv("LOCALDOMAIN","alpha.test beta.test",1)==0);assert(setenv("RES_OPTIONS","ndots:3 timeout:2 attempts:2",1)==0);
 assert(ninit(&a)==0);assert((a.options&RES_INIT)!=0);assert(a.ndots==3&&a.retrans==2&&a.retry==2);assert(a.nscount>=1&&a.nscount<=3);assert(strcmp(a.dnsrch[0],"alpha.test")==0);assert(strcmp(a.dnsrch[1],"beta.test")==0);
 assert(ninit(&b)==0);assert(strcmp(b.dnsrch[0],"alpha.test")==0);b.dnsrch[0]="other.test";b.ndots=1;
 assert(strcmp(a.dnsrch[0],"alpha.test")==0);assert(strcmp(b.dnsrch[0],"other.test")==0);assert(a.dnsrch[0]!=b.dnsrch[0]);assert(a.ndots==3&&b.ndots==1);
 nclose(&a);nclose(&b);assert(unsetenv("LOCALDOMAIN")==0);assert(unsetenv("RES_OPTIONS")==0);pass("independent initialization and caller overrides");
}
static void mk_cases(void){
 struct __res_state s={0};unsigned char b[512];
 for(int i=0;i<4;i++){s.options=(i&1?RES_RECURSE:0)|(i&2?RES_TRUSTAD:0);memset(b,0xa5,sizeof(b));int n=nmkquery(&s,0,"example.test",3,16,NULL,0,NULL,b,sizeof(b));assert(n==30);assert((((unsigned)b[2]<<8)|b[3])==(unsigned)((i&1?0x100:0)|(i&2?0x20:0)));assert(b[26]==0&&b[27]==16&&b[28]==0&&b[29]==3&&b[30]==0xa5);unsigned short id;memcpy(&id,b,2);assert(s.id==id);assert(!(s.options&RES_INIT));pass("per-state RD/AD, class/type, and transaction ID");}
 s.options=RES_RECURSE;int n=nmkquery(&s,4,"example.test",1,6,(const unsigned char*)"edge.test",0,NULL,b,sizeof(b));assert(n==47&&b[2]==0x21&&b[11]==1);pass("NOTIFY optional completion record");
}
static void send_case(int family,int tcp,int tc,int reuse,int fallback){
 struct sockaddr_storage addr,dead;socklen_t len,deadlen;struct server server={.tcp=tcp,.tc=tc,.marker=42,.number=1};server.fd=bind_socket(family,tcp,&addr,&len);
 struct __res_state state;configure(&state,&addr,tcp);if(tc)state.options|=RES_IGNTC;
 if(fallback){int fd=bind_socket(AF_INET,0,&dead,&deadlen);assert(close(fd)==0);state.nsaddr_list[1]=state.nsaddr_list[0];memcpy(&state.nsaddr_list[0],&dead,sizeof(struct sockaddr_in));state.nscount=2;}
 pthread_t worker;assert(pthread_create(&worker,NULL,serve,&server)==0);
 unsigned char output[514];memset(output,0xa5,sizeof(output));if(reuse)memcpy(output+1,wire,sizeof(wire));int cap=tcp?12:512;
 int n=nsend(&state,reuse?output+1:wire,sizeof(wire),output+1,cap);assert(n==(int)sizeof(wire)+(tc?0:16));assert(output[0]==0xa5&&output[513]==0xa5);
 assert(((output[3]&2)!=0)==(tcp||tc));
 if(!tcp&&!tc){assert(output[1+n-1]==42);assert(!(output[4]&0x20));}
 assert(pthread_join(worker,NULL)==0);assert(close(server.fd)==0);
 /* nsaddrs is explicitly borrowed stack storage in this IPv6 fixture. */
 if(family==AF_INET6)state._u._ext.nsaddrs[0]=NULL;
 nclose(&state);pass(fallback?"refused primary selects caller fallback":family==AF_INET6?"caller IPv6 server and port":reuse?"shared query/answer buffer":tcp?"caller forced TCP, full return length and TC":tc?"caller ignore-truncation flag":"caller IPv4 server and nondefault port");
}
static void query_case(int code,int marker,int host_error){
 struct sockaddr_storage addr;socklen_t len;struct server s={.code=code,.marker=marker,.number=1};s.fd=bind_socket(AF_INET,0,&addr,&len);struct __res_state state;configure(&state,&addr,0);state.res_h_errno=99;
 pthread_t thread;assert(pthread_create(&thread,NULL,serve,&s)==0);unsigned char b[512];memset(b,0xa5,sizeof(b));int n=nquery(&state,"example.test",1,1,b,sizeof(b));assert((n>0)==(host_error==0));assert(state.res_h_errno==(host_error==0?99:host_error));assert((b[2]&0x80)&&((b[3]&15)==code));assert(pthread_join(thread,NULL)==0);assert(close(s.fd)==0);nclose(&state);pass("query packet and per-state positive/NXDOMAIN/NODATA status");
}
static void search_case(int failure,int absolute,int flags_off){
 struct sockaddr_storage addr;socklen_t len;struct server s={.marker=7,.number=absolute||flags_off?1:2};s.fd=bind_socket(AF_INET,0,&addr,&len);struct __res_state state;configure(&state,&addr,0);state.dnsrch[0]="first.test";state.dnsrch[1]="second.test";
 if(flags_off)state.options&=~(RES_DEFNAMES|RES_DNSRCH);
 s.names[0]=absolute?"host.test":flags_off?"host":"host.first.test";s.codes[0]=absolute||flags_off?0:failure;s.names[1]="host.second.test";
 pthread_t thread;assert(pthread_create(&thread,NULL,serve,&s)==0);unsigned char b[512];int n=nsearch(&state,absolute?"host.test.":"host",1,1,b,sizeof(b));assert(n>0);assert(state.res_h_errno==(absolute||flags_off?HOST_NOT_FOUND:failure==2?TRY_AGAIN:HOST_NOT_FOUND));assert(pthread_join(thread,NULL)==0);assert(close(s.fd)==0);nclose(&state);pass(absolute?"absolute name bypasses search":flags_off?"disabled search flags use bare name":failure==2?"search advances after SERVFAIL":"caller suffix order after NXDOMAIN");
}
static void domain_case(void){
 struct sockaddr_storage addr;socklen_t len;struct server s={.marker=7,.number=1,.names={"host.suffix.test"}};s.fd=bind_socket(AF_INET,0,&addr,&len);struct __res_state state;configure(&state,&addr,0);pthread_t thread;assert(pthread_create(&thread,NULL,serve,&s)==0);unsigned char b[512];assert(nquerydomain(&state,"host","suffix.test",1,1,b,sizeof(b))>0);assert(pthread_join(thread,NULL)==0);assert(close(s.fd)==0);nclose(&state);pass("querydomain honors caller server and exact suffix");
}
int main(int argc,char **argv){
 assert(argc==2);const char *candidate=strcmp(argv[1],"--host")?argv[1]:NULL;void *handle=dlopen(candidate?candidate:"libc.so.6",RTLD_NOW|RTLD_LOCAL);assert(handle);
 ninit=(init_fn)symbol(handle,"__res_ninit",candidate);nclose=(close_fn)symbol(handle,"__res_nclose",candidate);nmkquery=(mk_fn)symbol(handle,"res_nmkquery",candidate);nsend=(send_fn)symbol(handle,"res_nsend",candidate);nquery=(query_fn)symbol(handle,"res_nquery",candidate);nsearch=(query_fn)symbol(handle,"res_nsearch",candidate);nquerydomain=(domain_fn)symbol(handle,"res_nquerydomain",candidate);
 init_case();mk_cases();send_case(AF_INET,0,0,0,0);send_case(AF_INET,1,0,0,0);send_case(AF_INET,0,1,0,0);send_case(AF_INET,0,0,1,0);send_case(AF_INET,0,0,0,1);send_case(AF_INET6,0,0,0,0);
 query_case(0,7,0);query_case(3,0,HOST_NOT_FOUND);query_case(0,0,NO_DATA);domain_case();search_case(3,0,0);search_case(2,0,0);search_case(0,1,0);search_case(0,0,1);
 printf("%u %s stateful resolver cases passed\n",cases,candidate?"candidate":"host-glibc");
}
