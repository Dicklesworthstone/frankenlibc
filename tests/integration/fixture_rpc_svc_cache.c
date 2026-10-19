/* Reuse the unchanged service fixture's glibc ABI shapes, wire oracles and
 * provider checks. Its original scenarios remain callable from the same binary. */
#define main rpc_svc_original_main
#include "fixture_rpc_svc.c"
#undef main
#include <limits.h>

static int (*enablecache)(Xprt *, unsigned long);
/* Public glibc LP64 XDR stream layout; x_private is the current buffer cursor. */
typedef struct {
    int op; const void *ops; char *public_data, *cursor, *base; unsigned remaining;
} CacheXdr;
_Static_assert(offsetof(CacheXdr,cursor)==24 && sizeof(CacheXdr)==48,"glibc XDR layout");
static int consume_decode(void *stream, void *value) {
    if (!xu32(stream,value)) return 0;
    CacheXdr *x=stream;
    if (x->op==1) memset(x->cursor-4,0,4);
    return 1;
}
static int fail_encoding(void *x, void *unused) {
    (void)unused;
    unsigned partial=123;
    CHECK(xu32(x,&partial));
    return 0;
}
static void cache_handler(Request *r, Xprt *x) {
    if (r->procedure==15) { ++calls; CHECK(!sendreply(x,fail_encoding,NULL)); }
    else if (r->procedure==16) {
        ++calls;unsigned value=0;CHECK(x->ops->getargs(x,consume_decode,&value));
        value+=7;CHECK(sendreply(x,xu32,&value));CHECK(x->ops->freeargs(x,xu32,&value));
    }
    else handler(r,x);
}
static void cache_error(unsigned xid) {
    unsigned char data[2048]; size_t n=request(data,xid,PROGRAM,1,3);
    send_packet(data,n);drive();expect_reply(xid,0,3,-1,0);
}
static void no_response(void) {
    struct pollfd p={client,POLLIN,0};CHECK(poll(&p,1,30)==0);
}
int main(int argc,char **argv) {
    CHECK(argc==2);
    if (strncmp(argv[1],"cache-",6)) return rpc_svc_original_main(argc,argv);
    scenario=argv[1];load();LOAD(enablecache,"svcudp_enablecache");
    server=bufcreate(-1,128,128);CHECK(server && server->ops);
    client=socket(AF_INET,SOCK_DGRAM,0);CHECK(client>=0);
    CHECK(reg(server,PROGRAM,1,cache_handler,0));
    if (!strcmp(scenario,"cache-limits")) {
        CHECK(!enablecache(server,0));CHECK(!enablecache(server,ULONG_MAX));
        CHECK(!enablecache(server,1024*1024));
    }
    unsigned long count=!strcmp(scenario,"cache-eviction")?2:4;
    CHECK(enablecache(server,count));
    if (!strcmp(scenario,"cache-basic")) {
        for (unsigned i=0;i<8;++i) {exchange(1,101);CHECK(calls==1);}
    } else if (!strcmp(scenario,"cache-input-snapshot")) {
        unsigned char data[2048];size_t n=request(data,101,PROGRAM,1,16);word(data,n,35);
        for(unsigned i=0;i<3;++i) {
            send_packet(data,n+4);drive();expect_reply(101,0,0,0,42);CHECK(calls==1);
        }
    } else if (!strcmp(scenario,"cache-peers")) {
        exchange(1,101);CHECK(calls==1);
        int first=client;client=socket(AF_INET,SOCK_DGRAM,0);CHECK(client>=0);
        exchange(1,101);CHECK(calls==2);CHECK(!close(client));client=first;
        exchange(1,101);CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-eviction")) {
        exchange(1,101);exchange(1,102);exchange(1,101);CHECK(calls==2);
        exchange(1,103);CHECK(calls==3);exchange(1,102);CHECK(calls==3);
        exchange(1,101);CHECK(calls==4);
    } else if (!strcmp(scenario,"cache-error")) {
        cache_error(101);cache_error(101);CHECK(calls==1);
        exchange(1,102);CHECK(calls==2);cache_error(101);CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-burst")) {
        unsigned char data[2048];size_t n=request(data,101,PROGRAM,1,1);word(data,n,35);
        send_packet(data,n+4);send_packet(data,n+4);word(data,0,102);send_packet(data,n+4);
        drive();expect_reply(101,0,0,0,42);expect_reply(101,0,0,0,42);expect_reply(102,0,0,0,42);
        CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-transport")) {
        transport();CHECK(calls==0);
        unsigned char data[2048];size_t n=request(data,22,PROGRAM,1,1);word(data,n,35);
        send_packet(data,n+4);struct pollfd p={server->fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
        unsigned long msg[12]={0};CHECK(!server->ops->recv(server,msg));
        expect_reply(22,0,0,0,42);CHECK(calls==0);
    } else if (!strcmp(scenario,"cache-failed-encode")) {
        unsigned char data[2048];size_t n=request(data,101,PROGRAM,1,15);
        for(unsigned i=1;i<=2;++i) {send_packet(data,n);drive();no_response();CHECK(calls==i);}
        exchange(1,102);CHECK(calls==3);
    } else if (!strcmp(scenario,"cache-body")) {
        exchange(1,101);CHECK(calls==1);
        unsigned char data[2048];size_t n=request(data,101,PROGRAM,1,1);word(data,n,41);
        send_packet(data,n+4);drive();expect_reply(101,0,0,0,48);CHECK(calls==2);
        exchange(1,101);CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-credentials")) {
        unsigned char data[2048];request(data,101,PROGRAM,1,0);word(data,24,1);word(data,28,32);
        unsigned body[]={1234,4,0x686f7374,1001,1002,2,11,12};
        for(unsigned i=0;i<8;++i)word(data,32+4*i,body[i]);
        word(data,64,0);word(data,68,0);
        send_packet(data,72);drive();expect_reply(101,0,0,-1,0);CHECK(calls==1);
        word(data,44,1003);send_packet(data,72);drive();expect_reply(101,0,0,-1,0);CHECK(calls==2);
        word(data,44,1001);send_packet(data,72);drive();expect_reply(101,0,0,-1,0);CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-generation")) {
        exchange(1,101);CHECK(calls==1);unreg(PROGRAM,1);
        CHECK(reg(server,PROGRAM,1,cache_handler,0));exchange(1,101);CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-limits")) {
        CHECK(!enablecache(server,2));exchange(1,101);exchange(1,101);CHECK(calls==1);
    } else if (!strcmp(scenario,"cache-destroy")) {
        exchange(1,101);int fd=server->fd;
        unsigned char data[2048];size_t n=request(data,102,PROGRAM,1,10);
        send_packet(data,n);drive();expect_reply(102,0,0,-1,0);server=NULL;
        CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);
    } else if (!strcmp(scenario,"cache-callback-exit")) {
        unsigned char data[2048];size_t n=request(data,101,PROGRAM,1,12);send_packet(data,n);
        struct pollfd p={server->fd,POLLIN,0};CHECK(poll(&p,1,1000)==1);
        pthread_t t;void *result;CHECK(!pthread_create(&t,NULL,serve_thread,NULL));CHECK(!pthread_join(t,&result));
        CHECK(result==(void *)19 && cleaned==1);expect_reply(101,0,0,-1,0);
        send_packet(data,n);drive();expect_reply(101,0,0,-1,0);CHECK(calls==1 && cleaned==1);
        exchange(1,102);CHECK(calls==2);
    } else if (!strcmp(scenario,"cache-oversized")) {
        exchange(1,101);
        unsigned char data[256]={0};size_t n=request(data,101,PROGRAM,1,1);word(data,n,35);
        send_packet(data,sizeof(data));drive();no_response();CHECK(calls==1);
        exchange(1,101);CHECK(calls==1);
    } else CHECK(0);
    unreg(PROGRAM,1);
    if(server) {int fd=server->fd;server->ops->destroy(server);CHECK(fcntl(fd,F_GETFD)==-1 && errno==EBADF);}
    CHECK(!close(client));printf("PASS %s\n",scenario);return 0;
}
