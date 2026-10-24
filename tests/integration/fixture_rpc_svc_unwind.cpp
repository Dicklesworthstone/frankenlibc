// Real C++ callbacks through the public glibc LP64 service interface.
// Every invocation is an isolated process; packets and expected replies are
// independent network-order words, not the candidate's serializer.
#include <arpa/inet.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstddef>
#include <cstdint>

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x); std::_Exit(1); } } while (0)
struct Auth { int flavor; char *base; unsigned length; };
struct Xprt;
using Proc = int (*)(void *, void *);
struct Ops {
    int (*recv)(Xprt *, void *); int (*stat)(Xprt *);
    int (*getargs)(Xprt *, Proc, void *); int (*reply)(Xprt *, void *);
    int (*freeargs)(Xprt *, Proc, void *); void (*destroy)(Xprt *);
};
struct Xprt {
    int fd; unsigned short port; const Ops *ops; int addrlen;
    sockaddr_in peer; Auth verifier; void *p1, *p2; char padding[256];
};
struct Request { unsigned long program, version, procedure; Auth cred; void *cooked; Xprt *x; };
static_assert(sizeof(Xprt)==336 && offsetof(Xprt,verifier)==40);
static_assert(sizeof(Request)==64 && sizeof(Auth)==24);
static Xprt *(*create)(int,unsigned,unsigned);
static int (*reg)(Xprt *,unsigned long,unsigned long,void (*)(Request *,Xprt *),int);
static void (*unreg)(unsigned long,unsigned long), (*common)(int);
static int (*sendreply)(Xprt *,Proc,void *), (*xu32)(void *,void *), (*enablecache)(Xprt *,unsigned long);
static Xprt *server;
static unsigned calls, destructors;
static bool armed = true;
static const char *scenario;
static bool stream_transport;
static constexpr unsigned PROGRAM = 0x31234767;
struct Marker { ~Marker() { ++destructors; } };
struct CallbackException {};
static void *symbol(const char *name) {
    void *p=dlsym(RTLD_DEFAULT,name);
    if (!p) p=dlvsym(RTLD_DEFAULT,name,"GLIBC_2.2.5");
    CHECK(p);
    const char *expected=std::getenv("FRANKENLIBC_TEST_LIBRARY");
    CHECK(expected);
    Dl_info info{}; struct stat a{},b{};
    CHECK(dladdr(p,&info) && !stat(info.dli_fname,&a) && !stat(expected,&b));
    if (a.st_dev!=b.st_dev || a.st_ino!=b.st_ino) {
        std::fputs("WRONG RPC SERVICE PROVIDER\n",stderr); std::_Exit(86);
    }
    return p;
}
#define LOAD(p,n) (p=reinterpret_cast<decltype(p)>(symbol(n)))
static bool is(const char *name) { return std::strcmp(scenario,name)==0; }
[[noreturn]] static void interrupt_callback() {
    if (std::strstr(scenario,"exit")) pthread_exit(reinterpret_cast<void *>(19));
    throw CallbackException{};
}
static int interrupted_codec(void *x, void *v) {
    Marker marker;
    // Exercise unwinding after the XDR stream has consumed a real word.
    CHECK(xu32(x,v));
    interrupt_callback();
}
static void handler(Request *r, Xprt *x) {
    Marker marker; ++calls;
    CHECK(r->program==PROGRAM && r->version==1 && r->procedure==1);
    if (armed && is("destroy-exit")) {
        x->ops->destroy(x); server=nullptr; interrupt_callback();
    }
    if (armed && is("dispatch-throw")) interrupt_callback();
    unsigned value=0;
    Proc decoder=armed && std::strstr(scenario,"decode") ? interrupted_codec : xu32;
    CHECK(x->ops->getargs(x,decoder,&value) && value==35); value+=7;
    Proc encoder=armed && std::strstr(scenario,"encode") ? interrupted_codec : xu32;
    CHECK(sendreply(x,encoder,&value));
    if (armed && is("dispatch-exit")) interrupt_callback();
    if (armed && is("free-throw")) {
        CHECK(x->ops->freeargs(x,interrupted_codec,&value));
    } else CHECK(x->ops->freeargs(x,xu32,&value));
}
static void *serve(void *arg) { common(*static_cast<int *>(arg)); return nullptr; }
static void ready(int fd, int timeout) {
    pollfd p{fd,POLLIN,0}; CHECK(poll(&p,1,timeout)==1 && (p.revents&POLLIN));
}
static void expect_reply(int client, unsigned xid) {
    ready(client,1000);
    std::uint32_t words[32]{};
    if(stream_transport) {
        std::uint32_t marker{};CHECK(recv(client,&marker,4,MSG_WAITALL)==4);
        CHECK(ntohl(marker)==(0x80000000u|28));CHECK(recv(client,words,28,MSG_WAITALL)==28);
    } else CHECK(recv(client,words,sizeof(words),0)==28);
    const unsigned expected[]={xid,1,0,0,0,0,42};
    for (unsigned i=0;i<7;++i) CHECK(ntohl(words[i])==expected[i]);
}
int main(int argc,char **argv) {
    CHECK(argc==2);bool local=std::strncmp(argv[1],"unix-",5)==0;
    stream_transport=local || std::strncmp(argv[1],"tcp-",4)==0;scenario=argv[1]+(local?5:stream_transport?4:0);
    if(local)LOAD(create,"svcunixfd_create");else if(stream_transport)LOAD(create,"svcfd_create");else LOAD(create,"svcudp_bufcreate");
    LOAD(reg,"svc_register"); LOAD(unreg,"svc_unregister");
    LOAD(common,"svc_getreq_common"); LOAD(sendreply,"svc_sendreply");
    LOAD(xu32,"xdr_u_int"); LOAD(enablecache,"svcudp_enablecache");
    int client;
    if(stream_transport) {
        int pair[2];CHECK(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));
        server=create(pair[0],128,128);client=pair[1];CHECK(server);
    } else { server=create(-1,128,128); CHECK(server && enablecache(server,4));client=socket(AF_INET,SOCK_DGRAM,0); }
    CHECK(reg(server,PROGRAM,1,handler,0));
    int fd=server->fd;CHECK(client>=0);
    sockaddr_in dest{}; dest.sin_family=AF_INET; dest.sin_port=htons(server->port);
    dest.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    unsigned words[]={101,0,2,PROGRAM,1,1,0,0,0,0,35};
    for (unsigned &w:words) w=htonl(w);
    auto send_request=[&]() {
        if(stream_transport) {
            std::uint32_t marker=htonl(0x80000000u|sizeof(words));
            CHECK(send(client,&marker,4,MSG_NOSIGNAL)==4 && send(client,words,sizeof(words),MSG_NOSIGNAL)==sizeof(words));
        } else CHECK(sendto(client,words,sizeof(words),0,reinterpret_cast<sockaddr *>(&dest),sizeof(dest))==sizeof(words));
        ready(fd,1000);
    };
    send_request();
    if (std::strstr(scenario,"exit")) {
        pthread_t thread; void *result=nullptr;
        CHECK(!pthread_create(&thread,nullptr,serve,&fd));
        CHECK(!pthread_join(thread,&result) && result==reinterpret_cast<void *>(19));
    } else {
        bool caught=false;
        try { common(fd); } catch (const CallbackException &) { caught=true; }
        CHECK(caught);
    }
    CHECK(calls==1);
    unsigned expected_dtors=std::strstr(scenario,"decode") || std::strstr(scenario,"encode") || is("free-throw") ? 2:1;
    CHECK(destructors==expected_dtors);
    if (is("destroy-exit")) {
        CHECK(fcntl(fd,F_GETFD)==-1); unreg(PROGRAM,1); CHECK(!close(client));
        std::printf("PASS %s\n",argv[1]); return 0;
    }
    bool replied=is("dispatch-exit") || is("free-throw");
    if (replied) expect_reply(client,101);
    else { pollfd p{client,POLLIN,0}; CHECK(poll(&p,1,20)==0); }
    armed=false;
    send_request(); common(fd); expect_reply(client,101);
    // A successful response survives a subsequent unwind. An incomplete
    // serialization must not populate the cache or suppress a fresh dispatch.
    CHECK(calls==(stream_transport?2u:replied?1u:2u));
    unsigned after=destructors;
    send_request(); common(fd); expect_reply(client,101); CHECK(destructors==after+(stream_transport?1u:0u));
    words[0]=htonl(102); send_request(); common(fd); expect_reply(client,102);
    CHECK(calls==(stream_transport?4u:replied?2u:3u));
    unreg(PROGRAM,1); server->ops->destroy(server); CHECK(fcntl(fd,F_GETFD)==-1);
    CHECK(!close(client)); std::printf("PASS %s\n",argv[1]);
}
