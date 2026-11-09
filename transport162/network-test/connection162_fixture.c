#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Executes actual Connection/socket constructors and relay coroutines. The
 * public UDP endpoints are loopback NAT facades; no public relay is contacted. */
static unsigned char *dll;
static volatile LONG blocked,build_requested,built,proxy_stop;
static volatile unsigned natneg_port,natneg_ip;
static void *context,*executor,*conn[2];
static SOCKET game[2],face[2],relay_sink;
static volatile LONG probe_replies[2];
static int expect_idle,expect_endpoint;
static void *extra_connection,*previous_extra_connection;
static volatile LONG action_completed;
static unsigned churn_current_rva,churn_endpoint_rva,churn_state_bytes;
static volatile LONG churn_passed;
static volatile LONG tiny_continues[2];
static void *tiny_continue_tramp;
static int registry_churn(void);
static struct sockaddr_in game_ep[2],face_ep[2],remote_ep[2],local_ep[2];
static unsigned packets_to_game[2],packets_to_peer[2];
typedef struct Bytes28 {unsigned char b[28];} Bytes28;
typedef struct Sock44 {unsigned char b[44];} Sock44;
typedef struct Vec {void *begin,*end,*capacity;} Vec;
static void (__cdecl *original_spawn)(void *,void *,void *,unsigned);
static void *(__fastcall *original_socket)(void *,void *,unsigned,void *);

static void jump_to(void *from,void *to) {
 DWORD old;VirtualProtect(from,5,PAGE_EXECUTE_READWRITE,&old);
 *(unsigned char *)from=0xe9;*(int *)((unsigned char *)from+1)=(unsigned char *)to-((unsigned char *)from+5);
 VirtualProtect(from,5,old,&old);FlushInstructionCache(GetCurrentProcess(),from,5);
}
static void *trampoline(unsigned rva,void *hook) {
 unsigned char *p=VirtualAlloc(0,32,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 if(!p || memcmp(dll+rva,"\x55\x8b\xec\x6a\xff",5)){printf("bad_trampoline %x\n",rva);ExitProcess(40);}
 memcpy(p,dll+rva,5);p[5]=0xe9;*(int *)(p+6)=dll+rva+5-(p+10);jump_to(dll+rva,hook);return p;
}
static void iat(unsigned rva,void *fn) {DWORD old;VirtualProtect(dll+rva,4,PAGE_READWRITE,&old);*(void **)(dll+rva)=fn;VirtualProtect(dll+rva,4,old,&old);}
static void __cdecl spawn_hook(void *ctx,void *fn,void *token,unsigned unused) {
 if(!context)context=ctx;original_spawn(ctx,fn,token,unused);
}
static void *__fastcall socket_hook(void *object,void *unused,unsigned zero,void *ex) {
 (void)unused;void *r=original_socket(object,0,zero,ex);if(!executor)executor=(unsigned char *)object+16;return r;
}
static void __cdecl logger(const char *s,unsigned n) {
 if(n && n<512 && !memchr(s,0,n))printf("dll: %.*s\n",(int)n,s);
}
static void *__cdecl identity(void **out) {out[0]="loopback-fixture";out[1]=(void *)16;return out;}
static unsigned __cdecl zero(void) {return 0;}
static LONG CALLBACK exception_log(PEXCEPTION_POINTERS e) {
 printf("exception=%08lx pc=%p rva=%08lx\n",e->ExceptionRecord->ExceptionCode,e->ExceptionRecord->ExceptionAddress,(unsigned char *)e->ExceptionRecord->ExceptionAddress-dll);return EXCEPTION_CONTINUE_SEARCH;
}
static int allowed(const struct sockaddr *a) {return a&&a->sa_family==AF_INET&&((unsigned char *)&((struct sockaddr_in *)a)->sin_addr)[0]==127;}
static int WSAAPI deny_dns(PCSTR a,PCSTR b,const ADDRINFOA *c,PADDRINFOA *out) {(void)a;(void)b;(void)c;*out=0;InterlockedIncrement(&blocked);return WSAHOST_NOT_FOUND;}
static int WSAAPI connect_hook(SOCKET s,const struct sockaddr *a,int n) {if(allowed(a))return connect(s,a,n);InterlockedIncrement(&blocked);WSASetLastError(WSAENETUNREACH);return SOCKET_ERROR;}
static int WSAAPI bind_hook(SOCKET s,const struct sockaddr *a,int n) {
 int r=bind(s,a,n),type=0,sz=sizeof type;struct sockaddr_in v={0};int len=sizeof v;getsockopt(s,SOL_SOCKET,SO_TYPE,(char *)&type,&sz);
 if(!r&&type==SOCK_DGRAM&&!natneg_port&&!getsockname(s,(struct sockaddr *)&v,&len)){natneg_port=ntohs(v.sin_port);natneg_ip=v.sin_addr.s_addr;}
 return r;
}
static Bytes28 ep28(const struct sockaddr_in *ep) {Bytes28 b={0};memcpy(b.b,ep,sizeof *ep);return b;}
static void *alloc_dll(unsigned bytes) {return ((void *(__cdecl *)(unsigned))(dll+0x1c60a4))(bytes);}
typedef void *(__cdecl *Factory)(void **);
static void *__cdecl remote0(void **out) {return ((void *(__fastcall *)(void *,void *,void **))(dll+0x10b670))(conn[0],0,out);}
static void *__cdecl remote1(void **out) {return ((void *(__fastcall *)(void *,void *,void **))(dll+0x10b670))(conn[1],0,out);}
static void *__cdecl local0(void **out) {return ((void *(__fastcall *)(void *,void *,void **))(dll+0x109ee0))(conn[0],0,out);}
static void *__cdecl local1(void **out) {return ((void *(__fastcall *)(void *,void *,void **))(dll+0x109ee0))(conn[1],0,out);}
static void *__cdecl speed0(void **out) {return ((void *(__fastcall *)(void *,void *,void **))(dll+0x108d30))(conn[0],0,out);}
static void *__cdecl speed1(void **out) {return ((void *(__fastcall *)(void *,void *,void **))(dll+0x108d30))(conn[1],0,out);}
static void build_connections(void) {
 typedef void *(__fastcall *SocketCtor)(void *,void *,void *,const Bytes28 *);
 typedef void *(__fastcall *Ctor)(void *,void *,unsigned,Bytes28,Bytes28,Vec,Vec,Sock44,Sock44);
 SocketCtor socket_ctor=(SocketCtor)(dll+0xff0d0);Ctor ctor=(Ctor)(dll+0xffab0);
 for(unsigned i=0;i<2;i++) {
  Sock44 local={0},remote={0};struct sockaddr_in bindep={0};bindep.sin_family=AF_INET;bindep.sin_addr.s_addr=htonl(INADDR_LOOPBACK);Bytes28 endpoint=ep28(&bindep);
  socket_ctor(&local,0,executor,&endpoint);socket_ctor(&remote,0,executor,&endpoint);
  int len=sizeof bindep;getsockname(*(SOCKET *)(local.b+4),(struct sockaddr *)&local_ep[i],&len);len=sizeof bindep;getsockname(*(SOCKET *)(remote.b+4),(struct sockaddr *)&remote_ep[i],&len);
  Bytes28 *ips=alloc_dll(28);memset(ips,0,28);*(unsigned *)(ips->b+4)=inet_addr("127.0.0.3");
  unsigned short *tokens=alloc_dll(2);*tokens=0x1357;Vec iv={ips,ips+1,ips+1},tv={tokens,tokens+1,tokens+1};
  conn[i]=VirtualAlloc(0,0x5000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
  ctor(conn[i],0,0x1600+i,ep28(&game_ep[i]),ep28(&face_ep[1-i]),iv,tv,local,remote);
  printf("connection=%u local=%u remote=%u game=%u peer=%u\n",i,ntohs(local_ep[i].sin_port),ntohs(remote_ep[i].sin_port),ntohs(game_ep[i].sin_port),ntohs(face_ep[1-i].sin_port));
 }
 Factory rf[2]={remote0,remote1},lf[2]={local0,local1};
 for(unsigned i=0;i<2;i++){original_spawn(context,rf[i],dll+0x22f43e,0);original_spawn(context,lf[i],dll+0x22f43e,0);/* speed refresh depends on live provider configuration; omitted here. */}
 InterlockedExchange(&built,1);
}

static void extra_lifecycle(int destroy) {
 if(destroy) {
  if(extra_connection) {((void(__fastcall *)(void *,void *))(dll+0x100a80))(extra_connection,0);VirtualFree(extra_connection,0,MEM_RELEASE);extra_connection=0;}
  return;
 }
 typedef void *(__fastcall *SocketCtor)(void *,void *,void *,const Bytes28 *);
 typedef void *(__fastcall *Ctor)(void *,void *,unsigned,Bytes28,Bytes28,Vec,Vec,Sock44,Sock44);
 SocketCtor socket_ctor=(SocketCtor)(dll+0xff0d0);Ctor ctor=(Ctor)(dll+0xffab0);
 Sock44 local={0},remote={0};struct sockaddr_in bindep={0};bindep.sin_family=AF_INET;bindep.sin_addr.s_addr=htonl(INADDR_LOOPBACK);Bytes28 endpoint=ep28(&bindep);
 socket_ctor(&local,0,executor,&endpoint);socket_ctor(&remote,0,executor,&endpoint);
 Bytes28 *ips=alloc_dll(28);memset(ips,0,28);*(unsigned *)(ips->b+4)=inet_addr("127.0.0.3");
 unsigned short *tokens=alloc_dll(2);*tokens=0x1357;Vec iv={ips,ips+1,ips+1},tv={tokens,tokens+1,tokens+1};
 extra_connection=VirtualAlloc(0,0x5000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 ctor(extra_connection,0,0x1600,ep28(&game_ep[0]),ep28(&face_ep[1]),iv,tv,local,remote);
}


static unsigned char *find_cache(unsigned sid) {
 unsigned char *node=*(unsigned char **)(dll+0x2f03f8);
 for(unsigned n=0;node&&n<4096;n++,node=*(unsigned char **)node)if(*(unsigned *)(node+4)==sid)return node+4;
 return 0;
}
static unsigned extra_port(void) {
 if(!extra_connection)return 0;struct sockaddr_in ep={0};int len=sizeof ep;
 if(getsockname(*(SOCKET *)((unsigned char *)extra_connection+0x2160),(struct sockaddr *)&ep,&len))return 0;
 return ntohs(ep.sin_port);
}
static void seed_extra_port(void) {
 unsigned char *entry=((unsigned char *(__cdecl *)(unsigned))(dll+0x10bd10))(0x1600);
 *(unsigned short *)(entry+0x24)=(unsigned short)extra_port();entry[0x26]=0;
}


static void __cdecl observe_tiny_continue(void *frame,unsigned bytes) {
 if(bytes<2&&*(void **)((unsigned char *)frame+0x24)==conn[0])InterlockedIncrement(&tiny_continues[bytes]);
}
__declspec(naked) static void tiny_continue_hook(void) {
 __asm {
  pushfd
  pushad
  push dword ptr [ebp-0xc8]
  push esi
  call observe_tiny_continue
  add esp,8
  popad
  popfd
  jmp dword ptr [tiny_continue_tramp]
 }
}
static int install_tiny_observer(void) {
 const unsigned rva=0x10b1d9;unsigned char *at=dll+rva;
 if(memcmp(at,"\xc7\x45\xfc\x01\x00\x00\x00",7))return 0;
 unsigned char *tramp=VirtualAlloc(0,32,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);if(!tramp)return 0;
 memcpy(tramp,at,7);tramp[7]=0xe9;*(int *)(tramp+8)=at+7-(tramp+12);tiny_continue_tramp=tramp;
 jump_to(at,tiny_continue_hook);return 1;
}

static void maybe_build(const char *b,int n) {
 if(n!=21||(unsigned char)b[7]!=1)return;
 LONG action=InterlockedExchange(&build_requested,0);
 if(action==1)build_connections();
 else if(action==2)for(unsigned i=0;i<2;i++)*((volatile unsigned char *)conn[i]+0x2117)=0;
 else if(action==3)extra_lifecycle(0);
 else if(action==4)extra_lifecycle(1);
 else if(action==5)seed_extra_port();
 else if(action==6){previous_extra_connection=extra_connection;extra_connection=0;extra_lifecycle(0);}
 else if(action==7){if(previous_extra_connection){((void(__fastcall *)(void *,void *))(dll+0x100a80))(previous_extra_connection,0);VirtualFree(previous_extra_connection,0,MEM_RELEASE);previous_extra_connection=0;}}
 else if(action==8)InterlockedExchange(&churn_passed,registry_churn());
 else if(action==9){for(unsigned i=0;i<2;i++){*((volatile unsigned char *)conn[i]+0x2116)=0;*((volatile unsigned char *)conn[i]+0x2117)=0;}}
 if(action>=3)InterlockedExchange(&action_completed,action);
}
static void count_probe(SOCKET s,const char *b,int n) {
 const char *m="HakureiReimuAliceMargatroid";
 for(unsigned start=0;start<=4;start+=2)if(n>=(int)start+32&&!memcmp(b+start,m,27)&&b[start+29]==1)for(unsigned i=0;i<2;i++)if(conn[i]&&s==*(SOCKET *)((unsigned char *)conn[i]+0x218c))InterlockedIncrement(&probe_replies[i]);
}
static int WSAAPI sendto_hook(SOCKET s,const char *b,int n,int f,const struct sockaddr *a,int z) {
 maybe_build(b,n);count_probe(s,b,n);if(allowed(a))return sendto(s,b,n,f,a,z);InterlockedIncrement(&blocked);WSASetLastError(WSAENETUNREACH);return SOCKET_ERROR;
}
static int WSAAPI wsasendto_hook(SOCKET s,LPWSABUF b,DWORD count,LPDWORD sent,DWORD flags,const struct sockaddr *a,int z,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE cb) {
 if(count==1){maybe_build(b[0].buf,b[0].len);count_probe(s,b[0].buf,b[0].len);}if(allowed(a))return WSASendTo(s,b,count,sent,flags,a,z,ov,cb);InterlockedIncrement(&blocked);WSASetLastError(WSAENETUNREACH);return SOCKET_ERROR;
}
static DWORD WINAPI relay_thread(void *x) {(void)x;((void(__cdecl *)(void))(dll+0x102740))();return 0;}
static SOCKET udp(const char *ip,struct sockaddr_in *ep) {
 SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);memset(ep,0,sizeof *ep);ep->sin_family=AF_INET;ep->sin_addr.s_addr=inet_addr(ip);
 if(bind(s,(struct sockaddr *)ep,sizeof *ep)){printf("bindfixture=%d\n",WSAGetLastError());ExitProcess(50);}int len=sizeof *ep;getsockname(s,(struct sockaddr *)ep,&len);return s;
}
static DWORD WINAPI proxy_thread(void *unused) {
 (void)unused;char b[65536];
 while(!proxy_stop) {
  SOCKET a=face[0],c=face[1];fd_set f;FD_ZERO(&f);FD_SET(a,&f);FD_SET(c,&f);struct timeval timeout={0,20000};
  int ready=select(0,&f,0,0,&timeout);if(ready<=0)continue;
  for(unsigned i=0;i<2;i++) {SOCKET in=i?c:a;if(!FD_ISSET(in,&f))continue;int n=recvfrom(in,b,sizeof b,0,0,0);if(n<1)continue;
   /* datagram for virtualpeer i goes to actualConnection i, with virtual
    * sourceaddress of the otherpeer. Bothhops are real loopback UDP. */
   SOCKET out=face[1-i];sendto(out,b,n,0,(struct sockaddr *)&remote_ep[i],sizeof remote_ep[i]);InterlockedIncrement((LONG *)&packets_to_peer[i]);
  }
 }
 return 0;
}
static int exchange_raw(unsigned from,const unsigned char *msg,unsigned bytes) {
 unsigned char got[512];
 if(sendto(game[from],(const char *)msg,bytes,0,(struct sockaddr *)&local_ep[from],sizeof local_ep[from])!=(int)bytes)return 0;
 fd_set f;FD_ZERO(&f);FD_SET(game[1-from],&f);struct timeval t={2,0};if(select(0,&f,0,0,&t)!=1)return 0;
 int n=recvfrom(game[1-from],(char *)got,sizeof got,0,0,0);if(n==(int)bytes&&!memcmp(msg,got,bytes)){packets_to_game[1-from]++;return 1;}
 printf("payload_mismatch from=%u n=%d\n",from,n);return 0;
}
static int exchange(unsigned from,unsigned seq) {
 unsigned char msg[64];memset(msg,0x20+from,sizeof msg);memcpy(msg,"CONNECTION-FIXTURE",18);memcpy(msg+24,&seq,4);msg[28]=(unsigned char)from;
 return exchange_raw(from,msg,sizeof msg);
}

static int register_seq0(SOCKET sock,unsigned sid,const struct sockaddr_in *natneg) {
 unsigned char p[21]={0xfd,0xfc,0x1e,0x66,0x6a,0xb2,3,0,0,0,0,0,0,0,0,127,0,0,1,0,0},ack[64];memcpy(p+8,&sid,4);
 for(unsigned stage=0;stage<2;stage++) {
  p[12]=stage?2:0;
  if(sendto(sock,(const char *)p,21,0,(const struct sockaddr *)natneg,sizeof *natneg)!=21)return 0;
  fd_set f;FD_ZERO(&f);FD_SET(sock,&f);struct timeval wait={2,0};if(select(0,&f,0,0,&wait)!=1)return 0;
  if(recvfrom(sock,(char *)ack,sizeof ack,0,0,0)!=21||ack[7]!=1)return 0;
 }
 return 1;
}
static int control_action(LONG action,const struct sockaddr_in *natneg) {
 unsigned char p[21]={0xfd,0xfc,0x1e,0x66,0x6a,0xb2,3,0,0,0,0,0,2,0,0,127,0,0,1,0,0},ack[64];
 InterlockedExchange(&action_completed,0);InterlockedExchange(&build_requested,action);
 if(sendto(game[0],(const char *)p,21,0,(const struct sockaddr *)natneg,sizeof *natneg)!=21)return 0;
 fd_set f;FD_ZERO(&f);FD_SET(game[0],&f);struct timeval wait={2,0};if(select(0,&f,0,0,&wait)!=1||recvfrom(game[0],(char *)ack,sizeof ack,0,0,0)!=21)return 0;
 for(unsigned i=0;i<100&&!action_completed;i++)Sleep(5);
 return action_completed==action;
}
static int local_roundtrip(SOCKET outgoing,SOCKET expected,SOCKET forbidden,const char *tag) {
 unsigned char payload[64],reply[64],got[64];memset(payload,0x4a,sizeof payload);strncpy((char *)payload,tag,30);
 memset(reply,0x62,sizeof reply);memcpy(reply,"REPLY-ENDPOINT-162",18);
 if(sendto(outgoing,(const char *)payload,sizeof payload,0,(struct sockaddr *)&local_ep[0],sizeof local_ep[0])!=sizeof payload)return 0;
 fd_set f;FD_ZERO(&f);FD_SET(game[1],&f);struct timeval wait={2,0};if(select(0,&f,0,0,&wait)!=1)return 0;
 if(recvfrom(game[1],(char *)got,sizeof got,0,0,0)!=sizeof payload||memcmp(got,payload,sizeof payload))return 0;
 if(sendto(game[1],(const char *)reply,sizeof reply,0,(struct sockaddr *)&local_ep[1],sizeof local_ep[1])!=sizeof reply)return 0;
 FD_ZERO(&f);FD_SET(expected,&f);FD_SET(forbidden,&f);wait.tv_sec=2;wait.tv_usec=0;if(select(0,&f,0,0,&wait)<1)return 0;
 int yes=FD_ISSET(expected,&f),no=FD_ISSET(forbidden,&f);
 if(yes && (recvfrom(expected,(char *)got,sizeof got,0,0,0)!=sizeof reply||memcmp(got,reply,sizeof reply)))return 0;
 FD_ZERO(&f);FD_SET(forbidden,&f);wait.tv_sec=0;wait.tv_usec=30000;int extra=select(0,&f,0,0,&wait);if(extra>0)no=1;
 printf("endpoint162_case=%s expected_destination=%d forbidden_destination=%d\n",tag,yes,no);
 return yes&&!no;
}

static unsigned request_ready_port(SOCKET sock,unsigned sid,const struct sockaddr_in *natneg) {
 unsigned char p[21]={0xfd,0xfc,0x1e,0x66,0x6a,0xb2,3,0,0,0,0,0,1,0,0,127,0,0,1,0,0},reply[64];memcpy(p+8,&sid,4);
 if(sendto(sock,(const char *)p,21,0,(const struct sockaddr *)natneg,sizeof *natneg)!=21)return 0;
 unsigned port=0,ack=0;
 for(unsigned i=0;i<2;i++) {
  fd_set f;FD_ZERO(&f);FD_SET(sock,&f);struct timeval wait={3,0};if(select(0,&f,0,0,&wait)!=1)return 0;
  int n=recvfrom(sock,(char *)reply,sizeof reply,0,0,0);
  if(n==21&&reply[7]==1)ack++;
  else if(n==20&&reply[7]==5&&!memcmp(reply+8,&sid,4)&&!memcmp(reply+12,"\x7f\x00\x00\x01",4))port=((unsigned)reply[16]<<8)|reply[17];
  else return 0;
 }
 return ack==1?port:0;
}

static int late_ctor_receive(SOCKET fresh) {
 unsigned char reply[64],got[64];memset(reply,0x62,sizeof reply);memcpy(reply,"CTOR-CACHE-ENDPOINT",20);
 if(sendto(game[1],(const char *)reply,sizeof reply,0,(struct sockaddr *)&local_ep[1],sizeof local_ep[1])!=sizeof reply)return 0;
 SOCKET expected=expect_endpoint?fresh:game[0],forbidden=expect_endpoint?game[0]:fresh;
 fd_set f;FD_ZERO(&f);FD_SET(expected,&f);FD_SET(forbidden,&f);struct timeval wait={2,0};if(select(0,&f,0,0,&wait)<1)return 0;
 int yes=FD_ISSET(expected,&f),no=FD_ISSET(forbidden,&f);if(!yes)return 0;
 if(recvfrom(expected,(char *)got,sizeof got,0,0,0)!=sizeof reply||memcmp(got,reply,sizeof reply))return 0;
 printf("endpoint162_late_ctor expected_fresh=%d expected_destination=%d forbidden_destination=%d\n",expect_endpoint,yes,no);return !no;
}

#define CHECK(x) do{if(!(x)){printf("FAIL line=%u %s error=%d\n",__LINE__,#x,WSAGetLastError());return 40;}}while(0)

#define CHURN(x) do{if(!(x)){printf("FAIL churn line=%u %s error=%d\n",__LINE__,#x,WSAGetLastError());return 0;}}while(0)
static unsigned registry_count(void) {
 unsigned count=0;unsigned char *records=dll+0x2f5500+1072;
 for(unsigned i=0;i<64;i++)if(*(void **)(records+i*24))count++;
 return count;
}
static int registry_churn(void) {
 typedef int (__cdecl *Current)(unsigned char *,void *,unsigned);
 typedef void (__cdecl *Endpoint)(unsigned char *,void *,unsigned);
 typedef void *(__fastcall *SocketCtor)(void *,void *,void *,const Bytes28 *);
 typedef void *(__fastcall *Ctor)(void *,void *,unsigned,Bytes28,Bytes28,Vec,Vec,Sock44,Sock44);
 Current current=(Current)(dll+churn_current_rva);Endpoint receive=(Endpoint)(dll+churn_endpoint_rva);
 SocketCtor socket_ctor=(SocketCtor)(dll+0xff0d0);Ctor ctor=(Ctor)(dll+0xffab0);
 unsigned char *state=dll+0x2f5500,*tail=state+churn_state_bytes,saved_tail[0xb00];unsigned tail_bytes=0xb00-churn_state_bytes;
 CHURN(churn_state_bytes>=2636&&churn_state_bytes<0xb00);memcpy(saved_tail,tail,tail_bytes);memset(tail,0xa5,tail_bytes);
 void *objects[66]={0};unsigned maximum=registry_count();CHURN(current(dll,conn[0],0x1600));
 for(unsigned i=0;i<66;i++) {
  CHURN(current(dll,conn[0],0x1600));
  Sock44 local={0},remote={0};struct sockaddr_in bindep={0};bindep.sin_family=AF_INET;bindep.sin_addr.s_addr=htonl(INADDR_LOOPBACK);Bytes28 endpoint=ep28(&bindep);
  socket_ctor(&local,0,executor,&endpoint);socket_ctor(&remote,0,executor,&endpoint);
  Bytes28 *ips=alloc_dll(28);memset(ips,0,28);*(unsigned *)(ips->b+4)=inet_addr("127.0.0.3");
  unsigned short *tokens=alloc_dll(2);*tokens=0x1357;Vec iv={ips,ips+1,ips+1},tv={tokens,tokens+1,tokens+1};
  objects[i]=VirtualAlloc(0,0x5000,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);CHURN(objects[i]);
  ctor(objects[i],0,0x3000+i,ep28(&game_ep[0]),ep28(&face_ep[1]),iv,tv,local,remote);
  CHURN(current(dll,objects[i],0x3000+i));CHURN(current(dll,conn[0],0x1600));
  unsigned count=registry_count();CHURN(count<=64);if(count>maximum)maximum=count;
  for(unsigned n=0;n<tail_bytes;n++)CHURN(tail[n]==0xa5);
 }
 CHURN(maximum==64&&registry_count()==64);CHURN(!current(dll,objects[0],0x3000));CHURN(current(dll,objects[65],0x3041));CHURN(current(dll,conn[0],0x1600));
 unsigned open_handles=0;
 for(unsigned i=0;i<66;i++)for(unsigned k=0;k<2;k++) {
  SOCKET handle=*(SOCKET *)((unsigned char *)objects[i]+(k?0x218c:0x2160));struct sockaddr_in ep;int len=sizeof ep;
  CHURN(!getsockname(handle,(struct sockaddr *)&ep,&len));open_handles++;
 }
 /* Execute the actual compiled endpoint helper with an evicted real object.
  * Only the receive frame and original seq0 cache membership are fixture data. */
 struct sockaddr_in fresh;SOCKET fresh_socket=udp("127.0.0.1",&fresh);Bytes28 registered=ep28(&fresh);
 ((void(__cdecl *)(unsigned,Bytes28))(dll+0x116cb0))(0x3000,registered);
 unsigned char before[28],frame[0x240]={0};memcpy(before,(unsigned char *)objects[0]+0x211c,28);
 *(void **)(frame+0x21c)=objects[0];memcpy(frame+0x44,registered.b,28);receive(dll,frame,64);
 CHURN(!memcmp(before,(unsigned char *)objects[0]+0x211c,28));CHURN(!current(dll,objects[0],0x3000));closesocket(fresh_socket);
 for(unsigned i=0;i<66;i++){((void(__fastcall *)(void *,void *))(dll+0x100a80))(objects[i],0);VirtualFree(objects[i],0,MEM_RELEASE);}
 CHURN(current(dll,conn[0],0x1600));CHURN(registry_count()==1);
 for(unsigned n=0;n<tail_bytes;n++)CHURN(tail[n]==0xa5);memcpy(tail,saved_tail,tail_bytes);
 printf("registry162_churn real_constructors=66 bound=64 observed_max=%u recent_owner_retained=1 newest_tracked=1 evicted_owner_rejected=1 evicted_endpoint_unchanged=1\n",maximum);
 printf("registry162_churn sockets_still_open_before_cleanup=%u unused_state_tail_bytes=%u canary=PASS cleanup_live_records=%u\n",open_handles,tail_bytes,registry_count());return 1;
}
#undef CHURN

int main(int argc,char **argv) {
 setbuf(stdout,0);if(argc<2)return 2;WSADATA w;CHECK(!WSAStartup(MAKEWORD(2,2),&w));
 game[0]=udp("127.0.0.1",&game_ep[0]);game[1]=udp("127.0.0.1",&game_ep[1]);face[0]=udp("127.0.0.2",&face_ep[0]);face[1]=udp("127.0.0.4",&face_ep[1]);
 struct sockaddr_in sink={0};relay_sink=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);sink.sin_family=AF_INET;sink.sin_addr.s_addr=inet_addr("127.0.0.3");sink.sin_port=htons(10190);CHECK(!bind(relay_sink,(struct sockaddr *)&sink,sizeof sink));
 dll=(unsigned char *)LoadLibraryA(argv[1]);CHECK(dll);printf("loaded=%p\n",dll);expect_idle=dll[0x10a61e]==0x90;expect_endpoint=dll[0x10948f]==0xe9;
 if(argc>2&&!strcmp(argv[2],"churn")){CHECK(argc>=6);churn_current_rva=strtoul(argv[3],0,0);churn_endpoint_rva=strtoul(argv[4],0,0);churn_state_bytes=strtoul(argv[5],0,0);CHECK(churn_current_rva>=0x316000&&churn_current_rva<0x400000);CHECK(churn_endpoint_rva>=0x316000&&churn_endpoint_rva<0x400000);}AddVectoredExceptionHandler(1,exception_log);
 original_spawn=trampoline(0xf2b70,spawn_hook);original_socket=trampoline(0xff480,socket_hook);
 iat(0x21036c,deny_dns);iat(0x210400,connect_hook);iat(0x210360,sendto_hook);iat(0x2103a4,wsasendto_hook);iat(0x210408,bind_hook);
 jump_to(dll+0x111846,dll+0x112ab0);DWORD old;VirtualProtect(dll+0x102865,4,PAGE_EXECUTE_READWRITE,&old);*(void **)(dll+0x102865)=dll+0x119be0;VirtualProtect(dll+0x102865,4,old,&old);
 jump_to(dll+0x14d190,logger);jump_to(dll+0x14d170,logger);jump_to(dll+0x14bd00,identity);jump_to(dll+0x14bd50,zero);jump_to(dll+0x86f30,zero);
 /* This game-facing metrics singleton requires vendor frontend initialization.
  * It does not choose sockets/endpoints or construct the probe reply. */
 jump_to(dll+0x347a0,zero);
 HANDLE rt=CreateThread(0,0,relay_thread,0,0,0);CHECK(rt);for(unsigned i=0;i<500&&!natneg_port;i++)Sleep(10);CHECK(natneg_port&&context&&executor);
 struct sockaddr_in n={0};n.sin_family=AF_INET;n.sin_addr.s_addr=natneg_ip;n.sin_port=htons((u_short)natneg_port);unsigned char init[21]={0xfd,0xfc,0x1e,0x66,0x6a,0xb2,3,0,0x16,0,0,1,0,0,0,127,0,0,1,0,0};

 int late=argc>2&&!strcmp(argv[2],"late");SOCKET early_fresh=INVALID_SOCKET;struct sockaddr_in early_ep;
 if(late) {early_fresh=udp("127.0.0.1",&early_ep);CHECK(register_seq0(early_fresh,0x1600,&n));init[12]=2;}
 InterlockedExchange(&build_requested,1);CHECK(sendto(game[0],(char *)init,21,0,(struct sockaddr *)&n,sizeof n)==21);
 for(unsigned i=0;i<500&&!built;i++)Sleep(10);CHECK(built);unsigned char ack[64];CHECK(recvfrom(game[0],(char *)ack,sizeof ack,0,0,0)==21);
 HANDLE px=CreateThread(0,0,proxy_thread,0,0,0);CHECK(px);
 if(late){CHECK(late_ctor_receive(early_fresh));CHECK(blocked==0);printf("late_ctor_mode=PASS blocked_remote=%ld\n",blocked);proxy_stop=1;WaitForSingleObject(px,1000);return 0;}


 if(argc>2&&!strcmp(argv[2],"tiny")) {
  CHECK(dll[0x10a2c6]==0xe9);CHECK(install_tiny_observer());CHECK(control_action(9,&n));
  Bytes28 saved_endpoint;memcpy(saved_endpoint.b,*(void **)((unsigned char *)conn[0]+0x2158),28);
  struct sockaddr_in alien_ep;SOCKET alien=udp("127.0.0.9",&alien_ep);unsigned char byte=0x12;
  for(unsigned count=0;count<2;count++) {
   CHECK(sendto(alien,(const char *)&byte,count,0,(struct sockaddr *)&remote_ep[0],sizeof remote_ep[0])==(int)count);
   for(unsigned tick=0;tick<500&&!tiny_continues[count];tick++)Sleep(1);
   CHECK(tiny_continues[count]==1);CHECK(!memcmp(saved_endpoint.b,*(void **)((unsigned char *)conn[0]+0x2158),28));
   CHECK(*((volatile unsigned char *)conn[0]+0x2116)==0);
   fd_set read;FD_ZERO(&read);FD_SET(game[0],&read);struct timeval wait={0,30000};CHECK(select(0,&read,0,0,&wait)==0);
  }
  unsigned char tiny_probe[32]={0};memcpy(tiny_probe,"HakureiReimuAliceMargatroid",27);
  CHECK(sendto(face[1],(const char *)tiny_probe,32,0,(struct sockaddr *)&remote_ep[0],sizeof remote_ep[0])==32);
  for(unsigned tick=0;tick<500&&!probe_replies[0];tick++)Sleep(1);CHECK(probe_replies[0]==1);
  CHECK(*((volatile unsigned char *)conn[0]+0x2116)==0);CHECK(!memcmp(saved_endpoint.b,*(void **)((unsigned char *)conn[0]+0x2158),28));
  CHECK(exchange(0,0xf00));CHECK(exchange(1,0xf01));CHECK(blocked==0);
  printf("remote162_tiny drop_zero=1 drop_one=1 endpoint_unchanged=1 watchdog_unchanged=1 no_game_datagrams=1\n");
  printf("remote162_tiny later_bidirectional_payload=PASS idle_probe_reply=PASS\n");
  printf("remote162_tiny_mode=PASS blocked_remote=%ld\n",blocked);closesocket(alien);proxy_stop=1;WaitForSingleObject(px,1000);return 0;
 }
 if(argc>2&&!strcmp(argv[2],"churn")) {
  CHECK(expect_endpoint);CHECK(control_action(8,&n));CHECK(churn_passed);CHECK(blocked==0);
  printf("registry162_churn_mode=PASS blocked_remote=%ld\n",blocked);proxy_stop=1;WaitForSingleObject(px,1000);return 0;
 }
 if(argc>2&&!strcmp(argv[2],"cache")) {
  CHECK(expect_endpoint);CHECK(register_seq0(game[0],0x1600,&n));
  unsigned first=request_ready_port(game[0],0x1600,&n);CHECK(first==ntohs(local_ep[0].sin_port));
  /* Two natural five-second cache-watchdog ticks guarantee expiry. */
  Sleep(11000);CHECK(!find_cache(0x1600));unsigned after=request_ready_port(game[0],0x1600,&n);CHECK(after==first);CHECK(!find_cache(0x1600));
  printf("cache162_natural_expiry original_cache_absent=1 same_live_registry_port=%u registration_bypassed=1\n",after);
  CHECK(control_action(3,&n));CHECK(extra_connection);CHECK(register_seq0(game[0],0x1600,&n));CHECK(control_action(5,&n));
  unsigned old_extra=extra_port();CHECK(old_extra);CHECK(control_action(6,&n));CHECK(extra_connection&&previous_extra_connection);CHECK(control_action(5,&n));
  unsigned new_extra=extra_port();CHECK(new_extra&&new_extra!=old_extra);CHECK(find_cache(0x1600)&&*(unsigned short *)(find_cache(0x1600)+0x24)==new_extra);
  CHECK(request_ready_port(game[0],0x1600,&n)==new_extra);CHECK(control_action(7,&n));CHECK(!previous_extra_connection);
  CHECK(find_cache(0x1600)&&*(unsigned short *)(find_cache(0x1600)+0x24)==new_extra);CHECK(request_ready_port(game[0],0x1600,&n)==new_extra);
  printf("cache162_old_destructor newer_owner_port_preserved=%u\n",new_extra);
  CHECK(control_action(4,&n));CHECK(!extra_connection);CHECK(find_cache(0x1600)&&*(unsigned short *)(find_cache(0x1600)+0x24)==0);
  printf("cache162_current_destructor cached_port_invalidated=1 old_owner_not_revived=1\n");
  CHECK(blocked==0);printf("cache162_mode=PASS blocked_remote=%ld\n",blocked);proxy_stop=1;WaitForSingleObject(px,1000);return 0;
 }

 for(unsigned i=0;i<8;i++){CHECK(exchange(0,i));CHECK(exchange(1,i));}printf("initial_bidirectional_payload=PASS\n");
 /* Real type7 payload observed in host2254. These tests execute the DLL's
  * native framing/XOR/UDP/deframing path; they do not model SDKProcessPing. */
 unsigned char nn[20]={0xfd,0xfc,0x1e,0x66,0x6a,0xb2,3,7,0x93,0x4e,0x4a,0xb8,127,0,0,1,0xf5,0x71,0,0};
 const unsigned char tails[3]={0,0x10,0x11};
 for(unsigned i=0;i<3;i++){nn[18]=tails[i];CHECK(exchange_raw(0,nn,sizeof nn));CHECK(exchange_raw(1,nn,sizeof nn));}
 printf("nncrypt_type7_tails_00_10_11_exact_both_directions=PASS\n");
 /* Reset the real activity bytes on the relay thread, matching the reset
  * normally made by the speed-test worker before its next round. */
 InterlockedExchange(&build_requested,2);CHECK(sendto(game[0],(char *)init,21,0,(struct sockaddr *)&n,sizeof n)==21);CHECK(recvfrom(game[0],(char *)ack,sizeof ack,0,0,0)==21);
 printf("idle_activity=%u,%u\n",*((unsigned char *)conn[0]+0x2117),*((unsigned char *)conn[1]+0x2117));
 unsigned char probe[32]={0};memcpy(probe,"HakureiReimuAliceMargatroid",27);CHECK(sendto(face[1],(char *)probe,32,0,(struct sockaddr *)&remote_ep[0],sizeof remote_ep[0])==32);Sleep(120);
 printf("idle_probe_requests=1 actual_replies_A=%ld expected=%d\n",probe_replies[0],expect_idle);CHECK(probe_replies[0]==expect_idle);
 /* Old idle probes may be misforwarded as game data: discard only that
  * unexpected diagnostic datagram before measuring the next real payload. */
 for(unsigned i=0;i<2;i++){u_long yes=1;ioctlsocket(game[i],FIONBIO,&yes);while(recvfrom(game[i],(char *)ack,sizeof ack,0,0,0)>0){}yes=0;ioctlsocket(game[i],FIONBIO,&yes);}
 int after_probe=exchange(1,90);printf("first_payload_after_idle_probe=%d\n",after_probe);if(expect_idle)CHECK(after_probe);
 CHECK(exchange(1,91));CHECK(exchange(0,92));
 SOCKET oldface=face[1];struct sockaddr_in fresh;SOCKET ns=udp("127.0.0.4",&fresh);InterlockedExchange((LONG *)&face[1],(LONG)ns);face_ep[1]=fresh;closesocket(oldface);Sleep(50);
 CHECK(exchange(1,100));CHECK(exchange(0,101));
 struct sockaddr_in *learned=(struct sockaddr_in *)*(void **)((unsigned char *)conn[0]+0x2158);
 CHECK(learned->sin_port==fresh.sin_port&&learned->sin_addr.s_addr==fresh.sin_addr.s_addr);
 for(unsigned i=0;i<8;i++){CHECK(exchange(0,200+i));CHECK(exchange(1,300+i));}
 printf("changed_source_port=%u learned=%u bidirectional_payload=PASS\n",ntohs(fresh.sin_port),ntohs(learned->sin_port));


 /* Authorization: G2 cannot redirect replies merely by sending UDP. */
 CHECK(register_seq0(game[0],0x1600,&n));
 struct sockaddr_in ep2,ep3,ep4;SOCKET g2=udp("127.0.0.1",&ep2),g3=udp("127.0.0.1",&ep3),g4=udp("127.0.0.1",&ep4);
 CHECK(local_roundtrip(g2,game[0],g2,"unregistered-port"));
 CHECK(register_seq0(g2,0x1700,&n));CHECK(local_roundtrip(g2,game[0],g2,"wrong-session-seq0"));
 CHECK(register_seq0(g2,0x1600,&n));SOCKET saved=expect_endpoint?g2:game[0],forbidden=expect_endpoint?game[0]:g2;
 CHECK(local_roundtrip(g2,saved,forbidden,"authorized-current-seq0"));
 /* Native ctor/destructor callbacks execute on the relay executor via ACK.
  * The extra same-SID Connection is not attached to coroutines: it safely
  * replaces registry ownership without replacing the tested live old object. */
 CHECK(control_action(3,&n));CHECK(extra_connection);
 CHECK(register_seq0(g3,0x1600,&n));CHECK(local_roundtrip(g3,saved,g3,"superseded-owner"));
 CHECK(control_action(4,&n));CHECK(!extra_connection);
 CHECK(register_seq0(g4,0x1600,&n));CHECK(local_roundtrip(g4,saved,g4,"unregistered-owner"));
 printf("endpoint162_matrix=PASS fixed_expected=%d blocked_remote=%ld\n",expect_endpoint,blocked);CHECK(blocked==0);
 proxy_stop=1;WaitForSingleObject(px,1000);return 0;
}
