#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned char *dll;
static volatile LONG remote_blocked;
static volatile unsigned relay_port,relay_ip;
static void __cdecl test_log(const char *s,unsigned n) {if(n>13 && !memcmp(s,"Octane relay162",15))printf("dll: %.*s\n",(int)n,s);}
static void *__cdecl test_identity(void **out) {out[0]="local-test";out[1]=(void *)10;return out;}
static unsigned __cdecl test_zero(void) {return 0;}
static void WINAPI test_debug(const wchar_t *s) {wprintf(L"debug: %ls\n",s);}
static LONG CALLBACK report_exception(PEXCEPTION_POINTERS p) {
 printf("exception=%08lx at=%p rva=%08lx\n",p->ExceptionRecord->ExceptionCode,p->ExceptionRecord->ExceptionAddress,(unsigned char *)p->ExceptionRecord->ExceptionAddress-dll);
 if(p->ExceptionRecord->ExceptionCode==0xe06d7363 && p->ExceptionRecord->NumberParameters>=3 && p->ExceptionRecord->ExceptionInformation[2]) {
  void *obj=(void *)p->ExceptionRecord->ExceptionInformation[1];unsigned *ti=(unsigned *)p->ExceptionRecord->ExceptionInformation[2];
  unsigned *ca=(unsigned *)ti[3],*ct=(unsigned *)ca[1];printf("type=%s\n",(char *)ct[1]+8);
  for(unsigned k=1;k<=ca[0];k++) {ct=(unsigned *)ca[k];if(!strcmp((char *)ct[1]+8,".?AVexception@std@@") && ct[3]==0xffffffff) {
    void *base=(unsigned char *)obj+ct[2];printf("what=%s\n",((const char *(__fastcall *)(void *,void *))(*(void ***)base)[1])(base,0));break;
  }}
 }
 return EXCEPTION_CONTINUE_SEARCH;
}
static int WSAAPI local_bind(SOCKET s,const struct sockaddr *a,int n) {
 int r=bind(s,a,n);struct sockaddr_in actual={0};int len=sizeof actual,type=0,tn=sizeof type;
 getsockopt(s,SOL_SOCKET,SO_TYPE,(char *)&type,&tn);
 if(!r && type==SOCK_DGRAM && !relay_port && !getsockname(s,(struct sockaddr *)&actual,&len) && actual.sin_family==AF_INET) {
  relay_ip=actual.sin_addr.s_addr;relay_port=ntohs(actual.sin_port);
 }
 return r;
}
static int WSAAPI no_dns(PCSTR node,PCSTR service,const ADDRINFOA *h,PADDRINFOA *out) {
 (void)node;(void)service;(void)h;*out=0;InterlockedIncrement(&remote_blocked);return WSAHOST_NOT_FOUND;
}
static int WSAAPI no_connect(SOCKET s,const struct sockaddr *a,int n) {
 if(a && a->sa_family==AF_INET && ((const unsigned char *)&((const struct sockaddr_in *)a)->sin_addr)[0]==127)return connect(s,a,n);
 InterlockedIncrement(&remote_blocked);WSASetLastError(WSAENETUNREACH);return SOCKET_ERROR;
}
static void seed_port(const char *buf,int len) {
 /* Seed a known-good local port on the relay thread, for a separate family of
  * test sessions. get_port itself, its cache lookup, and CONNECT remain real. */
 if(len==21 && (unsigned char)buf[7]==1 && (unsigned char)buf[8]==0x5a) {
  unsigned sid;memcpy(&sid,buf+8,4);
  unsigned char *entry=((unsigned char *(__cdecl *)(unsigned))(dll+0x10bd10))(sid);
  *(unsigned short *)(entry+0x24)=40000;
 }
}
static int WSAAPI local_sendto(SOCKET s,const char *buf,int len,int flags,const struct sockaddr *a,int n) {
 seed_port(buf,len);
 if(a && a->sa_family==AF_INET && ((const unsigned char *)&((const struct sockaddr_in *)a)->sin_addr)[0]==127)return sendto(s,buf,len,flags,a,n);
 InterlockedIncrement(&remote_blocked);WSASetLastError(WSAENETUNREACH);return SOCKET_ERROR;
}
static int WSAAPI local_wsasendto(SOCKET s,LPWSABUF buffers,DWORD count,LPDWORD sent,DWORD flags,const struct sockaddr *a,int n,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) {
 if(count==1)seed_port(buffers[0].buf,(int)buffers[0].len);
 if(a && a->sa_family==AF_INET && ((const unsigned char *)&((const struct sockaddr_in *)a)->sin_addr)[0]==127)return WSASendTo(s,buffers,count,sent,flags,a,n,ov,completion);
 InterlockedIncrement(&remote_blocked);WSASetLastError(WSAENETUNREACH);return SOCKET_ERROR;
}
static void iat(unsigned rva,void *fn) {DWORD old;VirtualProtect(dll+rva,4,PAGE_READWRITE,&old);*(void **)(dll+rva)=fn;VirtualProtect(dll+rva,4,old,&old);}
static void jump(unsigned from,unsigned to) {DWORD old;VirtualProtect(dll+from,5,PAGE_EXECUTE_READWRITE,&old);dll[from]=0xe9;*(unsigned *)(dll+from+1)=to-from-5;VirtualProtect(dll+from,5,old,&old);FlushInstructionCache(GetCurrentProcess(),dll+from,5);}
static DWORD WINAPI relay_thread(void *unused) {(void)unused;((void(__cdecl *)(void))(dll+0x102740))();return 0;}
static void packet(unsigned char *p,unsigned session) {
 const unsigned char magic[8]={0xfd,0xfc,0x1e,0x66,0x6a,0xb2,3,0};
 memset(p,0,21);memcpy(p,magic,8);p[8]=(unsigned char)(session>>24);p[9]=(unsigned char)(session>>16);p[10]=(unsigned char)(session>>8);p[11]=(unsigned char)session;p[12]=1;p[13]=0;p[14]=1;p[15]=127;p[18]=1;
}
static int exchange_ack(SOCKET s,const struct sockaddr_in *server,unsigned session,ULONGLONG *ms) {
 unsigned char p[21],buf[128];packet(p,session);ULONGLONG start=GetTickCount64();
 if(sendto(s,(char *)p,21,0,(const struct sockaddr *)server,sizeof *server)!=21)return 0;
 int n=recvfrom(s,(char *)buf,sizeof buf,0,0,0);*ms=GetTickCount64()-start;
 return n==21 && buf[7]==1 && !memcmp(p+8,buf+8,4);
}

extern void __cdecl network162_throw(int kind);
static volatile LONG fault_stage,fault_remaining;
static int fault_kind;
static void *(__cdecl *original_frame)(void **);
static void (__cdecl *original_spawn)(void *,void *,void *,unsigned);
static void *(__cdecl *original_json)(void *,unsigned);
static void *(__cdecl *original_port)(void **,void *,unsigned);
static void fault_hit(int stage) {
 if(fault_stage==stage && InterlockedCompareExchange(&fault_remaining,0,1)==1)network162_throw(fault_kind);
}
static void *__cdecl frame_fault(void **out){fault_hit(1);return original_frame(out);}
static void __cdecl spawn_fault(void *c,void *f,void *t,unsigned n){fault_hit(2);original_spawn(c,f,t,n);}
static void *__cdecl json_fault(void *out,unsigned sid){fault_hit(3);return original_json(out,sid);}
static void *__cdecl port_fault(void **out,void *json,unsigned sid){fault_hit(4);return original_port(out,json,sid);}
static unsigned __cdecl telemetry_fault(void *json){(void)json;fault_hit(5);return 0;}
static void *trap_function(unsigned rva,void *replacement) {
 unsigned char *original=VirtualAlloc(0,32,MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
 if(!original || memcmp(dll+rva,"\x55\x8b\xec\x6a\xff",5)){printf("bad_fault_trampoline %x\n",rva);ExitProcess(60);}
 memcpy(original,dll+rva,5);original[5]=0xe9;*(int *)(original+6)=dll+rva+5-(original+10);
 jump(rva,(unsigned)replacement-(unsigned)dll);return original;
}
static void install_faults(void) {
 original_frame=trap_function(0x112c50,frame_fault);
 original_spawn=trap_function(0xf2b70,spawn_fault);
 original_json=trap_function(0x116da0,json_fault);
 original_port=trap_function(0x10e490,port_fault);
 jump(0x86f30,(unsigned)telemetry_fault-(unsigned)dll);
}
#define CHECK(x) do {if(!(x)){printf("FAIL line=%d expression=%s error=%d\n",__LINE__,#x,WSAGetLastError());return 40;}}while(0)
int main(int argc,char **argv) {
 setbuf(stdout,0);if(argc<2)return 2;
 if(argc>2)CHECK(VirtualAlloc((void *)0x60000000,0x8000000,MEM_RESERVE,PAGE_NOACCESS));
 WSADATA wd;if(WSAStartup(MAKEWORD(2,2),&wd))return 3;
 dll=(unsigned char *)LoadLibraryA(argv[1]);if(!dll){printf("load_error=%lu\n",GetLastError());return 4;}
 printf("loaded=%p\n",dll);
 AddVectoredExceptionHandler(1,report_exception);
 iat(0x21036c,no_dns);iat(0x210400,no_connect);iat(0x210360,local_sendto);iat(0x2103a4,local_wsasendto);iat(0x210408,local_bind);
 /* Test-only: no RA3 process exists. Skip writing its five NATNEG port operands;
  * the actual receive/send loop and get_port coroutine remain unmodified. */
 jump(0x111846,0x112ab0);
 /* Isolate the local receiver: the separate periodic relay-directory updater
  * requires BattleNet's login/configuration, absent in this test process. */
 {DWORD old;VirtualProtect(dll+0x102865,4,PAGE_EXECUTE_READWRITE,&old);*(void **)(dll+0x102865)=dll+0x119be0;VirtualProtect(dll+0x102865,4,old,&old);FlushInstructionCache(GetCurrentProcess(),dll+0x102865,4);}
 jump(0x14d190,(unsigned)test_log-(unsigned)dll);
 /* Diagnostic identity normally comes from the running game's address table. */
 jump(0x14bd00,(unsigned)test_identity-(unsigned)dll);jump(0x14bd50,(unsigned)test_zero-(unsigned)dll);iat(0x210154,test_debug);
 /* Do not submit diagnostic telemetry to BattleNet from the offline test. */
 jump(0x86f30,(unsigned)test_zero-(unsigned)dll);
 HANDLE thread=CreateThread(0,0,relay_thread,0,0,0);if(!thread)return 5;
 unsigned port=0;for(int i=0;i<300;i++){port=relay_port;if(port)break;Sleep(10);}
 printf("relay_port=%u thread_wait=%lu\n",port,WaitForSingleObject(thread,0));if(!port)return 6;
 SOCKET s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);struct sockaddr_in local={0},server={0};local.sin_family=AF_INET;local.sin_addr.s_addr=htonl(INADDR_LOOPBACK);bind(s,(struct sockaddr *)&local,sizeof local);
 DWORD timeout=4000;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char *)&timeout,sizeof timeout);
 server.sin_family=AF_INET;server.sin_addr.s_addr=relay_ip;server.sin_port=htons((u_short)port);
 int fixed=((IMAGE_NT_HEADERS *)(dll+((IMAGE_DOS_HEADER *)dll)->e_lfanew))->FileHeader.NumberOfSections==12;
 unsigned char p[21],buf[128];ULONGLONG first,second,ms,max_ack=0;
 CHECK(exchange_ack(s,&server,0x16000001,&first));Sleep(50);CHECK(exchange_ack(s,&server,0x16000002,&second));
 printf("queue_first_ms=%llu queue_second_ms=%llu\n",first,second);
 CHECK(fixed?second<300:second>=650);Sleep(1300);
 unsigned *state=(unsigned *)(dll+0x2f5500);
 if(fixed)CHECK(state[1]==2 && state[5]==2);
 for(unsigned i=0;i<128;i++) {
  CHECK(exchange_ack(s,&server,0x5a900000+i,&ms));
  int n=recvfrom(s,(char *)buf,sizeof buf,0,0,0);packet(p,0x5a900000+i);p[7]=5;
  p[12]=127;p[13]=p[14]=0;p[15]=1;p[16]=0x9c;p[17]=0x40;p[18]=0x42;p[19]=0;
  CHECK(n==20 && !memcmp(p,buf,20));
 }
 printf("cached_connect_packets=128 exact_bytes=PASS\n");
 if(fixed) {
  Sleep(50);CHECK(state[4]==128);
  unsigned submitted=state[1],coalesced=state[2];
  for(unsigned i=0;i<32;i++) {CHECK(exchange_ack(s,&server,0x16001000,&ms));if(ms>max_ack)max_ack=ms;}
  Sleep(50);CHECK(state[1]==submitted+1 && state[2]==coalesced+31);CHECK(max_ack<300);Sleep(1200);
  submitted=state[1];unsigned saturated=state[3];
  for(unsigned i=0;i<24;i++) {CHECK(exchange_ack(s,&server,0x16002000+i,&ms));if(ms>max_ack)max_ack=ms;}
  Sleep(50);CHECK(state[1]==submitted+16 && state[3]==saturated+8);Sleep(1200);
  submitted=state[1];CHECK(exchange_ack(s,&server,0x16002017,&ms));Sleep(1200);CHECK(state[1]==submitted+1);
  for(unsigned i=0;i<16;i++)CHECK(state[6+i*15]==0);
  printf("duplicates=31 bounded_jobs=16 overflow=8 slots_reused=PASS max_ack_ms=%llu\n",max_ack);
  printf("submitted=%u coalesced=%u saturated=%u completed=%u failed=%u\n",state[1],state[2],state[3],state[4],state[5]);
 }

 install_faults();
 for(int kind=0;kind<2;kind++)for(int stage=1;stage<=5;stage++) {
  DWORD small=250;setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,(const char *)&small,sizeof small);
  unsigned before_failed=state[5],before_spawn=state[248],before_work=state[249],before_telemetry=state[250];
  fault_kind=kind;fault_stage=stage;InterlockedExchange(&fault_remaining,1);
  unsigned session=0x5aa00000u+(unsigned)(kind*16+stage);
  CHECK(exchange_ack(s,&server,session,&ms));
  int n=recvfrom(s,(char *)buf,sizeof buf,0,0,0);
  if(stage==5)CHECK(n==20&&buf[7]==5);
  else CHECK(n==SOCKET_ERROR&&WSAGetLastError()==WSAETIMEDOUT);
  Sleep(30);CHECK(!fault_remaining);fault_stage=0;
  for(unsigned i=0;i<16;i++)CHECK(state[6+i*15]==0);
  CHECK(stage==5?state[5]==before_failed:state[5]==before_failed+1);
  CHECK(stage<=2?state[248]==before_spawn+1:state[248]==before_spawn);
  CHECK(stage==3||stage==4?state[249]==before_work+1:state[249]==before_work);
  CHECK(stage==5?state[250]==before_telemetry+1:state[250]==before_telemetry);
  CHECK(exchange_ack(s,&server,session+0x100,&ms));
  n=recvfrom(s,(char *)buf,sizeof buf,0,0,0);CHECK(n==20&&buf[7]==5);
  printf("fault_kind=%d stage=%d slot_release=PASS receiver_resume=PASS\n",kind,stage);
 }
 printf("fault_injection_cases=10 Cpp_exceptions_actual=PASS\n");
 CHECK(remote_blocked==0);printf("PASS remote_requests=0 fixed=%d\n",fixed);
 closesocket(s);return 0;
}
