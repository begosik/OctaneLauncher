#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Native runtime-installer test. The entire authenticated game PE is mapped as
 * read-only DATA; no game entry point, TLS callback or instruction is executed. */
typedef struct Edit {DWORD rva,n;BYTE before[8],after[8];} Edit;
static Edit edits[]={
 {0x2a379d,6,{0x8b,0x13,0x8b,0x02,0x6a,0xff},{0xe9,0x52,0,0,0,0x90}},
 {0x29713f,5,{0xe8,0x2c,0xff,0xfe,0xff},{0x83,0xc4,0x10,0x90,0x90}},
 {0x297106,6,{0x3b,0x9e,0xc0,0,0,0},{0xe9,0,0,0,0,0x90}}
};
#define EDITS (sizeof edits/sizeof edits[0])
static BYTE *dll,*game,*original,*before;
static DWORD game_size,protection_calls,flush_calls,fail_protect,protect_failures,log_calls;
static DWORD successful_cases,failed_cases,assertions,api_bad;
static DWORD marker_rvas[2]={0x2a34a5,0x287070};
static const BYTE marker_values[2][5]={{0xe8,0x56,0x04,0x6c,0},{0xe9,0xd2,0x4a,0x6e,0}};
static BYTE *fake_main;
static void *game_reservation;
static void NTAPI reserve_game_early(PVOID module,DWORD reason,PVOID reserved) {(void)module;(void)reserved;if(reason==DLL_PROCESS_ATTACH){game_reservation=VirtualAlloc((void *)0x400000,0x1800000,MEM_RESERVE,PAGE_NOACCESS);if(!game_reservation){MEMORY_BASIC_INFORMATION m;if(VirtualQuery((void *)0x400000,&m,sizeof m)&&m.State==MEM_RESERVE&&m.AllocationBase==(void *)0x400000&&m.RegionSize>=0x1800000)game_reservation=(void *)0x400000;}}}
#pragma section(".CRT$XLB",long,read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK fixture_early_callback=reserve_game_early;
#pragma comment(linker,"/INCLUDE:__tls_used")
#pragma comment(linker,"/INCLUDE:_fixture_early_callback")
static const char *case_name;
static void iat(DWORD rva,void *fn) {DWORD old;VirtualProtect(dll+rva,4,PAGE_READWRITE,&old);*(void **)(dll+rva)=fn;VirtualProtect(dll+rva,4,old,&old);}
static void jump_to(void *from,void *to) {DWORD old;VirtualProtect(from,5,PAGE_EXECUTE_READWRITE,&old);*(BYTE *)from=0xe9;*(int *)((BYTE *)from+1)=(BYTE *)to-((BYTE *)from+5);VirtualProtect(from,5,old,&old);FlushInstructionCache(GetCurrentProcess(),from,5);}
static unsigned __cdecl no_spawn(void) {return 0;}
static void __cdecl logger(const char *s,unsigned n) {(void)s;(void)n;log_calls++;}
static HMODULE WINAPI main_module(LPCWSTR name) {if(name){api_bad++;return 0;}return (HMODULE)fake_main;}
static BOOL WINAPI protect_game(void *address,SIZE_T bytes,DWORD protection,DWORD *old) {
 protection_calls++;
 if((BYTE *)address<game || (BYTE *)address+bytes>game+game_size)api_bad++;
 if(fail_protect&&protection_calls==fail_protect){protect_failures++;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 return VirtualProtect(address,bytes,protection,old);
}
static BOOL WINAPI flush_game(HANDLE process,LPCVOID address,SIZE_T bytes) {
 flush_calls++;
 if(process!=(HANDLE)-1 || (const BYTE *)address<game || (const BYTE *)address+bytes>game+game_size)api_bad++;
 return FlushInstructionCache(process,address,bytes);
}
static int check(int ok,const char *why) {assertions++;if(!ok){printf("FAIL case=%s assertion=%s win32=%lu\n",case_name,why,GetLastError());failed_cases++;}return ok;}
#define CHECK(x) do{if(!check(!!(x),#x))return 0;}while(0)
static DWORD status(void) {return *(DWORD *)(dll+0x2f5500+984);}
static void invoke(void) {((void(__cdecl *)(void *,void *,void *,DWORD))(dll+0x316000))(0,0,0,0);}
static void writable(void) {DWORD old;VirtualProtect(game,game_size,PAGE_READWRITE,&old);}
static void snapshot(void) {DWORD old;memcpy(before,game,game_size);VirtualProtect(game,game_size,PAGE_READONLY,&old);protection_calls=flush_calls=fail_protect=protect_failures=log_calls=api_bad=0;}
static void prepare(const char *name) {
 case_name=name;writable();memcpy(game,original,game_size);memset(dll+0x2f5500,0,0xb00);fake_main=game;snapshot();
}
static int unchanged(void) {return memcmp(game,before,game_size)==0;}
static int all_readonly(void) {
 BYTE *at=game;MEMORY_BASIC_INFORMATION m;
 while(at<game+game_size){if(!VirtualQuery(at,&m,sizeof m) || m.Protect!=PAGE_READONLY)return 0;at=(BYTE *)m.BaseAddress+m.RegionSize;}
 return 1;
}
static int edited_exactly(void) {
 DWORD changed=0,wanted=0;
 for(unsigned e=0;e<EDITS;e++) {CHECK(!memcmp(game+edits[e].rva,edits[e].after,edits[e].n));for(DWORD k=0;k<edits[e].n;k++)wanted+=edits[e].before[k]!=edits[e].after[k];}
 for(DWORD i=0;i<game_size;i++)if(game[i]!=before[i]){int approved=0;for(unsigned e=0;e<EDITS;e++)if(i>=edits[e].rva&&i<edits[e].rva+edits[e].n)approved=1;CHECK(approved);changed++;}
 CHECK(changed==wanted);printf("installed_instruction_spans=3 span_bytes=17 actual_changed_bytes=%lu\n",changed);return 1;
}
static int accepted(void) {
 prepare("exact-authenticated-game");invoke();CHECK(status()==1);CHECK(edited_exactly());CHECK(protection_calls==2*EDITS);CHECK(flush_calls==EDITS);CHECK(!api_bad);CHECK(all_readonly());
 DWORD protects=protection_calls,flushes=flush_calls;memcpy(before,game,game_size);invoke();CHECK(status()==1);CHECK(unchanged());CHECK(protection_calls==protects&&flush_calls==flushes);successful_cases++;return 1;
}
static int already_applied(void) {
 prepare("already-all-applied");writable();for(unsigned i=0;i<EDITS;i++)memcpy(game+edits[i].rva,edits[i].after,edits[i].n);snapshot();invoke();CHECK(status()==1);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;return 1;
}
static int partial(void) {
 for(unsigned i=0;i<EDITS;i++) {
  prepare("partial-existing-patch");writable();memcpy(game+edits[i].rva,edits[i].after,edits[i].n);snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;
 }
 return 1;
}
static int incompatible_bytes(void) {
 for(unsigned i=0;i<EDITS;i++) {
  prepare("changed-edit-instruction");writable();game[edits[i].rva]^=0x55;snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;
 }
 for(unsigned i=0;i<2;i++) {
  prepare("unsupported-eight-player-marker");writable();game[marker_rvas[i]]^=0x55;snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;
 }
 DWORD helpers[4]={0x954820,0x953ec0,0x953f20,0x953f60};
 for(unsigned i=0;i<4;i++){prepare("unsupported-native-helper");writable();game[helpers[i]]^=0x55;snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;}
 return 1;
}
static int malformed_header(void) {
 for(unsigned i=0;i<8;i++) {
  prepare("unsupported-game-PE");writable();IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)game;IMAGE_NT_HEADERS32 *nt=(IMAGE_NT_HEADERS32 *)(game+dos->e_lfanew);
  switch(i){case 0:fake_main=0;break;case 1:dos->e_magic=0;break;case 2:dos->e_lfanew=0x10;break;case 3:dos->e_lfanew=0x1001;break;case 4:nt->Signature=0;break;case 5:nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;break;case 6:nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;break;case 7:nt->OptionalHeader.SizeOfImage=0x2a37ff;break;}
  snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;
 }
 prepare("oversized-game-image-header");writable();IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)game;IMAGE_NT_HEADERS32 *nt=(IMAGE_NT_HEADERS32 *)(game+dos->e_lfanew);nt->OptionalHeader.SizeOfImage=0x2000001;snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());successful_cases++;return 1;
}
static int protect_rollback(void) {
 for(unsigned i=1;i<=EDITS;i++) {
  prepare("VirtualProtect-denial-before-write");fail_protect=i;invoke();CHECK(status()==2);CHECK(unchanged());CHECK(protect_failures==1);CHECK(protection_calls==2*i-1);CHECK(!flush_calls);CHECK(!api_bad);CHECK(all_readonly());successful_cases++;
 }
 return 1;
}
static BYTE *read_game(const char *path) {
 FILE *f=fopen(path,"rb");if(!f)return 0;fseek(f,0,SEEK_END);long bytes=ftell(f);fseek(f,0,SEEK_SET);if(bytes<0x1000){fclose(f);return 0;}BYTE *file=VirtualAlloc((void *)0x30000000,(size_t)bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!file){fclose(f);return 0;}if(fread(file,1,(size_t)bytes,f)!=(size_t)bytes){fclose(f);VirtualFree(file,0,MEM_RELEASE);return 0;}fclose(f);
 IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)file;if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0x40||dos->e_lfanew>0x1000){VirtualFree(file,0,MEM_RELEASE);return 0;}IMAGE_NT_HEADERS32 *nt=(IMAGE_NT_HEADERS32 *)(file+dos->e_lfanew);if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->OptionalHeader.SizeOfImage>0x2000000){VirtualFree(file,0,MEM_RELEASE);return 0;}game_size=nt->OptionalHeader.SizeOfImage;
 BYTE *mapped=VirtualAlloc((void *)0x40000000,game_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!mapped){VirtualFree(file,0,MEM_RELEASE);return 0;}memcpy(mapped,file,nt->OptionalHeader.SizeOfHeaders);IMAGE_SECTION_HEADER *sec=IMAGE_FIRST_SECTION(nt);
 for(unsigned i=0;i<nt->FileHeader.NumberOfSections;i++){if(sec[i].VirtualAddress+sec[i].SizeOfRawData>game_size||sec[i].PointerToRawData+sec[i].SizeOfRawData>(DWORD)bytes){VirtualFree(mapped,0,MEM_RELEASE);VirtualFree(file,0,MEM_RELEASE);return 0;}memcpy(mapped+sec[i].VirtualAddress,file+sec[i].PointerToRawData,sec[i].SizeOfRawData);}
 VirtualFree(file,0,MEM_RELEASE);return mapped;
}
int main(int argc,char **argv) {
 if(argc==4)freopen(argv[3],"w",stdout);setbuf(stdout,0);if(argc!=3&&argc!=4)return 2;original=read_game(argv[2]);if(!original){printf("bad-game-PE\n");return 3;}
 for(unsigned i=0;i<EDITS;i++)if(memcmp(original+edits[i].rva,edits[i].before,edits[i].n)){printf("bad-game-instruction %u\n",i);return 4;}
 for(unsigned i=0;i<2;i++)if(memcmp(original+marker_rvas[i],marker_values[i],5)){printf("bad-game-8P-marker %u\n",i);return 5;}
 printf("early_reservation=%p\n",game_reservation);
 game=VirtualAlloc((void *)0x400000,game_size,MEM_COMMIT|(game_reservation?0:MEM_RESERVE),PAGE_READWRITE);if(!game){printf("early-game-allocation-error=%lu\n",GetLastError());MEMORY_BASIC_INFORMATION m;VirtualQuery((void *)0x400000,&m,sizeof m);printf("at400000 base=%p alloc=%p size=%u type=%lu protect=%lu\n",m.BaseAddress,m.AllocationBase,(unsigned)m.RegionSize,m.Type,m.Protect);
 char name[1024]={0};typedef DWORD(WINAPI *MappedFileName)(HANDLE,LPVOID,LPSTR,DWORD);MappedFileName mapped=(MappedFileName)GetProcAddress(GetModuleHandleA("kernel32.dll"),"K32GetMappedFileNameA");if(mapped&&mapped(GetCurrentProcess(),m.BaseAddress,name,sizeof name))printf("mapping=%s\n",name);return 7;}
 dll=(BYTE *)LoadLibraryA(argv[1]);if(!dll){printf("load-error=%lu\n",GetLastError());return 6;}
 printf("native_dll_base=%p admission_target=%p\n",dll,dll+0x3160e0);
 iat(0x210198,main_module);iat(0x21020c,protect_game);iat(0x210258,flush_game);jump_to(dll+0xf2b70,no_spawn);jump_to(dll+0x14d190,logger);
 *(int *)(edits[2].after+1)=(dll+0x3160e0)-((BYTE *)0x400000+edits[2].rva+5);
 before=VirtualAlloc((void *)0x50000000,game_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 for(unsigned base=0;base<2;base++) {
  if(base)game=VirtualAlloc((void *)0x10000000,game_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!game){printf("allocation-error=%lu\n",GetLastError());return 7;}
  printf("game_data_base=%p image_bytes=%lu\n",game,game_size);
  if(!base){if(!accepted()||!already_applied()||!partial()||!incompatible_bytes()||!malformed_header()||!protect_rollback())return 40;}
  else {prepare("unsupported-relocated-game");invoke();if(!check(status()==2&&unchanged()&&!protection_calls&&!flush_calls&&all_readonly(),"unsupported base preserved"))return 40;successful_cases++;}
  VirtualFree(game,0,MEM_RELEASE);
 }
 printf("PASS installer_cases=%lu assertions=%lu failures=%lu no_game_code_executed=1\n",successful_cases,assertions,failed_cases);return failed_cases?40:0;
}
