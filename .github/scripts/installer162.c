#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Actual Native162 capture/installer; authenticated game PE is read-only DATA.
 * Game entry/TLS/instructions and real co_spawn are never executed. */
typedef struct Edit {DWORD rva,n;BYTE before[8],after[8];} Edit;
static Edit edits[]={
 {0x2a379d,6,{0x8b,0x13,0x8b,0x02,0x6a,0xff},{0xe9,0x52,0,0,0,0x90}},
 {0x29713f,5,{0xe8,0x2c,0xff,0xfe,0xff},{0x83,0xc4,0x10,0x90,0x90}},
 {0x297106,6,{0x3b,0x9e,0xc0,0,0,0},{0xe9,0,0,0,0,0x90}},
 {0x954857,5,{0x8b,0x55,0x14,0x89,0x10},{0xe9,0,0,0,0}},
 {0x96392c,5,{0xe9,0xcf,0x28,0xdd,0xff},{0xe9,0,0,0,0}}
};
#define EDITS (sizeof edits/sizeof edits[0])
#define PAGES 4
static BYTE *dll,*game,*original,*before,*fake_main;
static DWORD game_size,protection_calls,flush_calls,fail_protect,fail_protect_again,fail_flush,protect_failures,flush_failures,log_calls,installed_logs;
static DWORD successful_cases,failed_cases,assertions,api_bad;
static void *game_reservation;
static const char *case_name;
static void NTAPI reserve_game_early(PVOID module,DWORD reason,PVOID reserved) {
 (void)module;(void)reserved;
 if(reason==DLL_PROCESS_ATTACH){game_reservation=VirtualAlloc((void *)0x400000,0x1800000,MEM_RESERVE,PAGE_NOACCESS);if(!game_reservation){MEMORY_BASIC_INFORMATION m;if(VirtualQuery((void *)0x400000,&m,sizeof m)&&m.State==MEM_RESERVE&&m.AllocationBase==(void *)0x400000&&m.RegionSize>=0x1800000)game_reservation=(void *)0x400000;}}
}
#pragma section(".CRT$XLB",long,read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK fixture_early_callback=reserve_game_early;
#pragma comment(linker,"/INCLUDE:__tls_used")
#pragma comment(linker,"/INCLUDE:_fixture_early_callback")
static void iat(DWORD rva,void *fn){DWORD old;VirtualProtect(dll+rva,4,PAGE_READWRITE,&old);*(void **)(dll+rva)=fn;VirtualProtect(dll+rva,4,old,&old);}
static void jump_to(void *from,void *to){DWORD old;VirtualProtect(from,5,PAGE_EXECUTE_READWRITE,&old);*(BYTE *)from=0xe9;*(int *)((BYTE *)from+1)=(BYTE *)to-((BYTE *)from+5);VirtualProtect(from,5,old,&old);FlushInstructionCache(GetCurrentProcess(),from,5);}
static unsigned __cdecl no_spawn(void){return 0;}
static void __cdecl logger(const char *s,unsigned n){char message[1024];unsigned count=n<sizeof(message)-1?n:sizeof(message)-1;memcpy(message,s,count);message[count]=0;log_calls++;if(strstr(message,"installed"))installed_logs++;printf("native_log=%s\n",message);}
static HMODULE WINAPI main_module(LPCWSTR name){if(name){api_bad++;return 0;}return(HMODULE)fake_main;}
static BOOL WINAPI protect_game(void *address,SIZE_T bytes,DWORD protection,DWORD *old){
 protection_calls++;
 if((BYTE *)address<game||(BYTE *)address+bytes>game+game_size)api_bad++;
 if((fail_protect&&protection_calls==fail_protect)||(fail_protect_again&&protection_calls==fail_protect_again)){protect_failures++;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 return VirtualProtect(address,bytes,protection,old);
}
static BOOL WINAPI flush_game(HANDLE process,LPCVOID address,SIZE_T bytes){
 flush_calls++;
 if(process!=(HANDLE)-1||(const BYTE *)address<game||(const BYTE *)address+bytes>game+game_size)api_bad++;
 if(fail_flush&&flush_calls==fail_flush){flush_failures++;SetLastError(ERROR_ACCESS_DENIED);return FALSE;}
 return FlushInstructionCache(process,address,bytes);
}
static int check(int ok,const char *why){assertions++;if(!ok){printf("FAIL case=%s assertion=%s win32=%lu\n",case_name,why,GetLastError());failed_cases++;}return ok;}
#define CHECK(x) do{if(!check(!!(x),#x))return 0;}while(0)
static DWORD status(void){return *(DWORD *)(dll+0x2f5500+984);}
static void invoke(void){((void(__cdecl *)(void *,void *,void *,DWORD))(dll+0x316000))(0,0,0,0);}
static void writable(void){DWORD old;VirtualProtect(game,game_size,PAGE_READWRITE,&old);}
static void reset_counts(void){protection_calls=flush_calls=fail_protect=fail_protect_again=fail_flush=protect_failures=flush_failures=log_calls=installed_logs=api_bad=0;}
static void snapshot(void){DWORD old;memcpy(before,game,game_size);VirtualProtect(game,game_size,PAGE_READONLY,&old);reset_counts();}
static void prepare(const char *name){case_name=name;writable();memcpy(game,original,game_size);memset(dll+0x2f5500,0,0xb00);fake_main=game;snapshot();}
static int unchanged(void){return memcmp(game,before,game_size)==0;}
static int all_readonly(void){BYTE *at=game;MEMORY_BASIC_INFORMATION m;while(at<game+game_size){if(!VirtualQuery(at,&m,sizeof m)||m.Protect!=PAGE_READONLY)return 0;at=(BYTE *)m.BaseAddress+m.RegionSize;}return 1;}
static int edited_exactly(void){
 DWORD changed=0,wanted=0;
 for(unsigned e=0;e<EDITS;e++){CHECK(!memcmp(game+edits[e].rva,edits[e].after,edits[e].n));for(DWORD k=0;k<edits[e].n;k++)wanted+=edits[e].before[k]!=edits[e].after[k];}
 for(DWORD i=0;i<game_size;i++)if(game[i]!=before[i]){int approved=0;for(unsigned e=0;e<EDITS;e++)if(i>=edits[e].rva&&i<edits[e].rva+edits[e].n)approved=1;CHECK(approved);changed++;}
 CHECK(changed==wanted);printf("installed_instruction_spans=5 span_bytes=27 actual_changed_bytes=%lu\n",changed);return 1;
}
static void pass_case(void){printf("CASE_PASS name=%s status=%lu protects=%lu flushes=%lu logs=%lu installed_logs=%lu\n",case_name,status(),protection_calls,flush_calls,log_calls,installed_logs);successful_cases++;}
static int accepted(void){
 prepare("exact-authenticated-game");invoke();CHECK(status()==1);CHECK(edited_exactly());CHECK(protection_calls==2*PAGES);CHECK(flush_calls==EDITS);CHECK(!api_bad);CHECK(all_readonly());CHECK(installed_logs>=1);
 DWORD protects=protection_calls,flushes=flush_calls;memcpy(before,game,game_size);invoke();CHECK(status()==1);CHECK(unchanged());CHECK(protection_calls==protects&&flush_calls==flushes);pass_case();return 1;
}
static int already_applied(void){prepare("already-all-applied");writable();for(unsigned i=0;i<EDITS;i++)memcpy(game+edits[i].rva,edits[i].after,edits[i].n);snapshot();invoke();CHECK(status()==1);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(all_readonly());pass_case();return 1;}
static int partial(void){for(unsigned i=0;i<EDITS;i++){prepare("partial-existing-patch");writable();memcpy(game+edits[i].rva,edits[i].after,edits[i].n);snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(!installed_logs);CHECK(all_readonly());pass_case();}return 1;}
static int incompatible_bytes(void){
 for(unsigned i=0;i<EDITS;i++){prepare("changed-edit-instruction");writable();game[edits[i].rva]^=0x55;snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(!installed_logs);CHECK(all_readonly());pass_case();}
 DWORD markers[]={0x2a34a5,0x287070,0x954820,0x953ec0,0x953f20,0x953f60};
 for(unsigned i=0;i<sizeof(markers)/sizeof(markers[0]);i++){prepare("unsupported-eight-player-marker-or-helper");writable();game[markers[i]]^=0x55;snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(!installed_logs);CHECK(all_readonly());pass_case();}
 return 1;
}
static int malformed_header(void){
 for(unsigned i=0;i<9;i++){
  prepare("unsupported-game-PE");writable();IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)game;IMAGE_NT_HEADERS32 *nt=(IMAGE_NT_HEADERS32 *)(game+dos->e_lfanew);
  switch(i){case 0:fake_main=0;break;case 1:dos->e_magic=0;break;case 2:dos->e_lfanew=0x10;break;case 3:dos->e_lfanew=0x1001;break;case 4:nt->Signature=0;break;case 5:nt->FileHeader.Machine=IMAGE_FILE_MACHINE_AMD64;break;case 6:nt->OptionalHeader.Magic=IMAGE_NT_OPTIONAL_HDR64_MAGIC;break;case 7:nt->OptionalHeader.SizeOfImage=0x2a37ff;break;case 8:nt->OptionalHeader.SizeOfImage=0x2000001;break;}
  snapshot();invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(!installed_logs);CHECK(all_readonly());pass_case();
 }return 1;
}
static int protect_preparation_failures(void){
 for(unsigned i=1;i<=PAGES;i++){
  prepare("VirtualProtect-preparation-denial");fail_protect=i;invoke();CHECK(status()==3);CHECK(unchanged());CHECK(protect_failures==1);CHECK(!flush_calls);CHECK(!api_bad);CHECK(!installed_logs);CHECK(all_readonly());
  fail_protect=0;invoke();CHECK(status()==1);CHECK(edited_exactly());CHECK(!api_bad);CHECK(all_readonly());CHECK(installed_logs>=1);pass_case();
 }return 1;
}
static int protect_rollback_failures(void){
 for(unsigned prep=2;prep<=PAGES;prep++)for(unsigned rollback=1;rollback<prep;rollback++){
  prepare("VirtualProtect-preparation-and-rollback-denial");fail_protect=prep;fail_protect_again=prep+rollback;
  invoke();CHECK(status()==3);CHECK(unchanged());CHECK(protect_failures==2);CHECK(!flush_calls);CHECK(!api_bad);CHECK(!installed_logs);CHECK(!all_readonly());
  fail_protect=fail_protect_again=0;invoke();CHECK(status()==1);CHECK(edited_exactly());CHECK(!api_bad);CHECK(all_readonly());CHECK(installed_logs>=1);pass_case();
 }return 1;
}
static int post_write_failures(void){
 for(unsigned mode=0;mode<2;mode++)for(unsigned i=1;i<=(mode?EDITS:PAGES);i++){
  prepare(mode?"FlushInstructionCache-post-write-denial":"VirtualProtect-restore-denial");
  if(mode)fail_flush=i;else fail_protect=PAGES+i;
  invoke();CHECK(status()==4);CHECK(edited_exactly());CHECK(!api_bad);CHECK(!installed_logs);CHECK(mode?flush_failures==1:protect_failures==1);
  /* Keep pending installer ownership; do not clear State before recovery. */
  memcpy(before,game,game_size);fail_protect=fail_flush=0;invoke();CHECK(status()==1);CHECK(unchanged());CHECK(!api_bad);CHECK(all_readonly());CHECK(installed_logs>=1);pass_case();
 }return 1;
}
static BYTE *read_game(const char *path){
 FILE *f=fopen(path,"rb");if(!f)return 0;fseek(f,0,SEEK_END);long bytes=ftell(f);fseek(f,0,SEEK_SET);if(bytes<0x1000){fclose(f);return 0;}
 BYTE *file=VirtualAlloc((void *)0x30000000,(size_t)bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!file){fclose(f);return 0;}if(fread(file,1,(size_t)bytes,f)!=(size_t)bytes){fclose(f);VirtualFree(file,0,MEM_RELEASE);return 0;}fclose(f);
 IMAGE_DOS_HEADER *dos=(IMAGE_DOS_HEADER *)file;if(dos->e_magic!=IMAGE_DOS_SIGNATURE||dos->e_lfanew<0x40||dos->e_lfanew>0x1000){VirtualFree(file,0,MEM_RELEASE);return 0;}
 IMAGE_NT_HEADERS32 *nt=(IMAGE_NT_HEADERS32 *)(file+dos->e_lfanew);if(nt->Signature!=IMAGE_NT_SIGNATURE||nt->OptionalHeader.SizeOfImage>0x2000000){VirtualFree(file,0,MEM_RELEASE);return 0;}game_size=nt->OptionalHeader.SizeOfImage;
 BYTE *mapped=VirtualAlloc((void *)0x40000000,game_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!mapped){VirtualFree(file,0,MEM_RELEASE);return 0;}
 memcpy(mapped,file,nt->OptionalHeader.SizeOfHeaders);IMAGE_SECTION_HEADER *sec=IMAGE_FIRST_SECTION(nt);
 for(unsigned i=0;i<nt->FileHeader.NumberOfSections;i++){if(sec[i].VirtualAddress+sec[i].SizeOfRawData>game_size||sec[i].PointerToRawData+sec[i].SizeOfRawData>(DWORD)bytes){VirtualFree(mapped,0,MEM_RELEASE);VirtualFree(file,0,MEM_RELEASE);return 0;}memcpy(mapped+sec[i].VirtualAddress,file+sec[i].PointerToRawData,sec[i].SizeOfRawData);}
 VirtualFree(file,0,MEM_RELEASE);return mapped;
}
int main(int argc,char **argv){
 if(argc!=6)return 2;freopen(argv[3],"w",stdout);setbuf(stdout,0);DWORD terminal_rva=strtoul(argv[4],0,0),recovery_rva=strtoul(argv[5],0,0);
 original=read_game(argv[2]);if(!original){printf("bad-game-PE\n");return 3;}for(unsigned i=0;i<EDITS;i++)if(memcmp(original+edits[i].rva,edits[i].before,edits[i].n)){printf("bad-game-instruction=%u\n",i);return 4;}
 game=VirtualAlloc((void *)0x400000,game_size,MEM_COMMIT|(game_reservation?0:MEM_RESERVE),PAGE_READWRITE);if(!game){printf("game-map-error=%lu\n",GetLastError());return 5;}
 dll=(BYTE *)LoadLibraryA(argv[1]);if(!dll){printf("load-error=%lu\n",GetLastError());return 6;}
 printf("native_dll_base=%p terminal_target=%p game_data=%p\n",dll,dll+terminal_rva,game);
 iat(0x210198,main_module);iat(0x21020c,protect_game);iat(0x210258,flush_game);jump_to(dll+0xf2b70,no_spawn);jump_to(dll+0x14d190,logger);
 *(int *)(edits[2].after+1)=(dll+0x3160e0)-((BYTE *)0x400000+edits[2].rva+5);
 *(int *)(edits[3].after+1)=(dll+terminal_rva)-((BYTE *)0x400000+edits[3].rva+5);
 *(int *)(edits[4].after+1)=(dll+recovery_rva)-((BYTE *)0x400000+edits[4].rva+5);
 before=VirtualAlloc((void *)0x50000000,game_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!before)return 7;
 if(!accepted()||!already_applied()||!partial()||!incompatible_bytes()||!malformed_header()||!protect_preparation_failures()||!protect_rollback_failures()||!post_write_failures())return 40;
 VirtualFree(game,0,MEM_RELEASE);game=VirtualAlloc((void *)0x10000000,game_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!game)return 8;
 prepare("unsupported-relocated-game");invoke();CHECK(status()==2);CHECK(unchanged());CHECK(!protection_calls&&!flush_calls);CHECK(!installed_logs);CHECK(all_readonly());pass_case();
 printf("PASS installer_cases=%lu assertions=%lu failures=%lu instruction_spans=5 span_bytes=27 no_game_code_executed=1\n",successful_cases,assertions,failed_cases);return failed_cases?40:0;
}
