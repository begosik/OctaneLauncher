#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
/* Reserve fake game base in the new suspended fixture, before CRT mappings. */
int main(int argc,char **argv){
 if(argc!=7)return 2;char cmd[8192];STARTUPINFOA si={0};PROCESS_INFORMATION pi={0};si.cb=sizeof si;si.dwFlags=STARTF_USESHOWWINDOW;si.wShowWindow=SW_HIDE;
 if(_snprintf(cmd,sizeof cmd,"\"%s\" \"%s\" \"%s\" \"%s\" \"%s\" \"%s\"",argv[1],argv[2],argv[3],argv[4],argv[5],argv[6])<0)return 3;
 if(!CreateProcessA(argv[1],cmd,0,0,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,0,0,&si,&pi)){printf("create-error=%lu\n",GetLastError());return 4;}
 void *reservation=VirtualAllocEx(pi.hProcess,(void *)0x400000,0x1800000,MEM_RESERVE,PAGE_NOACCESS);
 if(reservation!=(void *)0x400000){printf("child-reservation-error=%lu\n",GetLastError());TerminateProcess(pi.hProcess,40);return 40;}
 if(ResumeThread(pi.hThread)==(DWORD)-1){TerminateProcess(pi.hProcess,40);return 40;}
 DWORD wait=WaitForSingleObject(pi.hProcess,30000),code=40;
 if(wait==WAIT_OBJECT_0)GetExitCodeProcess(pi.hProcess,&code);else{printf("child-timeout\n");TerminateProcess(pi.hProcess,40);WaitForSingleObject(pi.hProcess,1000);}
 CloseHandle(pi.hThread);CloseHandle(pi.hProcess);printf("fixture_exit=%lu\n",code);return(int)code;
}
