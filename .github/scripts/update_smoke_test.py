"""Exercise the public updater in an isolated Windows runner, without RA3.
DrawText observation is test-process-only and is removed before installation.
No launcher sources, signing material, or game data are used by this test.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import struct
import time
import zipfile

K=C.WinDLL('kernel32',use_last_error=True)
U=C.WinDLL('user32',use_last_error=True)
P=C.c_void_p
SZ=C.c_size_t
D=W.DWORD

def fn(lib,name,args,result):
    f=getattr(lib,name);f.argtypes=args;f.restype=result;return f

create=fn(K,'CreateProcessW',[W.LPCWSTR,W.LPWSTR,P,P,W.BOOL,D,P,W.LPCWSTR,P,P],W.BOOL)
wait=fn(K,'WaitForDebugEvent',[P,D],W.BOOL)
cont=fn(K,'ContinueDebugEvent',[D,D,D],W.BOOL)
read=fn(K,'ReadProcessMemory',[P,P,P,SZ,P],W.BOOL)
write=fn(K,'WriteProcessMemory',[P,P,P,SZ,P],W.BOOL)
protect=fn(K,'VirtualProtectEx',[P,P,SZ,D,P],W.BOOL)
flush=fn(K,'FlushInstructionCache',[P,P,SZ],W.BOOL)
thread=fn(K,'OpenThread',[D,W.BOOL,D],P)
getctx=fn(K,'GetThreadContext',[P,P],W.BOOL)
setctx=fn(K,'SetThreadContext',[P,P],W.BOOL)
close=fn(K,'CloseHandle',[P],W.BOOL)
detach=fn(K,'DebugActiveProcessStop',[D],W.BOOL)
killdebug=fn(K,'DebugSetProcessKillOnExit',[W.BOOL],W.BOOL)
terminate=fn(K,'TerminateProcess',[P,D],W.BOOL)
post=fn(U,'PostMessageW',[P,W.UINT,SZ,C.c_ssize_t],W.BOOL)
text=fn(U,'GetWindowTextW',[P,W.LPWSTR,C.c_int],C.c_int)
getpid=fn(U,'GetWindowThreadProcessId',[P,P],D)
getdlg=fn(U,'GetDlgItem',[P,C.c_int],P)
visible=fn(U,'IsWindowVisible',[P],W.BOOL)
openproc=fn(K,'OpenProcess',[D,W.BOOL,D],P)
queryexe=fn(K,'QueryFullProcessImageNameW',[P,D,W.LPWSTR,P],W.BOOL)
CB=C.WINFUNCTYPE(W.BOOL,P,C.c_ssize_t)
enum=fn(U,'EnumWindows',[CB,C.c_ssize_t],W.BOOL)
enumchild=fn(U,'EnumChildWindows',[P,CB,C.c_ssize_t],W.BOOL)

def checked(value):
    if not value:raise C.WinError(C.get_last_error())
    return value

def word(buf,off,n=4):return int.from_bytes(bytes(buf[off:off+n]),'little')

def rpm(process,address,size):
    buf=C.create_string_buffer(size);done=SZ()
    checked(read(process,address,buf,size,C.byref(done)))
    if done.value!=size:raise RuntimeError('Short test-process read')
    return buf.raw

def patch(process,address,data):
    old=D();checked(protect(process,address,len(data),0x40,C.byref(old)))
    try:
        b=C.create_string_buffer(data);done=SZ()
        checked(write(process,address,b,len(data),C.byref(done)))
        checked(flush(process,address,len(data)))
    finally:
        ignored=D();checked(protect(process,address,len(data),old.value,C.byref(ignored)))

def import_slot(data,wanted):
    u16=lambda o:struct.unpack_from('<H',data,o)[0]
    u32=lambda o:struct.unpack_from('<I',data,o)[0]
    u64=lambda o:struct.unpack_from('<Q',data,o)[0]
    pe=u32(60);op=pe+24;st=op+u16(pe+20)
    assert data[:2]==b'MZ' and u16(op)==0x20b
    def off(rva):
        for i in range(u16(pe+6)):
            p=st+40*i;va=u32(p+12);n=u32(p+16)
            if va<=rva<va+n:return u32(p+20)+rva-va
        raise ValueError('Invalid PE address')
    p=off(u32(op+120))
    while any(data[p:p+20]):
        original=u32(p);first=u32(p+16);q=off(original or first);i=0
        while u64(q+8*i):
            item=u64(q+8*i)
            if not item>>63:
                name=off(item)+2
                if data[name:data.index(0,name)]==wanted:return first+8*i
            i+=1
        p+=20
    raise ValueError('DrawText import not found')

def window_title(hwnd):
    b=C.create_unicode_buffer(2048);text(hwnd,b,len(b));return b.value

def windows(pid=None,root=None):
    result=[]
    @CB
    def visit(hwnd,_):
        p=D();getpid(hwnd,C.byref(p))
        match=(pid is None or p.value==pid)
        if match and root is not None:
            h=openproc(0x1000,False,p.value)
            if not h:return True
            try:
                b=C.create_unicode_buffer(32768);n=D(len(b))
                match=bool(queryexe(h,0,b,C.byref(n))) and Path(b.value).parent==root
            finally:close(h)
        if match and visible(hwnd):result.append((hwnd,p.value,window_title(hwnd)))
        return True
    checked(enum(visit,0));return result

def labels(hwnd):
    found=[]
    @CB
    def visit(child,_):found.append(window_title(child));return True
    enumchild(hwnd,visit,0)
    return ' '.join(found)

def capture_update_button(exe,root):
    data=exe.read_bytes();iat=import_slot(data,b'DrawTextW')
    startup=C.create_string_buffer(104);struct.pack_into('<I',startup,0,104)
    pi=C.create_string_buffer(24);command=C.create_unicode_buffer('"'+str(exe)+'"')
    checked(create(str(exe),command,None,None,False,2,None,str(root),startup,pi))
    process=word(pi.raw,0,8);pid=word(pi.raw,16);mainthread=word(pi.raw,8,8)
    checked(killdebug(False))
    base=0;address=0;saved=None;stepping=set();button=None;observed=set();began=time.monotonic();attached=True
    try:
        while time.monotonic()-began<45:
            event=C.create_string_buffer(176)
            if not wait(event,250):continue
            raw=event.raw;kind,epid,tid=struct.unpack_from('<III',raw);status=0x10002;finish=False
            if kind==3:
                base=word(raw,40,8)
                hfile=word(raw,16,8)
                if hfile:close(hfile)
            elif kind==6:
                hfile=word(raw,16,8)
                if hfile:close(hfile)
            elif kind==5:
                checked(cont(epid,tid,status));attached=False
                raise RuntimeError('Launcher exited before the update control was observed')
            elif kind==1:
                code=word(raw,16);where=word(raw,32,8)
                if code==0x80000003 and not address:
                    address=int.from_bytes(rpm(process,base+iat,8),'little')
                    saved=rpm(process,address,1);patch(process,address,b'\xcc')
                elif (code==0x80000003 and where==address) or (code==0x80000004 and tid in stepping):
                    h=checked(thread(0x1fffff,False,tid));allocation=C.create_string_buffer(1250);context=(C.addressof(allocation)+15)&~15
                    C.c_uint32.from_address(context+48).value=0x100003
                    try:
                        checked(getctx(h,context))
                        flags=C.c_uint32.from_address(context+68)
                        if code==0x80000003:
                            string=C.c_uint64.from_address(context+136).value
                            rectptr=C.c_uint64.from_address(context+192).value
                            try:
                                value=rpm(process,string,512).decode('utf-16le','ignore').split('\0')[0]
                                rect=struct.unpack('<4i',rpm(process,rectptr,16))
                                if 'UPDATE' in value.upper():observed.add(value[:160])
                                if value.strip().upper()=='INSTALL UPDATE':button=rect
                            except OSError:pass
                            patch(process,address,saved)
                            C.c_uint64.from_address(context+248).value=address
                            flags.value|=0x100;stepping.add(tid)
                        else:
                            flags.value&=~0x100;stepping.remove(tid)
                            if button is not None:finish=True
                            else:patch(process,address,b'\xcc')
                        checked(setctx(h,context))
                    finally:close(h)
                else:status=0x80010001
            checked(cont(epid,tid,status))
            if finish:break
        if stepping:raise RuntimeError('Test debugger could not finish a step safely')
        if saved is not None:patch(process,address,saved)
        checked(detach(pid));attached=False
        print('Observed update captions:',json.dumps(sorted(observed)))
        return process,pid,button
    except Exception:
        if saved is not None:
            try:patch(process,address,saved)
            except OSError:pass
        terminate(process,2)
        if attached:detach(pid)
        close(process)
        raise
    finally:close(mainthread)

def main():
    if os.name!='nt' or C.sizeof(P)!=8:raise RuntimeError('Windows x64 test only')
    root=Path(os.environ['RUNNER_TEMP'])/'octane-self-update'
    root.mkdir()
    packages={
        '1.2.31':'fd37b7d219ea8faa3d0bf1c258d5499a91270cc6c35b34bd8826bf19f2fcbdcd',
        '1.2.32':'0337ed762d57fa24a59033d4b3c65084a98867275cc89dfad2cf4af08b84ef73',
    }
    files={}
    for v,digest in packages.items():
        p=Path('RA3Octane_'+v+'_Players_Compact.zip')
        assert hashlib.sha256(p.read_bytes()).hexdigest()==digest
        with zipfile.ZipFile(p) as z:
            files[v]={n:z.read('RA3Octane/'+n) for n in ('RA3Octane.exe','patches.octpack','release.oct')}
    for n,data in files['1.2.31'].items():(root/n).write_bytes(data)
    process=None
    try:
        process,pid,button=capture_update_button(root/'RA3Octane.exe',root)
        if button is None:raise RuntimeError('Install Update was not displayed; no update was initiated')
        candidates=windows(pid=pid)
        if len(candidates)!=1:raise RuntimeError('Unexpected launcher windows before update')
        hwnd=candidates[0][0];l,t,r,b=button;x=(l+r)//2;y=(t+b)//2
        checked(post(hwnd,0x201,1,(y<<16)|(x&65535)))
        checked(post(hwnd,0x202,0,(y<<16)|(x&65535)))
        confirmed=False;deadline=time.monotonic()+15
        while time.monotonic()<deadline and not confirmed:
            for dialog,_,title in windows(pid=pid):
                content=labels(dialog)
                if '1.2.32' in content and 'install' in content.lower() and 'update' in content.lower():
                    yes=getdlg(dialog,6)
                    if yes:checked(post(yes,0xf5,0,0));confirmed=True;break
            time.sleep(.25)
        if not confirmed:raise RuntimeError('Expected 1.2.32 update confirmation was not found')
        print('Confirmed the original launcher update dialog for 1.2.32.')
        deadline=time.monotonic()+70;matched=False
        while time.monotonic()<deadline:
            try:matched=all((root/n).read_bytes()==data for n,data in files['1.2.32'].items())
            except OSError:matched=False
            if matched:break
            time.sleep(.5)
        time.sleep(8)
        print('Installed files exactly match signed 1.2.32:',matched)
        for hwnd,_,title in windows(root=root):
            print('Restarted window:',title)
            post(hwnd,0x10,0,0)
        time.sleep(4)
        leftovers=[]
        for folder in (root/'.update',root/'.updates'):
            if folder.exists():
                for path in folder.rglob('*'):
                    leftovers.append({'path':str(path.relative_to(root)),'directory':path.is_dir(),'bytes':path.stat().st_size if path.is_file() else 0})
        print('UPDATE_WORKSPACE',json.dumps(leftovers))
        log=root/'Logs/launcher.log'
        if log.exists():
            entries=log.read_text(encoding='utf8',errors='replace').splitlines()
            print('UPDATE_LOG',json.dumps([s for s in entries if any(x in s.lower() for x in ('update','backup','recover','signature'))][-22:]))
        print('Runtime scope: public launcher self-update only, not RA3 gameplay.')
        if not matched:raise RuntimeError('Update did not install the expected signed files')
    finally:
        for hwnd,pid,_ in windows(root=root):
            h=openproc(1,False,pid)
            if h:terminate(h,0);close(h)
        if process:close(process)

if __name__=='__main__':main()
