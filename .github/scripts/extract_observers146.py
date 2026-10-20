"""Extract actual x86 observers only from verified signed public launchers."""
from pathlib import Path
import hashlib,json,struct,sys,zipfile

def need(ok):
    if not ok:raise ValueError('Verified embedded observer extraction failed')
def sha(b):return hashlib.sha256(b).hexdigest()
def imports(b):
    pe=struct.unpack_from('<I',b,60)[0];opt=pe+24;count=struct.unpack_from('<H',b,pe+6)[0]
    st=opt+struct.unpack_from('<H',b,pe+20)[0]
    def u32(at):return struct.unpack_from('<I',b,at)[0]
    def raw(rva,n):
        for i in range(count):
            at=st+40*i;va=u32(at+12);size=u32(at+16);off=u32(at+20)
            if va<=rva and rva-va+n<=size and off+rva-va+n<=len(b):return off+rva-va
        raise ValueError('Unbacked embedded observer import RVA')
    def string(at):
        end=b.find(b'\0',at,at+256);need(end>=at);return b[at:end].decode('ascii')
    directory=u32(opt+104);out=[]
    if not directory:return out
    at=raw(directory,20)
    for _ in range(256):
        thunk,_,_,name,first=struct.unpack_from('<5I',b,at)
        if not any((thunk,name,first)):return sorted(out)
        string(raw(name,1));slot=raw(thunk or first,4)
        for _ in range(2048):
            value=u32(slot);slot+=4
            if not value:break
            if not value&0x80000000:out.append(string(raw(value,3)+2))
        else:need(False)
        at+=20
    need(False)

def extract(launcher):
    hits=[];at=0;marker='octane_diagnostics.log'.encode('utf-16le')
    while True:
        at=launcher.find(b'MZ',at)
        if at<0:break
        try:
            pe=at+struct.unpack_from('<I',launcher,at+60)[0]
            need(at+64<=pe and pe+248<=len(launcher)and launcher[pe:pe+4]==b'PE\0\0')
            machine,count=struct.unpack_from('<HH',launcher,pe+4);flags=struct.unpack_from('<H',launcher,pe+22)[0]
            opt=pe+24;st=opt+struct.unpack_from('<H',launcher,pe+20)[0]
            need(machine==0x14c and 1<=count<=64 and not flags&0x2000 and st+count*40<=len(launcher))
            need(struct.unpack_from('<H',launcher,opt)[0]==0x10b)
            extent=max(struct.unpack_from('<I',launcher,st+40*i+20)[0]+struct.unpack_from('<I',launcher,st+40*i+16)[0]for i in range(count))
            need(512<=extent<2*1024*1024 and at+extent<=len(launcher))
            child=launcher[at:at+extent]
            if marker in child and b'ReadProcessMemory\0'in child:hits.append((child,at))
        except (ValueError,struct.error):pass
        at+=2
    need(len(hits)==1);child,offset=hits[0]
    return child,{'launcher_file_offset':offset,'bytes':len(child),'sha256':sha(child),'imports':imports(child)}

def main():
    baseline,target,manifest,out=map(Path,sys.argv[1:]);m=json.loads(manifest.read_text())
    need(sha(baseline.read_bytes())==m['base_zip_sha256']and sha(target.read_bytes())==m['archive_sha256'])
    out.mkdir(parents=True,exist_ok=True);report={}
    for name,path in [('old',baseline),('new',target)]:
        with zipfile.ZipFile(path)as z:launcher=z.read('RA3Octane/RA3Octane.exe')
        observer,info=extract(launcher);(out/(name+'-observer.exe')).write_bytes(observer);report[name]=info
    need(report['old']['sha256']=='72626dfa734fe72b3d55fea3cb64a2e06f03c69632c7933ed2d03c244f9e7c62')
    debugger={'DebugActiveProcess','DebugActiveProcessStop','WaitForDebugEvent','ContinueDebugEvent','DebugSetProcessKillOnExit'}
    need(debugger<=set(report['old']['imports']))
    thread_or_memory_control={'OpenThread','GetThreadContext','SetThreadContext','SuspendThread','ResumeThread','WriteProcessMemory'}
    need(not (debugger|thread_or_memory_control)&set(report['new']['imports']))
    need({'OpenProcess','ReadProcessMemory','WaitForSingleObject','GetExitCodeProcess'}<=set(report['new']['imports']))
    (out/'observers.json').write_text(json.dumps(report,indent=2)+'\n')
    print('VERIFIED_EMBEDDED_OBSERVERS',report['old']['sha256'],report['new']['sha256'])

if __name__=='__main__':main()
