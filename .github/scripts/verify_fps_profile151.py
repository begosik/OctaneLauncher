"""Inspect the opaque FPS component only from verified public packages.

No publisher key, source tree, standalone game/DLL or installer is used. The
profile fingerprint is checked against the exact supplied active RPF bytes.
"""
from pathlib import Path
import hashlib,hmac,json,shutil,struct,subprocess,sys,zipfile

def require(ok):
    if not ok:raise ValueError('Public FPS profile fingerprint check failed')
def sha(b):return hashlib.sha256(b).hexdigest()
def read(p,name):
    with zipfile.ZipFile(p)as z:return z.read('RA3Octane/'+name)

def main():
    baseline,target,manifest,layout,output=map(Path,sys.argv[1:])
    m=json.loads(manifest.read_text());cfg=json.loads(layout.read_text())
    require(sha(baseline.read_bytes())==m['base_zip_sha256']and sha(target.read_bytes())==m['archive_sha256'])
    old=read(baseline,'RA3Octane.exe');pack=read(target,'patches.octpack')
    enc,mac=(old[o:o+32]for o in m['client_material_offsets'])
    n=struct.unpack_from('<Q',pack,24)[0]
    require(pack[:8]==b'OCTPACK1'and n%16==0 and n+448==len(pack))
    require(hmac.compare_digest(pack[32+n:64+n],hmac.new(mac,pack[:32+n],'sha256').digest()))
    openssl=shutil.which('openssl')or'C:/Program Files/Git/usr/bin/openssl.exe'
    result=subprocess.run([openssl,'enc','-d','-aes-256-cbc','-K',enc.hex(),'-iv',pack[8:24].hex()],input=pack[32:32+n],capture_output=True)
    require(result.returncode==0);clear=result.stdout
    if clear[:8]==b'OCTLZ401':
        expected=struct.unpack_from('<I',clear,8)[0];require(0<expected<64*1024*1024)
        src=clear[12:];data=bytearray();at=0
        def length(base):
            nonlocal at
            n=base
            if base==15:
                while True:
                    require(at<len(src));v=src[at];at+=1;n+=v
                    require(n<=expected)
                    if v!=255:break
            return n
        while at<len(src):
            token=src[at];at+=1;n=length(token>>4);require(at+n<=len(src)and len(data)+n<=expected)
            data+=src[at:at+n];at+=n
            if at==len(src):break
            require(at+2<=len(src));off=int.from_bytes(src[at:at+2],'little');at+=2;n=length(token&15)+4
            require(0<off<=len(data)and len(data)+n<=expected)
            chunk=bytes(data[-off:]);data+=(chunk*((n+off-1)//off))[:n]
        require(len(data)==expected);clear=bytes(data)
    require(clear[:8]==b'OCTPAY01');at=8
    def take(n):
        nonlocal at
        require(isinstance(n,int)and 0<=n<=len(clear)-at);b=clear[at:at+n];at+=n;return b
    def u32():return struct.unpack('<I',take(4))[0]
    def u64():return struct.unpack('<Q',take(8))[0]
    def text():return take(struct.unpack('<H',take(2))[0]).decode('utf8','strict')
    label=text();require(label==cfg['package_label']);games=u32();require(0<games<=16)
    for _ in range(games):
        text();take(96);fields=struct.unpack('<9I',take(36));require(fields[-1]<=16);take(fields[-1]*8)
        edits=u32();require(edits<=65536)
        for _ in range(edits):
            u32();n=u32();require(n<=32*1024*1024);take(n*2)
        take(u32())
    resources=u32();require(resources==1)
    for _ in range(resources):
        text();take(64);u64();u64();operations=u32();require(operations<=65536)
        for _ in range(operations):
            mode=take(1)[0]
            if mode==0:u64();u64()
            elif mode==1:take(u64())
            else:require(False)
    size=u32();digest=take(32);profile=take(size)
    require(hashlib.sha256(profile).digest()==digest)
    require(size==cfg['profile_component_bytes']and sha(profile)==cfg['profile_component_sha256'])
    require(profile[:8]==b'R3PACK01'and len(profile)>=56)
    rx,ds,dvs,reloc,edits,guards,base,log_rva=struct.unpack_from('<8I',profile,24)
    require(edits==cfg['profile_component_edits'] and guards==cfg['profile_component_guards'] and base==0x400000)
    at_rpf=56+rx+ds+4*reloc;require(at_rpf<=len(profile))
    for _ in range(edits):
        require(at_rpf+12<=len(profile));_,n,k=struct.unpack_from('<3I',profile,at_rpf)
        require(0<n<=4096 and k<=64);at_rpf+=12+2*n+4*k;require(at_rpf<=len(profile))
    for _ in range(guards):
        require(at_rpf+8<=len(profile));_,n=struct.unpack_from('<2I',profile,at_rpf);require(0<n<=16384)
        at_rpf+=8+n;require(at_rpf<=len(profile))
    require(at_rpf==len(profile))
    report={'passed':True,'component':'exact supplied active RA3FPS 1.0.26 RPF',
            'component_sha256':sha(profile),'component_bytes':size,'edits':edits,'guards':guards,
            'package_sha256':sha(target.read_bytes()),'package_label':label,
            'payload_C_source_rebuilt':False,'gameplay_or_network_tested':False}
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(report,indent=2)+'\n')
    print('PUBLIC_FPS_PROFILE_VERIFIED',size,sha(profile),edits,guards)

if __name__=='__main__':main()
