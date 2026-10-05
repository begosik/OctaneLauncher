"""Extract a test fixture only from the verified PUBLIC packages; never publish it."""
from pathlib import Path
import hashlib,hmac,json,struct,subprocess,sys,zipfile,shutil
m=json.loads(Path(sys.argv[3]).read_text());out=Path(sys.argv[4]);out.mkdir(parents=True,exist_ok=True)
def read(p,n):
 with zipfile.ZipFile(p)as z:return z.read('RA3Octane/'+n)
old=read(sys.argv[1],'RA3Octane.exe');pack=read(sys.argv[2],'patches.octpack')
assert hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest()==m['base_zip_sha256']
assert hashlib.sha256(Path(sys.argv[2]).read_bytes()).hexdigest()==m['archive_sha256']
e,mac=(old[o:o+32]for o in m['client_material_offsets']);n=struct.unpack_from('<Q',pack,24)[0]
assert n+448==len(pack)and hmac.compare_digest(pack[32+n:64+n],hmac.new(mac,pack[:32+n],'sha256').digest())
openssl=shutil.which('openssl')or'C:/Program Files/Git/usr/bin/openssl.exe'
p=subprocess.run([openssl,'enc','-d','-aes-256-cbc','-K',e.hex(),'-iv',pack[8:24].hex()],input=pack[32:32+n],capture_output=True,check=True).stdout
if p[:8]==b'OCTLZ401':
 target=struct.unpack_from('<I',p,8)[0];assert 0<target<64*1024*1024;src=p[12:];p=bytearray();a=0
 def length(base):
  global a
  n=base
  if base==15:
   while True:
    assert a<len(src);v=src[a];a+=1;n+=v
    if v!=255:break
  return n
 while a<len(src):
  token=src[a];a+=1;size=length(token>>4);assert a+size<=len(src)and len(p)+size<=target;p+=src[a:a+size];a+=size
  if a==len(src):break
  assert a+2<=len(src);off=int.from_bytes(src[a:a+2],'little');a+=2;size=length(token&15)+4;assert 0<off<=len(p)and len(p)+size<=target
  chunk=bytes(p[-off:]);p+=(chunk*((size+off-1)//off))[:size]
 assert len(p)==target;p=bytes(p)
assert p[:8]==b'OCTPAY01',p[:8]
a=p.rfind(b'OCTBN001');assert a>0;n=struct.unpack_from('<I',p,a+72)[0];dll=p[a+76:a+76+n]
assert len(dll)==n and hashlib.sha256(dll).digest()==p[a+40:a+72]
(out/'patched.dll').write_bytes(dll)
print('Public NativeDll fixture verified',len(dll),hashlib.sha256(dll).hexdigest())
