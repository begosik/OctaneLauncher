"""Extract canonical game and Native fixtures only from authenticated public packages."""
from pathlib import Path
import runpy,sys,struct,hashlib
scope=runpy.run_path(str(Path(__file__).with_name('extract_native141.py')),run_name='__main__')
p=scope['p'];out=Path(sys.argv[4]);at=8
def take(n):
 global at
 assert 0<=n<=len(p)-at
 b=p[at:at+n];at+=n;return b
def u16():return struct.unpack('<H',take(2))[0]
def u32():return struct.unpack('<I',take(4))[0]
def text():return take(u16()).decode('utf8')
text();count=u32();assert 0<count<=16
text();take(32);target_sha=take(32);take(32)
values=[u32()for _ in range(8)];target_size,prefix=values[1:3]
assert target_size==10059776 and 0<prefix<=target_size
mc=u32();assert mc<=16;take(mc*8)
ec=u32();assert ec<=65536;heads=[]
for _ in range(ec):
 off=u32();n=u32();assert n<=32*1024*1024
 take(n);new=take(n)
 if off==0 and n==prefix:heads.append(new)
tail=take(u32());assert len(heads)==1
game=heads[0]+tail;assert len(game)==target_size
assert hashlib.sha256(game).digest()==target_sha
assert hashlib.sha256(game).hexdigest()=='f1b4ede3229921abd474e0a251fe1880ca98981d9cbf45e4b5c3b8fee08c7a31'
(out/'canonical.game').write_bytes(game)
print('Public canonical game fixture verified',len(game))
