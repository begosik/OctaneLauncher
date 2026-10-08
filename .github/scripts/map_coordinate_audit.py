"""Read-only binary audit. No patch, release, private source or user log upload."""
from pathlib import Path
import bisect,hashlib,json,re,struct,sys
import capstone,pefile

root=Path(sys.argv[1]);out=Path('coordinate-audit-results');out.mkdir(exist_ok=True)
paths=[p for p in root.rglob('ra3_1.12.game') if 'session-runtime' in str(p) and p.stat().st_size>4000000]
if not paths:raise SystemExit('No real session image was created; audit not executed')
p=paths[-1];raw=p.read_bytes();pe=pefile.PE(data=raw);base=pe.OPTIONAL_HEADER.ImageBase
lines=[]
def emit(s):lines.append(str(s))
emit('IMAGE '+p.name+' SHA256 '+hashlib.sha256(raw).hexdigest()+' BYTES '+str(len(raw)))
sections=[]
for s in pe.sections:
 name=s.Name.rstrip(b'\0').decode('ascii','replace');sections.append((name,base+s.VirtualAddress,s.get_data(),s.Characteristics))
 emit('SECTION '+name+' VA '+hex(base+s.VirtualAddress)+' SIZE '+hex(s.Misc_VirtualSize))
md=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_32);md.skipdata=True
ins=[]
for name,va,data,flags in sections:
 if flags&0x20000000:ins.extend(md.disasm_lite(data,va))
ins.sort();addrs=[x[0] for x in ins]
def context(address,before=10,after=18):
 i=bisect.bisect_left(addrs,address)
 for a,n,m,o in ins[max(0,i-before):i+after]:emit(f'{a:08X} {m:10} {o}')
const={}
for val in (750.0,800.0,768.0,1024.0,4096.0,7500.0,7680.0,8000.0,8192.0,10000.0,16384.0,32768.0,65536.0):
 for fmt in ('<f','<d'):
  needle=struct.pack(fmt,val)
  for name,va,data,flags in sections:
   if flags&0x20000000:continue
   pos=-1
   while True:
    pos=data.find(needle,pos+1)
    if pos<0:break
    const.setdefault(va+pos,[]).append(f'{val}:{fmt}')
refs={a:[] for a in const}
for a,n,m,o in ins:
 for hx in re.findall(r'0x[0-9a-f]+',o):
  v=int(hx,16)
  if v in refs:refs[v].append(a)
emit('--- NUMERIC CONSTANT REFERENCES ---')
for a,vals in const.items():
 rr=refs[a]
 if rr:
  emit(f'CONSTANT {a:08X} {vals} REFS '+','.join(f'{x:08X}' for x in rr))
  if any(v.startswith(('8192.','8000.','7680.','7500.','10000.')) for v in vals):
   for ref in rr[:40]:context(ref,12,18)
emit('--- SPATIAL / COORDINATE STRINGS ---')
strings=[]
rx=re.compile(rb'[\x20-\x7e]{7,}')
terms=(b'partition',b'cachedPos',b'coord',b'spatial',b'position',b'pathfind',b'out of sync',b'desync',b'syncerror',b'map size',b'map width')
for name,va,data,flags in sections:
 if flags&0x20000000:continue
 for hit in rx.finditer(data):
  txt=hit.group();low=txt.lower()
  if any(t.lower() in low for t in terms):strings.append((va+hit.start(),txt.decode()))
stringrefs={a:[] for a,t in strings}
for a,n,m,o in ins:
 for hx in re.findall(r'0x[0-9a-f]+',o):
  v=int(hx,16)
  if v in stringrefs:stringrefs[v].append(a)
for a,t in strings:
 rr=stringrefs[a];emit(f'STRING {a:08X} {t[:240]} REFS '+','.join(f'{x:08X}'for x in rr[:24]))
 if rr and any(x in t.lower() for x in ('cachedpos','partition','out of sync','syncerror','spatial')):
  for r in rr[:8]:context(r,8,15)
emit('--- INTEGER BOUND / MASK SITES ---')
limits={0x2000,0x1fff,0x8000,0x7fff,0x10000,0xffff,0x3ff,0x3fff}
counts={}
for a,n,m,o in ins:
 if m not in ('and','cmp','test'):continue
 mm=re.search(r', (0x[0-9a-f]+)$',o)
 if mm and int(mm.group(1),16)in limits:
  key=int(mm.group(1),16);counts[key]=counts.get(key,0)+1
  if key in (0x1fff,0x7fff,0x3fff)or (0x580000<=a<=0x850000 and key in (0x8000,0x2000)):
   emit(f'BOUND {a:08X} {m} {o}');context(a,7,9)
emit('COUNTS '+json.dumps({hex(k):v for k,v in counts.items()}))
emit('SCOPE Static disassembly of the actual launcher-created public session image; no game simulation or desync reproduction.')
text='\n'.join(lines)+'\n';(out/'stage1.txt').write_text(text,encoding='utf-8');print(text)
