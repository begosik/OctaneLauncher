"""Read-only investigation. Uses public release bytes only. Never publishes a game image."""
from pathlib import Path
import hashlib,json,re,runpy,struct,sys
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32

args=sys.argv[:]
sys.argv=['extract_native141.py','RA3Octane_1.2.40_Players_Compact.zip','RA3Octane_1.2.41_Players_Compact.zip','transport141/1.2.41/manifest.json','private-fixture']
v=runpy.run_path('.github/scripts/extract_native141.py');sys.argv=args
payload=v['p'];images=[]
for m in re.finditer(b'MZ',payload):
 o=m.start()
 try:
  h=struct.unpack_from('<I',payload,o+60)[0]
  if not 64<=h<4096 or payload[o+h:o+h+4]!=b'PE\0\0':continue
  pe=pefile.PE(data=payload[o:],fast_load=True)
  size=max([pe.OPTIONAL_HEADER.SizeOfHeaders]+[s.PointerToRawData+s.SizeOfRawData for s in pe.sections])
  if size>len(payload)-o or pe.FILE_HEADER.Machine!=0x14c:continue
  images.append((o,size,pe.OPTIONAL_HEADER.ImageBase,pe))
 except (ValueError,struct.error,pefile.PEFormatError):pass
print('EMBEDDED_PE',[(o,s,hex(b)) for o,s,b,p in images])
candidates=[x for x in images if x[2]==0x400000 and x[1]>5000000]
if len(candidates)!=1:raise RuntimeError('Expected one complete public game image; raw payload header '+payload[:128].hex())
o,size,base,pe=candidates[0];game=payload[o:o+size];out=Path('inspection');out.mkdir(exist_ok=True)
(out/'identity.json').write_text(json.dumps({'bytes':size,'sha256':hashlib.sha256(game).hexdigest(),'payload_offset':o,'base':hex(base),'scope':'Static read-only inspection of published Octane 1.2.41 target. Not the uploaded Corona DLL. Not gameplay.'},indent=2))
def vaoff(va):return pe.get_offset_from_rva(va-base)
def offva(off):return base+pe.get_rva_from_offset(off)
def occurrences(raw):return [m.start() for m in re.finditer(re.escape(raw),game)]
md=Cs(CS_ARCH_X86,CS_MODE_32);md.skipdata=True
text=[]
for s in pe.sections:
 if s.Characteristics&0x20000000:text.append((base+s.VirtualAddress,s.get_data()))
def refs(va):
 raw=struct.pack('<I',va);a=[]
 for start,blob in text:
  a += [start+m.start() for m in re.finditer(re.escape(raw),blob)]
 return a

def dump(va,n=160):
 try:return '\n'.join('%08X: %-30s %s %s'%(i.address,i.bytes.hex(' '),i.mnemonic,i.op_str) for i in md.disasm(game[vaoff(va):vaoff(va)+n],va))
 except Exception as e:return repr(e)

report=[]
for m in re.finditer(rb'[ -~]{7,}',game):
 s=m.group().decode('ascii')
 if any(k.lower() in s.lower() for k in ['cachedpos','partitionmanager','partitioncell','spatial','broadphase','broad phase','collisiongrid','collision grid','quadtree','OctTree','Quantiz','WorldBounds','WorldSize','MAX_MAP','MapWidth','MapHeight','OutOfSync','out of sync']):
  va=offva(m.start());r=refs(va);report.append({'va':hex(va),'text':s[:500],'refs':[hex(x) for x in r]})
(out/'strings.json').write_text(json.dumps(report,indent=2))
print('RELEVANT_STRINGS',json.dumps(report[:100]))
constants=[]
for n in [750,800,8192,10000,16384,20000,32768,65535,2048,2000]:
 for ty,raw in [('int',struct.pack('<I',n)),('float',struct.pack('<f',n)),('negative_float',struct.pack('<f',-n))]:
  hits=[]
  for off in occurrences(raw):
   try:va=offva(off);r=refs(va)
   except Exception:continue
   if r:hits.append({'constant_va':hex(va),'refs':[hex(x) for x in r]})
  if hits:constants.append({'n':n,'type':ty,'hits':hits})
(out/'constants.json').write_text(json.dumps(constants,indent=2))
print('CONSTANT_REFERENCES',json.dumps(constants))
windows={hex(a):dump(a,n) for a,n in [(0x7ec300,400),(0x7dc960,512),(0x7ec080,512)]}
(out/'object_windows.json').write_text(json.dumps(windows,indent=2))
for a,s in windows.items():print('DISASSEMBLY',a,'\n'+s)
print('INSPECTION_COMPLETE',hashlib.sha256(game).hexdigest())
