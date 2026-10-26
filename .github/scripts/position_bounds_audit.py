"""Read-only investigation of coordinate assertions in an already public runtime.
Does not modify the executable, supply a patch, or execute a game simulation.
Only bounded instruction excerpts and metadata are emitted; no game image upload.
"""
from pathlib import Path
from collections import deque
import argparse, hashlib, json, re, struct
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

p=argparse.ArgumentParser();p.add_argument('image');p.add_argument('output');a=p.parse_args()
path=Path(a.image);raw=path.read_bytes();pe=pefile.PE(data=raw,fast_load=True)
assert pe.FILE_HEADER.Machine==0x14c
base=pe.OPTIONAL_HEADER.ImageBase
out=Path(a.output);out.mkdir(parents=True,exist_ok=True)
report={'scope':'Static disassembly of launcher-prepared public image. No full gameplay, no patch applied.',
        'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'image_base':hex(base),'strings':[],'sites':[]}
needles=[b'Drawable/Object position too large',b'Drawable/Object position NAN',b'm_cachedPos.X()',b'm_cachedPos.x']
seen=set()
for needle in needles:
    at=0
    while True:
        at=raw.find(needle,at)
        if at<0:break
        begin=raw.rfind(b'\0',max(0,at-256),at)+1
        end=raw.find(b'\0',at)
        if end<0:end=min(len(raw),at+512)
        va=base+pe.get_rva_from_offset(begin)
        if va not in seen:
            seen.add(va);report['strings'].append({'va':hex(va),'offset':begin,'text':raw[begin:end].decode('ascii','replace')})
        at+=len(needle)
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.skipdata=True
for sec in pe.sections:
    if not sec.Characteristics&0x20000000:continue
    data=sec.get_data();start=base+sec.VirtualAddress
    refs=[]
    for s in report['strings']:
        needle=struct.pack('<I',int(s['va'],16));at=0
        while True:
            at=data.find(needle,at)
            if at<0:break
            refs.append((start+at,s['va']));at+=1
    refs.sort()
    if not refs:continue
    assert len(refs)<64,'Unexpectedly many references'
    windows=[];prior=deque(maxlen=70);idx=0;active=[]
    for address,size,mnemonic,operands in cs.disasm_lite(data,start):
        row={'va':hex(address),'bytes':data[address-start:address-start+size].hex(),'asm':mnemonic+' '+operands}
        for w in active:
            if w['remaining']>0:w['instructions'].append(row);w['remaining']-=1
        while idx<len(refs)and refs[idx][0]<address+size:
            ref,stringva=refs[idx];idx+=1
            if ref>=address:
                w={'reference_va':hex(address),'string_va':stringva,'instructions':list(prior)+[row],'remaining':50}
                windows.append(w);active.append(w)
        prior.append(row)
        active=[w for w in active if w['remaining']>0]
        if idx==len(refs)and not active:break
    for w in windows:
        w.pop('remaining',None);constants={}
        for row in w['instructions']:
            for hx in re.findall(r'\[(0x[0-9a-f]+)\]',row['asm']):
                va=int(hx,16)
                try:
                    if not(base<=va<base+pe.OPTIONAL_HEADER.SizeOfImage):continue
                    off=pe.get_offset_from_rva(va-base);b=raw[off:off+8]
                    if len(b)<4:continue
                    f=struct.unpack('<f',b[:4])[0]
                    if abs(f)>=100 and abs(f)<=1e10:
                        constants[hx]={'raw4':b[:4].hex(),'float32':f}
                except (ValueError,pefile.PEFormatError):pass
        w['possible_float_constants']=constants
    report['sites']+=windows
assert report['strings'],'No coordinate assertion strings found'
(out/'position_bounds.json').write_text(json.dumps(report,indent=2),encoding='utf8')
text=[]
text.append('IMAGE '+report['sha256']+' BASE '+hex(base))
text.append(report['scope'])
for s in report['strings']:text.append('STRING '+s['va']+' '+s['text'])
for w in report['sites']:
    text.append('\nREFERENCE '+w['reference_va']+' -> '+w['string_va'])
    for r in w['instructions']:text.append(r['va']+'  '+r['bytes']+'  '+r['asm'])
    text.append('FLOAT_CANDIDATES '+json.dumps(w['possible_float_constants'],sort_keys=True))
(out/'position_bounds.txt').write_text('\n'.join(text)+'\n',encoding='utf8')
print('\n'.join(text))
