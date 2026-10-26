"""Execute only the existing coordinate guard in an x86 emulator.
No substitute comparison function: original 37 bytes are read from the public
launcher-prepared image. Stop before diagnostic handlers or continuation code.
This is a branch-level check, not a moving-unit or gameplay test.
"""
from pathlib import Path
from collections import deque
import hashlib,json,struct,sys
import pefile
from capstone import Cs,CS_ARCH_X86,CS_MODE_32
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE
from unicorn.x86_const import UC_X86_REG_ESI,UC_X86_REG_ESP,UC_X86_REG_EFLAGS,UC_X86_REG_MXCSR

raw=Path(sys.argv[1]).read_bytes();out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
pe=pefile.PE(data=raw,fast_load=True);base=pe.OPTIONAL_HEADER.ImageBase
assert base==0x400000 and pe.FILE_HEADER.Machine==0x14c
ENTRY=0x7ec3ba;FAIL=0x7ec3df;PASS=0x7ec465;CONST=0xbe61d4
expected=bytes.fromhex('f30f1005d461be000f2f4638c746480000000076100f2f463c760a0f2f46400f8786000000')
def at(va,n):
    off=pe.get_offset_from_rva(va-base);return raw[off:off+n]
assert at(ENTRY,len(expected))==expected,'Published coordinate predicate changed'
assert struct.unpack('<f',at(CONST,4))[0]==10000.0
assert at(0x7ec437,5)==bytes.fromhex('684c36c500'),'Diagnostic link changed'
assert at(0xc5364c,34).startswith(b'Drawable/Object position too large!')
mu=Uc(UC_ARCH_X86,UC_MODE_32)
mu.mem_map(0x7ec000,0x1000);mu.mem_write(ENTRY,expected);mu.mem_write(PASS,b'\x90')
mu.mem_map(0xbe6000,0x1000);mu.mem_write(CONST,at(CONST,4))
OBJ=0x10000000;STACK=0x20000000
mu.mem_map(OBJ,0x1000);mu.mem_map(STACK,0x1000)
reached=[]
def stop(uc,address,size,user):
    if address in (FAIL,PASS):reached.append(address);uc.emu_stop()
mu.hook_add(UC_HOOK_CODE,stop)
rows=[]
values=[0.0,750.0,800.0,7500.0,8000.0,8192.0,9999.0,9999.9990234375,10000.0,10000.0009765625,15000.0,20000.0]
for axis in range(3):
    for value in values:
        point=[100.0,100.0,50.0];point[axis]=value
        packed=struct.pack('<3f',*point);reached.clear()
        mu.mem_write(OBJ,b'\xa5'*0x100);mu.mem_write(OBJ+0x38,packed)
        mu.reg_write(UC_X86_REG_ESI,OBJ);mu.reg_write(UC_X86_REG_ESP,STACK+0x800)
        mu.reg_write(UC_X86_REG_EFLAGS,2);mu.reg_write(UC_X86_REG_MXCSR,0x1f80)
        mu.emu_start(ENTRY,PASS+1,timeout=1000000,count=32)
        assert len(reached)==1,'Guard did not reach exactly one exit'
        expected_exit=PASS if all(x<10000 for x in point) else FAIL
        assert reached[0]==expected_exit,(point,reached)
        assert mu.mem_read(OBJ+0x38,12)==packed,'Guard modified position'
        assert mu.mem_read(OBJ+0x48,4)==b'\0'*4,'Original cache reset lost'
        rows.append({'axis':'XYZ'[axis],'point':point,'exit':hex(reached[0]),'outcome':'normal_continuation' if reached[0]==PASS else 'too_large_diagnostic_path'})
# Coordinates are compared individually, not by distance from the origin.
point=[8000.0,8000.0,50.0];reached.clear();mu.mem_write(OBJ+0x38,struct.pack('<3f',*point))
mu.reg_write(UC_X86_REG_ESI,OBJ);mu.reg_write(UC_X86_REG_ESP,STACK+0x800);mu.reg_write(UC_X86_REG_EFLAGS,2)
mu.emu_start(ENTRY,PASS+1,timeout=1000000,count=32)
assert reached==[PASS]
rows.append({'axis':'XY','point':point,'exit':hex(PASS),'outcome':'normal_continuation'})
cs=Cs(CS_ARCH_X86,CS_MODE_32);cs.skipdata=True
shared=[]
for sec in pe.sections:
    if not sec.Characteristics&0x20000000:continue
    data=sec.get_data();start=base+sec.VirtualAddress
    positions=[];offset=0;needle=struct.pack('<I',CONST)
    while True:
        offset=data.find(needle,offset)
        if offset<0:break
        positions.append(start+offset);offset+=1
    if not positions:continue
    index=0
    for addr,size,mnem,ops in cs.disasm_lite(data,start):
        while index<len(positions)and positions[index]<addr+size:
            ref=positions[index];index+=1
            if ref>=addr:shared.append({'va':hex(addr),'bytes':data[addr-start:addr-start+size].hex(),'asm':mnem+' '+ops})
        if index==len(positions):break
context=[]
for start,end in [(0x7ec280,0x7ec320),(0x6069f0,0x606b30)]:
    context.append({'start':hex(start),'instructions':[{'va':hex(i.address),'asm':i.mnemonic+' '+i.op_str,'bytes':i.bytes.hex()} for i in cs.disasm(at(start,end-start),start)]})
result={'scope':'Original 37-byte guard executed under Unicorn x86; controlled object memory; stops before all diagnostics and full transform continuation. Not a game or network simulation.',
        'image_sha256':hashlib.sha256(raw).hexdigest(),'guard_va':hex(ENTRY),'guard_bytes':expected.hex(),'constant_va':hex(CONST),'constant_float32':10000.0,'scenarios':len(rows),'all_expected_exits':True,'points':rows,'constant_references':shared,'context':context}
(out/'position_guard_probe.json').write_text(json.dumps(result,indent=2),encoding='utf8')
lines=[result['scope'],'GUARD '+hex(ENTRY)+' LIMIT '+str(result['constant_float32'])]
for r in rows:lines.append('POINT '+str(r['point'])+' -> '+r['outcome'])
lines.append('SHARED_CONSTANT_REFERENCES '+str(len(shared)))
for r in shared:lines.append(r['va']+' '+r['bytes']+' '+r['asm'])
for c in context:
    lines.append('CONTEXT '+c['start'])
    for r in c['instructions']:lines.append(r['va']+' '+r['bytes']+' '+r['asm'])
lines.append('RESULT '+str(len(rows))+' expected exits; no game patched; no gameplay executed')
(out/'position_guard_probe.txt').write_text('\n'.join(lines)+'\n',encoding='utf8')
print('\n'.join(lines))
