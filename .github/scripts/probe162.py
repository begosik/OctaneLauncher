"""Execute the real x86 probe-classification instructions, including prefix comparison.

These are machine-code regression tests, not a simulated network or RA3 match.
"""
import sys, struct, hashlib, json
from pathlib import Path
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import *
ROOT=Path(__file__).resolve().parents[1]
BASE_SHA='00760f8f848ef5248fb4616b8eea64c8ee47aad48dff8fa2fee189a93ca45c52'

def classify(image,base,packet,active):
    uc=Uc(UC_ARCH_X86,UC_MODE_32)
    uc.mem_map(base,0x400000)
    uc.mem_write(base,image)
    uc.mem_map(0x10000,0x20000)
    state,conn,buf,stack=0x10000,0x12000,0x18000,0x29000
    def u32(a,v):uc.mem_write(a,struct.pack('<I',v))
    u32(state+0x74,buf);u32(state+0x78,len(packet))
    uc.mem_write(buf,packet or b'\0');uc.mem_write(conn+0x2117,bytes([active]))
    uc.reg_write(UC_X86_REG_ESI,state);uc.reg_write(UC_X86_REG_EDI,conn)
    uc.reg_write(UC_X86_REG_EBP,stack);uc.reg_write(UC_X86_REG_ESP,stack-0x400)
    uc.reg_write(UC_X86_REG_EBX,0x12345678)
    terminal={base+0x10a66e:'probe',base+0x10a897:'game'}
    seen=[]
    def stop(uc,addr,size,_):
        if addr in terminal:seen.append(terminal[addr]);uc.emu_stop()
    uc.hook_add(UC_HOOK_CODE,stop)
    uc.emu_start(base+0x10a5cf,base+0x10a898,count=2000)
    assert len(seen)==1
    assert uc.reg_read(UC_X86_REG_ESP)==stack-0x400
    assert uc.reg_read(UC_X86_REG_ESI)==state and uc.reg_read(UC_X86_REG_EDI)==conn
    assert uc.reg_read(UC_X86_REG_EBX)==0x12345678
    assert uc.mem_read(conn+0x2117,1)==bytes([active])
    return seen[0]

def main():
    src=Path(sys.argv[1]).read_bytes();fixed=Path(sys.argv[2]).read_bytes();edits=[]
    assert hashlib.sha256(fixed).hexdigest()=='c7de4f1968831e6b66103f52739bd6afea2758f7f0b42ffe8f590543b8427b58'
    assert hashlib.sha256(src).hexdigest()==BASE_SHA
    marker=b'HakureiReimuAliceMargatroid'
    assert len(marker)==27
    cases=[('request',marker+b'\0\0\0\0\0','probe'),
           ('reply',marker+b'\2\3\1\0\0','probe'),
           ('empty',b'','game'),('short',marker,'game'),
           ('long',marker+b'\0'*6,'game'),('game32',b'\x12\x34'+b'\0'*30,'game')]
    for i in range(27):
        b=bytearray(marker+b'\0'*5);b[i]^=1
        cases.append((f'prefix-mismatch-{i}',bytes(b),'game'))
    results=[]
    for base in (0x10000000,0x53000000,0x68000000):
        images=[]
        for data in (src,fixed):
            image=pefile.PE(data=data);image.relocate_image(base)
            images.append(image.get_memory_mapped_image())
        for active in (0,1):
            for name,packet,want in cases:
                before=classify(images[0],base,packet,active)
                after=classify(images[1],base,packet,active)
                assert after==want,(base,active,name,after)
                expected_old='game' if not active else want
                assert before==expected_old,(base,active,name,before)
                results.append(dict(base=hex(base),active=active,case=name,old=before,new=after))
    result=dict(passed=True,classification_cases=len(results),old_idle_bug_reproduced=True,
        actual_x86_prefix_comparison_executed=True,ASLR_bases=3,classification_region_activity_gate_only=True,
        live_RA3_multiplayer_tested=False,patches=edits,results=results)
    Path(sys.argv[3]).write_text(json.dumps(result,indent=2)+'\n')
    print('PASS',len(results),'x86 classification cases; original idle failure reproduced')

if __name__=='__main__':main()
