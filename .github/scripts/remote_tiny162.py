"""Execute actual Native162 min-frame bridge x86 instructions at three bases."""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import pefile
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
    UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
    UC_X86_REG_EFLAGS,
)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('native',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    raw=args.native.read_bytes();pe=pefile.PE(data=raw)
    image=pe.get_memory_mapped_image()
    cases=[]
    for base in [0x10000000,0x20000000,0x60000000]:
        for length in [0,1,2,32,2048,0xffffffff]:
            for flags in [0x202,0x246,0x602]:
                emu=Uc(UC_ARCH_X86,UC_MODE_32)
                emu.mem_map(base,(len(image)+4095)&~4095);emu.mem_write(base,image)
                frame=0x30000000;stack=0x40000000
                emu.mem_map(frame,4096);emu.mem_map(stack,65536)
                ebp=stack+0x8000;esp=stack+0x7800
                span_pointer=0x12345678
                emu.mem_write(frame+0x30c,struct.pack('<I',span_pointer))
                emu.mem_write(ebp-0xc8,struct.pack('<I',length))
                registers={UC_X86_REG_EAX:0x11111111,UC_X86_REG_EBX:0x22222222,
                           UC_X86_REG_ECX:0x33333333,UC_X86_REG_EDX:0x44444444,
                           UC_X86_REG_ESI:frame,UC_X86_REG_EDI:0x66666666,
                           UC_X86_REG_EBP:ebp,UC_X86_REG_ESP:esp}
                for register,value in registers.items():emu.reg_write(register,value)
                emu.reg_write(UC_X86_REG_EFLAGS,flags)
                original_flags=emu.reg_read(UC_X86_REG_EFLAGS)
                stop=[]
                def observe(cpu,address,size,user):
                    if address in [base+0x10a2cc,base+0x10b1d9]:
                        stop.append(address);cpu.emu_stop()
                emu.hook_add(UC_HOOK_CODE,observe)
                emu.emu_start(base+0x10a2c6,base+len(image),count=30)
                expected=base+(0x10b1d9 if length<2 else 0x10a2cc)
                assert stop==[expected],(base,length,flags,stop)
                for register,value in registers.items():
                    wanted=span_pointer if register==UC_X86_REG_EAX and length>=2 else value
                    assert emu.reg_read(register)==wanted,(base,length,register)
                assert emu.reg_read(UC_X86_REG_EFLAGS)==original_flags
                cases.append(dict(base=hex(base),length=length,flags=hex(flags),
                                  path='original_continue_cleanup' if length<2 else 'original_packet_parser',passed=True))
    result=dict(passed=True,cases=len(cases),image_bases=3,
                native_sha256=hashlib.sha256(raw).hexdigest(),
                flags_and_GP_preserved_except_replayed_EAX_load=True,
                packet_capacity_or_truncation_changed=False,
                scope='Actual compiled bridge reached through actual patched NativeDll hook. Unicorn executes only guard/control transfers and stops at original parser/continue targets; original async cleanup/UDP behavior is covered separately by native Windows fixture.',results=cases)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print('REMOTE_TINY162_X86_PASS',len(cases))


if __name__=='__main__':main()
