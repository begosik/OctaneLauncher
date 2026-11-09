"""Retained original directional160 x86 fixture prefix for candidate-bound162 tests.

Own test harness code; no private vendor source. Paths are supplied explicitly by
recovery162.py. Candidate code hash is checked against committed adapter metadata
before this module is loaded. The original Fixture implementation is unchanged.
"""
"""Isolated review/test of independent NAT completion publication.

Executes the original game instructions and original canonical 6+2 matrix
setter. Does not edit the installed game or any release input. Diagnostic
formatting, critical-section operations and UI notification are isolated.
"""
from pathlib import Path
import hashlib,json,struct,sys
import pefile
from unicorn import Uc,UC_ARCH_X86,UC_MODE_32,UC_HOOK_CODE
from unicorn.x86_const import *

HERE=Path(__file__).resolve().parent
assert len(sys.argv)==4,'Explicit game/native/output paths are required'
GAME=Path(sys.argv[1])
OUT=Path(sys.argv[3])
OUT.mkdir(parents=True,exist_ok=True)
GAME_SHA='f1b4ede3229921abd474e0a251fe1880ca98981d9cbf45e4b5c3b8fee08c7a31'
PATCHES=[
    (0x6A379D,bytes.fromhex('8b138b026aff'),bytes.fromhex('e95200000090'),
     'Remote CONNDONE publishes only its advertised direction; retain pending local SDK phase'),
    (0x69713F,bytes.fromhex('e82cfffeff'),bytes.fromhex('83c4109090'),
     'Local SDK success retains phase4 and peer->local state3, without synthesizing local->peer success'),
]
ADMISSION_SITE=0x697106
ADMISSION_BEFORE=bytes.fromhex('3b9ec0000000')
ADMISSION_TEST_VA=0x20000000

def admission_code():
    b=bytearray.fromhex('84c07500')
    b+=bytes.fromhex('3b9ec00000007500')
    skipreset=len(b)-1
    b+=bytes.fromhex('c786c0000000ffffffff')
    failure=len(b)
    b+=bytes.fromhex('8bceb830706900ffd0')
    b+=bytes.fromhex('8d470850ff15d871bc00')
    b+=bytes.fromhex('5f5e5bc20800')
    success=len(b)
    b+=ADMISSION_BEFORE+bytes.fromhex('680c716900c3')
    b[3]=success-4;b[skipreset]=failure-(skipreset+1)
    return bytes(b)

ADMISSION_THUNK=admission_code()
NATIVE_PATH=Path(sys.argv[2])
assert NATIVE_PATH.is_file(),'Actual compiled Native160 fixture required'
# Candidate hash/code are authenticated by the recovery162 caller before import.
NATIVE_RAW=NATIVE_PATH.read_bytes() if NATIVE_PATH.is_file() else None
NATIVE_PE=pefile.PE(data=NATIVE_RAW) if NATIVE_RAW else None
NATIVE_IMAGE=NATIVE_PE.get_memory_mapped_image() if NATIVE_PE else None
if NATIVE_PE:ADMISSION_TEST_VA=NATIVE_PE.OPTIONAL_HEADER.ImageBase+0x3160e0
REGIONS={'remote_complete':(0x6a374c,0xc6),'local_complete':(0x697122,0x3a),
    'admission_call_and_ignored_result':(0x6970f0,0x32),'admission_function':(0x671fe0,0x124),
    'setter_entry':(0x687070,5),'setter_body':(0xd54820,0x4e),
    'matrix_index':(0xd53ec0,0x43),'matrix_state':(0xd53f20,0x1d),
    'matrix_token':(0xd53f60,0x20)}
HASH=lambda b:hashlib.sha256(b).hexdigest()

def guarded(raw):
    if HASH(raw)!=GAME_SHA:raise ValueError('Expected exact reviewed canonical game')
    pe=pefile.PE(data=raw);out=bytearray(raw)
    for va,before,after,_ in PATCHES:
        at=pe.get_offset_from_rva(va-0x400000)
        assert raw[at:at+len(before)]==before,(hex(va),raw[at:at+len(before)].hex())
        assert len(before)==len(after)
        out[at:at+len(before)]=after
    at=pe.get_offset_from_rva(ADMISSION_SITE-0x400000)
    assert raw[at:at+len(ADMISSION_BEFORE)]==ADMISSION_BEFORE
    out[at:at+6]=b'\xe9'+struct.pack('<i',ADMISSION_TEST_VA-(ADMISSION_SITE+5))+b'\x90'
    allowed={i for va,b,_,_ in PATCHES for i in range(pe.get_offset_from_rva(va-0x400000),pe.get_offset_from_rva(va-0x400000)+len(b))}
    allowed.update(range(at,at+6))
    assert all(a==b or i in allowed for i,(a,b)in enumerate(zip(raw,out)))
    for va,n in [REGIONS[k]for k in ('setter_entry','setter_body','matrix_index','matrix_state','matrix_token')]:
        off=pe.get_offset_from_rva(va-0x400000);assert raw[off:off+n]==out[off:off+n]
    return bytes(out)

def index(a,b):
    if not(0<=a<8 and 0<=b<8):return None
    if a<6 and b<6:return False,a*6+b
    if a<6:return True,a*2+b-6
    return True,12+(a-6)*8+b

def state_offset(a,b):
    k=index(a,b)
    return None if k is None else (0x510 if k[0] else 0x1c)+k[1]*4

def token_offset(a,b):
    k=index(a,b)
    return None if k is None else (0x580 if k[0] else 0xac)+k[1]*4

CTX=0x11000;MGR=0x13000;LOCK=0x15000;VT=0x16000;STACK=0x30000
SENTINEL=0x1f000;LOCK_FN=0x1f100;TOKEN=0x22B40F8B
INITIAL=0x11223344

class Fixture:
    def __init__(self,image,local,peer,token=TOKEN,phase=1,matrix_token=TOKEN):
        self.u=Uc(UC_ARCH_X86,UC_MODE_32);u=self.u
        u.mem_map(0,0x40000);u.mem_map(0x400000,(len(image)+0xfff)&~0xfff);u.mem_write(0x400000,image)
        self.notifications=[];self.lock_calls=0;self.reconcile=0;self.setters=[];self.done=False;self.full=False
        self.closed=[];self.sent_failed=0;self.sent_done=0;self.admit_mode=None
        self.liveness_phase=None;self.liveness_handler_calls=0
        if NATIVE_IMAGE:
            native_base=NATIVE_PE.OPTIONAL_HEADER.ImageBase
            u.mem_map(native_base,(len(NATIVE_IMAGE)+0xfff)&~0xfff);u.mem_write(native_base,NATIVE_IMAGE)
        else:u.mem_map(ADMISSION_TEST_VA,0x1000);u.mem_write(ADMISSION_TEST_VA,ADMISSION_THUNK)
        u.mem_write(MGR,b'\xcd'*0x1000)
        for a in range(8):
            for b in range(8):self.put(MGR+state_offset(a,b),INITIAL);self.put(MGR+token_offset(a,b),matrix_token)
        self.put(CTX+0x50,MGR);self.put(CTX+0x64,local);self.put(CTX+0x68,peer);self.put(CTX+0x70,token);self.put(CTX+0xbc,phase)
        self.put(CTX+0x58,0x1c000)
        self.put(LOCK,VT);self.put(VT,LOCK_FN);u.mem_write(LOCK_FN,b'\xc2\x04\x00')
        self.put(CTX+0x28,VT)
        self.put(0xbc71d8,LOCK_FN)
        # Suppress bounded diagnostic formatter only; real setter/index/token
        # guards still run, including extended-slot cases.
        self.put(0xd6d8fc,0x200)
        u.reg_write(UC_X86_REG_ESI,CTX);u.reg_write(UC_X86_REG_EBX,LOCK);u.reg_write(UC_X86_REG_EDI,0x456789ab)
        u.reg_write(UC_X86_REG_EBP,0x23456789)
        u.hook_add(UC_HOOK_CODE,self.hook)
        self.before=bytes(u.mem_read(MGR,0x1000));self.initial_phase=phase

    def put(self,at,v):self.u.mem_write(at,struct.pack('<I',v&0xffffffff))
    def get(self,at):return struct.unpack('<I',self.u.mem_read(at,4))[0]
    def ret(self,cleanup=0):
        u=self.u;sp=u.reg_read(UC_X86_REG_ESP);pc=self.get(sp)
        u.reg_write(UC_X86_REG_ESP,sp+4+cleanup);u.reg_write(UC_X86_REG_EIP,pc)
    def hook(self,u,pc,size,_):
        if pc in (0x6a3631,SENTINEL) or (pc==0x69715c and not self.full):self.done=True;u.emu_stop()
        elif pc==LOCK_FN:self.lock_calls+=1
        elif pc==0x6722f0:self.reconcile+=1;u.reg_write(UC_X86_REG_EAX,1);self.ret()
        elif pc==0xd54120:
            self.notifications.append((u.reg_read(UC_X86_REG_EAX),u.reg_read(UC_X86_REG_EDX)));self.ret()
        elif pc==0x687070:
            sp=u.reg_read(UC_X86_REG_ESP)
            self.setters.append(tuple(self.get(sp+4+i*4)for i in range(4)))
        elif pc in (0xb2acc6,0xb2acc0):
            sp=u.reg_read(UC_X86_REG_ESP);n=4 if pc==0xb2acc6 else 2
            u.reg_write(UC_X86_REG_EAX,int.from_bytes(bytes(u.mem_read(sp+4,n)),'big'));self.ret(4)
        elif pc==0xb2ac60:
            self.closed.append(self.get(u.reg_read(UC_X86_REG_ESP)+4));u.reg_write(UC_X86_REG_EAX,0);self.ret(4)
        elif pc==0x416970 and self.admit_mode=='oom':u.reg_write(UC_X86_REG_EAX,0);self.ret()
        elif pc==0x671fe0 and self.admit_mode=='success_stub':u.reg_write(UC_X86_REG_EAX,1);self.ret(12)
        elif pc==0x695c00:self.sent_failed+=1;self.ret()
        elif pc==0x6959f0:self.sent_done+=1;self.ret()
        elif pc==0x697030 and self.liveness_phase is not None:
            self.liveness_handler_calls+=1;self.put(CTX+0xbc,self.liveness_phase);self.ret()

    def run(self,kind,message=None):
        u=self.u
        if kind=='local':u.reg_write(UC_X86_REG_ESP,STACK);start=0x697122
        else:
            # Start at first instruction after the existing sscanf. All three
            # tuple comparisons and both completion paths are original code.
            a,b,t=message;self.put(STACK+0x14,a);self.put(STACK+0x18,b);self.put(STACK+0x10,t)
            u.reg_write(UC_X86_REG_ESP,STACK-20);start=0x6a377f
        u.emu_start(start,0x1400000,count=10000)
        assert self.done,'No terminal reached'
        assert u.reg_read(UC_X86_REG_ESP)==STACK
        assert u.reg_read(UC_X86_REG_ESI)==CTX
        assert u.reg_read(UC_X86_REG_EBX)==LOCK
        assert u.reg_read(UC_X86_REG_EDI)==0x456789ab
        assert u.reg_read(UC_X86_REG_EBP)==0x23456789
        after=bytes(u.mem_read(MGR,0x1000))
        valid_state={state_offset(a,b) for a in range(8)for b in range(8)}
        assert all(x==y or any(at<=i<at+4 for at in valid_state)for i,(x,y)in enumerate(zip(self.before,after))), 'Write outside64 state DWORDs'
        return {'phase':self.get(CTX+0xbc),'cells':{f'{a},{b}':self.get(MGR+state_offset(a,b))for a in range(8)for b in range(8)},'setters':self.setters,'notifications':self.notifications,'lock_calls':self.lock_calls,'reconcile':self.reconcile}

    def callback(self,mode,pending_socket=0xa55):
        self.full=True;self.done=False;self.admit_mode=mode;u=self.u
        local=self.get(CTX+0x64);peer=self.get(CTX+0x68)
        ep=0x18000
        u.mem_write(ep,bytes.fromhex('02001f907f000001')+b'\0'*8)
        for slot in range(8):self.put(CTX+(0x94+slot*4 if slot<6 else 0xf0+(slot-6)*4),ep+0x100+slot*8)
        self.put(CTX+0x54,0 if mode=='no_session' else 0x1b000)
        self.put(CTX+0xc0,pending_socket)
        self.put(STACK,SENTINEL);self.put(STACK+4,0xa55);self.put(STACK+8,ep)
        u.reg_write(UC_X86_REG_ESP,STACK);u.reg_write(UC_X86_REG_ECX,CTX)
        for reg,value in [(UC_X86_REG_EBX,0x13579bdf),(UC_X86_REG_ESI,0x2468ace0),(UC_X86_REG_EDI,0x11235813),(UC_X86_REG_EBP,0x23456789)]:u.reg_write(reg,value)
        u.emu_start(0x6970b0,ADMISSION_TEST_VA+0x1000,count=10000)
        assert self.done
        assert u.reg_read(UC_X86_REG_ESP)==STACK+12
        for reg,value in [(UC_X86_REG_EBX,0x13579bdf),(UC_X86_REG_ESI,0x2468ace0),(UC_X86_REG_EDI,0x11235813),(UC_X86_REG_EBP,0x23456789)]:assert u.reg_read(reg)==value
        return {'phase':self.get(CTX+0xbc),'local_peer':self.get(MGR+state_offset(local,peer)),'peer_local':self.get(MGR+state_offset(peer,local)),
            'closed':self.closed,'failed_notify':self.sent_failed,'done_notify':self.sent_done,'pending_socket':self.get(CTX+0xc0),'setters':self.setters,'host_driver':self.get(CTX+0x60)}

    def stub_liveness(self,host=0,local=0,manager=MGR,session=0x1b000,result_phase=5):
        self.full=True;self.done=False;self.liveness_phase=result_phase;u=self.u
        self.put(CTX+0x50,manager);self.put(CTX+0x54,session);self.put(CTX+0x5c,host)
        self.put(CTX+0x64,local);self.put(CTX+0x60,0);self.put(CTX+0xc0,0xa55)
        saved=[0x11235813,0x2468ace0,0x13579bdf,SENTINEL,0xa55,0x18000]
        for i,v in enumerate(saved):self.put(STACK+i*4,v)
        u.reg_write(UC_X86_REG_ESP,STACK);u.reg_write(UC_X86_REG_ESI,CTX)
        u.reg_write(UC_X86_REG_EBX,0xa55);u.reg_write(UC_X86_REG_EDI,CTX+0x28)
        u.reg_write(UC_X86_REG_EBP,0x23456789);u.reg_write(UC_X86_REG_EAX,0)
        u.emu_start(ADMISSION_TEST_VA,ADMISSION_TEST_VA+0x1000,count=10000)
        assert self.done and self.liveness_handler_calls==1
        assert self.closed==[],'Already-closed socket closed again'
        assert self.get(CTX+0xc0)==0xffffffff
        assert u.reg_read(UC_X86_REG_ESP)==STACK+24
        for reg,value in [(UC_X86_REG_EDI,saved[0]),(UC_X86_REG_ESI,saved[1]),(UC_X86_REG_EBX,saved[2]),(UC_X86_REG_EBP,0x23456789)]:assert u.reg_read(reg)==value
        return self.get(CTX+0x60)
