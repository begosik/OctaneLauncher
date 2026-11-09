"""Actual old-game SDK Begin failure branches + compiled retirement helper.

No game/Internet execution. Existing directional fixture isolates locks/UI/logs.
Requires explicit package-extracted game/Native paths and reviewed adapter metadata.
The candidate function executes; full installer execution is a separate test.
"""
from pathlib import Path
import argparse,hashlib,importlib.util,json,struct,sys
import pefile
from unicorn import UC_HOOK_CODE
from unicorn.x86_const import *

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser(description='Verify actual old-game synchronous SDK Begin retirement with compiled Native162')
parser.add_argument('--native',required=True,type=Path)
parser.add_argument('--game',required=True,type=Path)
parser.add_argument('--metadata',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--expected-native-sha')
args=parser.parse_args()
for name in ('native','game','metadata','output'):setattr(args,name,getattr(args,name).resolve())
args.output.parent.mkdir(parents=True,exist_ok=True)
H=lambda b:hashlib.sha256(b).hexdigest()
GAME=args.game.read_bytes();RAW=args.native.read_bytes();PE=pefile.PE(data=RAW);BASE=PE.OPTIONAL_HEADER.ImageBase
METADATA_RAW=args.metadata.read_bytes();META=json.loads(METADATA_RAW)
assert H(GAME)=='f1b4ede3229921abd474e0a251fe1880ca98981d9cbf45e4b5c3b8fee08c7a31'
if args.expected_native_sha:assert H(RAW)==args.expected_native_sha.lower()
assert PE.FILE_HEADER.Machine==0x14c and PE.OPTIONAL_HEADER.Magic==0x10b
assert H(PE.get_data(0x316000,META['code_bytes']))==META['code_sha256'],'Candidate and adapter metadata differ'
ENTRY=META['recovery_begin_va'];IMAGE=PE.get_memory_mapped_image()
# Explicit package-extracted paths replace every old WORK/default assumption.
sys.argv=['recovery_fixture162.py',str(args.game),str(args.native),str(args.output.parent)]
fixture_path=HERE/'recovery_fixture162.py'
spec=importlib.util.spec_from_file_location('recovery162_directional_fixture',fixture_path)
FIXTURE_RAW=fixture_path.read_bytes()
d=importlib.util.module_from_spec(spec);spec.loader.exec_module(d)
d.ADMISSION_TEST_VA=META['admission_va']
NSDK=0x22000
CALL=0x6a34a5;STOP=0x6a34bb;TAIL=0xd6392c

def patch_image(enable):
 raw=d.guarded(GAME);pe=pefile.PE(data=raw);b=bytearray(pe.get_memory_mapped_image())
 assert b[TAIL-0x400000:TAIL-0x400000+5]==bytes.fromhex('e9cf28ddff')
 if enable:b[TAIL-0x400000:TAIL-0x400000+5]=b'\xe9'+struct.pack('<i',ENTRY-TAIL-5)
 return bytes(b)

class RecoveryFixture(d.Fixture):
 def __init__(self,enable,mode='backend',local=0,remote=7,shared=False,mutation=None,**kwargs):
  self.mode=mode;self.mutation=mutation;self.sdk_cleanup=0;self.sdk_calls=0;self.exact_stop=None
  super().__init__(patch_image(enable),local,remote,**kwargs)
  self.u.mem_map(0x40000,0x40000)
  self.put(d.CTX+0x54,0x1b000);self.put(d.CTX+0xc0,0xa55);self.put(d.CTX+0x5c,local);self.put(d.CTX+0x60,0)
  self.u.mem_write(0x1b000+0x40e48,bytes([int(shared)]))
  self.put(d.MGR+d.state_offset(local,remote),2);self.put(d.MGR+d.state_offset(remote,local),2)
  self.put(0xd63c64,32)  # Bypass retained bounded diagnostic wrapper only.
  self.put(0xd1b230,0 if mode=='backend' else 1)
  self.u.hook_add(UC_HOOK_CODE,self.extra_hook)
 def extra_hook(self,u,pc,size,_):
  if pc in (self.exact_stop,STOP):self.done=True;u.emu_stop()
  elif pc==0xb36200:
   self.sdk_calls+=1
   if self.mutation:self.mutation(self)
   if self.mode=='success':u.reg_write(UC_X86_REG_EAX,0);self.ret()
  elif pc==0xb36180:
   u.reg_write(UC_X86_REG_EAX,0 if self.mode=='dns' else 1);self.ret()
  elif pc==0xb35a90:
   u.reg_write(UC_X86_REG_EAX,0 if self.mode=='alloc' else NSDK);self.ret()
  elif pc==0xb2ac78:
   u.reg_write(UC_X86_REG_EAX,0xffffffff);self.ret(12)
  elif pc==0xb35af0:
   self.sdk_cleanup+=1;self.ret()
 def begin(self,progress=0xbb1ac0,complete=0x6a31e0,context=d.CTX,index=0,token=d.TOKEN,socket=0xa55,caller=True):
  u=self.u;self.done=False
  values=[socket,token,index,progress,complete,context]
  for i,v in enumerate(values):self.put(d.STACK+4*i,v)
  u.reg_write(UC_X86_REG_ESP,d.STACK)
  before={reg:u.reg_read(reg)for reg in [UC_X86_REG_EBX,UC_X86_REG_ESI,UC_X86_REG_EDI,UC_X86_REG_EBP]}
  if caller:start=CALL;self.exact_stop=STOP;expect_sp=d.STACK+24
  else:
   self.put(0x1f204,0) # writable test code lies outside game image
   u.mem_write(0x1f200,b'\xe8'+struct.pack('<i',ENTRY-0x1f205));self.exact_stop=0x1f205;start=0x1f200;expect_sp=d.STACK
  u.emu_start(start,0xffffffff,count=100000)
  assert self.done and self.sdk_calls==1
  assert u.reg_read(UC_X86_REG_ESP)==expect_sp
  assert all(u.reg_read(reg)==value for reg,value in before.items()),'cdecl nonvolatile register changed'
  local=self.get(d.CTX+0x64);remote=self.get(d.CTX+0x68)
  return {'result':u.reg_read(UC_X86_REG_EAX),'phase':self.get(d.CTX+0xbc),
          'local_peer':self.get(d.MGR+d.state_offset(local,remote)) if local<8 and remote<8 else None,
          'peer_local':self.get(d.MGR+d.state_offset(remote,local)) if local<8 and remote<8 else None,
          'pending_socket':self.get(d.CTX+0xc0),'closed':self.closed,'failed_reports':self.sent_failed,
          'done_reports':self.sent_done,'host_wake':self.get(d.CTX+0x60),'sdk_node_cleanup':self.sdk_cleanup}

def main():
 rows=[]
 for local,remote in [(0,1),(0,6),(6,0),(6,7)]:
  for mode,result in [('backend',2),('dns',3),('alloc',1),('socket',2)]:
   old=RecoveryFixture(False,mode,local,remote).begin()
   assert old['result']==result and old['phase']==5 and old['local_peer']==old['peer_local']==2
   assert old['pending_socket']==0xa55 and old['closed']==[] and old['failed_reports']==0
   new=RecoveryFixture(True,mode,local,remote).begin()
   assert new['result']==result and new['phase']==5 and new['local_peer']==new['peer_local']==4
   assert new['pending_socket']==0xffffffff and new['closed']==[0xa55]
   assert new['failed_reports']==1 and new['done_reports']==0 and new['host_wake']==1
   assert new['sdk_node_cleanup']==int(mode=='socket')
   rows.append({'case':mode,'local':local,'remote':remote,'old':old,'new':new})
 for shared in [False,True]:
  f=RecoveryFixture(True,'success',shared=shared);v=f.begin()
  assert v['result']==0 and v['phase']==1 and v['local_peer']==v['peer_local']==2
  assert v['pending_socket']==0xa55 and v['closed']==[] and v['failed_reports']==0 and v['host_wake']==0
  rows.append({'case':'success-mocked','shared':shared,'result':v})
  f=RecoveryFixture(True,'backend',shared=shared);v=f.begin()
  assert v['closed']==([] if shared else [0xa55]) and v['pending_socket']==0xffffffff
  assert v['local_peer']==v['peer_local']==4 and v['failed_reports']==1
  rows.append({'case':'ownership','shared':shared,'result':v})
 mismatches=[('wrong-progress',{'progress':0xbb1ac1}),('wrong-completion',{'complete':0x6a31e1}),
             ('null-owner',{'context':0}),('wrong-index',{'index':2}),('wrong-token',{'token':d.TOKEN+1}),
             ('wrong-socket',{'socket':0xa56}),('other-callsite',{'caller':False})]
 for name,case_args in mismatches:
  f=RecoveryFixture(True,'backend');v=f.begin(**case_args)
  assert v['result']==2 and v['closed']==[] and v['failed_reports']==0 and v['host_wake']==0
  assert v['pending_socket']==0xa55 and v['local_peer']==v['peer_local']==2
  rows.append({'case':name,'result':v})
 for mutate in ['matrix','phase','owner-token','invalid-peer','nonhost']:
  f=RecoveryFixture(True,'backend')
  if mutate=='matrix':f.put(d.MGR+d.token_offset(0,7),d.TOKEN+1)
  elif mutate=='phase':f.put(d.CTX+0xbc,4)
  elif mutate=='owner-token':f.put(d.CTX+0x70,d.TOKEN+1)
  elif mutate=='invalid-peer':f.put(d.CTX+0x68,8)
  else:f.put(d.CTX+0x5c,1)
  v=f.begin()
  if mutate=='nonhost':assert v['failed_reports']==1 and v['host_wake']==0
  else:assert v['closed']==[] and v['failed_reports']==0 and v['host_wake']==0
  rows.append({'case':mutate,'result':v})
 f=RecoveryFixture(True,'backend',mutation=lambda f:f.put(d.CTX+0x70,d.TOKEN+1));v=f.begin()
 assert v['closed']==[] and v['failed_reports']==0 and v['host_wake']==0
 rows.append({'case':'identity-changes-during-sdk-call','result':v})
 report={'passed':True,'cases':len(rows),'native_sha256':H(RAW),'recovery_begin_va':hex(ENTRY),
         'fixture_source_sha256':H(Path(__file__).read_bytes()),'fixture_base_sha256':H(FIXTURE_RAW),'adapter_metadata_sha256':H(METADATA_RAW),
         'game_sha256':H(GAME),'game_hook_va':hex(TAIL),'before':'e9cf28ddff',
         'scope':'Original old-game NNBegin synchronous error branches and actual original failure handler/6+2 setters, with actual candidate Native162 compiled recovery helper. Original fixture isolates locks/UI/diagnostics/report transport. DNS resolver and allocator/socket system boundaries isolated; successful NNBegin mocked; socket-failure SDK cleanup counted. No live game, lobby, Internet or full Native162 installer execution.',
         'large_packet_limits_changed':False,'wire_format_changed':False,'timers_changed':False,
         'rows':rows}
 args.output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('RECOVERY162_PASS',len(rows))
if __name__=='__main__':main()
