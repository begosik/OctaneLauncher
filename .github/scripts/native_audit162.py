"""Verify exact allowed old-image edits, preserved packet policy and SafeSEH."""
from pathlib import Path
import hashlib,json,struct,sys
import pefile
H=lambda b:hashlib.sha256(b).hexdigest()
OLD='00760f8f848ef5248fb4616b8eea64c8ee47aad48dff8fa2fee189a93ca45c52'
NEW='c7de4f1968831e6b66103f52739bd6afea2758f7f0b42ffe8f590543b8427b58'

def main():
 old=Path(sys.argv[1]).read_bytes();new=Path(sys.argv[2]).read_bytes()
 meta=json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
 assert H(old)==OLD and H(new)==NEW
 a=pefile.PE(data=old);b=pefile.PE(data=new)
 base=a.OPTIONAL_HEADER.ImageBase;assert base==b.OPTIONAL_HEADER.ImageBase==0x10000000
 assert a.OPTIONAL_HEADER.DllCharacteristics==b.OPTIONAL_HEADER.DllCharacteristics
 assert b.generate_checksum()==b.OPTIONAL_HEADER.CheckSum
 assert len(b.sections)==len(a.sections)+1 and b.sections[-1].Name.rstrip(b'\0')==b'.O162'
 for x,y in zip(a.sections,b.sections):
  assert x.Name==y.Name and x.VirtualAddress==y.VirtualAddress and x.PointerToRawData==y.PointerToRawData and x.SizeOfRawData==y.SizeOfRawData
  assert y.Misc_VirtualSize==(0x26000 if x.Name.startswith(b'.data') else x.Misc_VirtualSize)
 headers=a.DOS_HEADER.e_lfanew+24+a.FILE_HEADER.SizeOfOptionalHeader+40*len(b.sections)
 allowed=set(range(a.DOS_HEADER.e_lfanew,headers))
 edits=[(0x1010a61e,'0f8473020000','909090909090'),
        (0x1010286a,'e80103ffff',None),(0x101121a0,'8b8e78050000',None)]
 edits.extend((int(x['va'],16),x['before'],None)for x in meta['endpoint_hooks'])
 for va,before,after in edits:
  off=a.get_offset_from_rva(va-base);expected=bytes.fromhex(before)
  assert old[off:off+len(expected)]==expected
  assert new[off:off+len(expected)]!=expected
  if after:assert new[off:off+len(expected)]==bytes.fromhex(after)
  allowed.update(range(off,off+len(expected)))
 cfg=a.DIRECTORY_ENTRY_LOAD_CONFIG.struct;newcfg=b.DIRECTORY_ENTRY_LOAD_CONFIG.struct
 sehfield=cfg.get_field_absolute_offset('SEHandlerTable');allowed.update(range(sehfield,sehfield+8))
 changed=[i for i,(x,y)in enumerate(zip(old,new))if x!=y]
 assert all(i in allowed for i in changed),'Unexpected edit outside reviewed hook/header/SEH metadata spans'
 oldseh=struct.unpack('<'+'I'*cfg.SEHandlerCount,a.get_data(cfg.SEHandlerTable-base,cfg.SEHandlerCount*4))
 newseh=struct.unpack('<'+'I'*newcfg.SEHandlerCount,b.get_data(newcfg.SEHandlerTable-base,newcfg.SEHandlerCount*4))
 assert list(newseh)==sorted(set(newseh))
 assert set(newseh)==set(oldseh).union(meta['seh_handlers'])
 assert b.get_data(cfg.SEHandlerTable-base,cfg.SEHandlerCount*4)==a.get_data(cfg.SEHandlerTable-base,cfg.SEHandlerCount*4)
 olddir=a.OPTIONAL_HEADER.DATA_DIRECTORY[5];newdir=b.OPTIONAL_HEADER.DATA_DIRECTORY[5]
 assert b.get_data(newdir.VirtualAddress,olddir.Size)==a.get_data(olddir.VirtualAddress,olddir.Size)
 sehfieldrva=a.get_rva_from_offset(sehfield)
 assert sum(e.type==3 and e.rva==sehfieldrva for block in b.DIRECTORY_ENTRY_BASERELOC for e in block.entries)==1
 for target in (0x53000000,0x68000000):
  rebased=pefile.PE(data=new);rebased.relocate_image(target)
  actual=struct.unpack('<I',rebased.get_data(sehfieldrva,4))[0]
  assert actual==target+(newcfg.SEHandlerTable-base)
  assert rebased.get_data(actual-target,newcfg.SEHandlerCount*4)==struct.pack('<'+'I'*len(newseh),*newseh)
 code=b.get_data(0x316000,meta['code_bytes']);assert H(code)==meta['code_sha256']
 assert b.get_memory_mapped_image()[0x2f5500:0x2f6000]==b'\0'*0xb00
 result=dict(passed=True,native_sha256=NEW,baseline_sha256=OLD,explicit_native_hook_spans=len(edits),
  old_bytes_outside_reviewed_changes_preserved=True,packet_buffers_and_original_Route_send_truncation_byte_identical=True,
  original_SafeSEH_entries=len(oldseh),new_SafeSEH_entries=len(newseh)-len(oldseh),SafeSEH_disabled=False,
  old_relocation_prefix_preserved=True,ASLR_SafeSEH_bases=2,state_bytes=2636,reserved_bytes=2816,
  scope='PE/byte/relocation verification of exact published Native input and candidate; no game execution')
 Path(sys.argv[4]).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,indent=2))

if __name__=='__main__':main()
