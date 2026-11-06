"""Build local-only PE32 loader fixtures from the actual prepared runtime.

The complete original 17 retained import descriptors/IATs are kept. Only the
test entry point, TLS/resource activation, and a new probe section differ from
the prepared game. Three old SDK/CRT dependencies are inert export-compatible
fixtures; all other imports use Windows. The negative control re-adds the exact
original XInput ordinal-2 descriptor. No fixture binary is a deliverable.
"""
from pathlib import Path
import hashlib,json,struct,sys

H=lambda b:hashlib.sha256(b).hexdigest()
P=lambda *v:struct.pack('<'+'I'*len(v),*v)
U=lambda b,o:struct.unpack_from('<I',b,o)[0]
W=lambda b,o:struct.unpack_from('<H',b,o)[0]
ALIGN=lambda n,a:(n+a-1)&~(a-1)
STUB=bytes.fromhex('b88f040000c20800')
THUNK=0xB13A9C
EXPECTED_DLLS=['MSVCR80.dll','KERNEL32.dll','SHELL32.dll','SHLWAPI.dll',
 'GDI32.dll','USER32.dll','ADVAPI32.dll','d3d9.dll','d3dx9_35.dll',
 'DSOUND.dll','MSVCP80.dll','IMM32.dll','WS2_32.dll','NETAPI32.dll',
 'USP10.dll','WINMM.dll','ole32.dll']

class PE:
 def __init__(self,b):
  self.b=b;assert b[:2]==b'MZ';self.pe=U(b,60);assert b[self.pe:self.pe+4]==b'PE\0\0'
  self.opt=self.pe+24;assert W(b,self.pe+4)==0x14C and W(b,self.opt)==0x10B
  self.base=U(b,self.opt+28);self.st=self.opt+W(b,self.pe+20);self.count=W(b,self.pe+6)
  self.sections=[struct.unpack_from('<8s6I2HI',b,self.st+40*i)for i in range(self.count)]
 def raw(self,rva,n=1):
  if 0<=rva and rva+n<=U(self.b,self.opt+60):return rva
  for s in self.sections:
   if s[2]<=rva and rva-s[2]+n<=s[3]:
    off=s[4]+rva-s[2];assert off+n<=len(self.b);return off
  raise ValueError('Unmapped fixture RVA')
 def cstring(self,rva):
  off=self.raw(rva);end=self.b.find(b'\0',off,off+1024);assert end>=off
  return self.b[off:end].decode('ascii')
 def imports(self):
  rva=U(self.b,self.opt+104);size=U(self.b,self.opt+108)
  off=self.raw(rva,size);rows=[]
  for k in range(size//20):
   d=bytes(self.b[off+20*k:off+20*(k+1)]);fields=struct.unpack('<5I',d)
   if not any(fields):return rows
   oft,stamp,chain,name,ft=fields;assert oft and name and ft
   funcs=[]
   for i in range(2048):
    x=U(self.b,self.raw(oft+4*i,4))
    if not x:break
    funcs.append({'name':None,'ordinal':x&0xFFFF,'iat':self.base+ft+4*i}if x&0x80000000 else
     {'name':self.cstring(x+2),'ordinal':None,'iat':self.base+ft+4*i})
   else:raise ValueError('Unterminated thunk list')
   rows.append({'name':self.cstring(name),'descriptor':d,'functions':funcs})
  raise ValueError('Unterminated import list')

def make_dll(name,functions,sentinel=False):
 """Tiny PE32 export provider; sentinel writes a marker only in DllMain."""
 # These relocation-free fixtures coexist in one process. Every module needs
 # a distinct preferred base; the real game remains fixed at 0x00400000.
 bases={'xinput1_3.dll':0x20000000,'msvcr80.dll':0x21000000,
        'msvcp80.dll':0x22000000,'d3dx9_35.dll':0x23000000}
 base=bases[name.lower()];data=bytearray();dirs={}
 def put(blob,align=4):
  data.extend(b'\0'*((-len(data))%align));rva=0x2000+len(data);data.extend(blob);return rva
 def write(rva,blob):data[rva-0x2000:rva-0x2000+len(blob)]=blob
 named=sorted(set(f['name']for f in functions if f['name']is not None))
 ordinals=set(f['ordinal']for f in functions if f['ordinal']is not None)
 assert not ordinals or 0<min(ordinals)<=max(ordinals)<65536
 assigned={};used=set(ordinals)
 for n in named:
  i=1
  while i in used:i+=1
  assigned[n]=i;used.add(i)
 maximum=max(used or{1});export=put(b'\0'*40)
 eat=put(P(*[0x1100 if i in used else 0 for i in range(1,maximum+1)]))
 names=put(P(*([0]*len(named))))if named else 0
 ords=put(struct.pack('<'+'H'*len(named),*[assigned[n]-1 for n in named]))if named else 0
 dllname=put(name.encode()+b'\0',1)
 for i,n in enumerate(named):write(names+4*i,P(put(n.encode()+b'\0',1)))
 write(export,struct.pack('<IIHH7I',0,0,0,0,dllname,1,maximum,len(named),eat,names,ords))
 dirs[0]=(export,len(data))
 code=bytearray(b'\xB8\x01\0\0\0\xC2\x0C\0')
 if sentinel:
  # Import only CreateFileA/CloseHandle, enough to prove DLL_PROCESS_ATTACH ran.
  descriptor=put(b'\0'*40);hint1=put(b'\0\0CreateFileA\0',2);hint2=put(b'\0\0CloseHandle\0',2)
  ilt=put(P(hint1,hint2,0));iat=put(P(hint1,hint2,0));kernel=put(b'KERNEL32.dll\0',1)
  write(descriptor,P(ilt,0,0,kernel,iat));dirs[1]=(descriptor,40);dirs[12]=(iat,12)
  marker=put(b'xinput-loaded.marker\0',1)
  code=bytearray(bytes.fromhex('837c2408017500'))
  code+=b'\x6A\x00\x68'+P(0x80)+b'\x6A\x02\x6A\x00\x6A\x03\x68'+P(0x40000000)+b'\x68'+P(base+marker)
  code+=b'\xFF\x15'+P(base+iat)+b'\x50\xFF\x15'+P(base+iat+4)
  code[6]=len(code)-7
  code+=bytes.fromhex('b801000000c20c00')
 assert len(code)<0x100
 text=code+bytearray(0x100-len(code))+(STUB if sentinel else bytes.fromhex('31c0c3'))
 rawtext=ALIGN(len(text),0x200);rawdata=ALIGN(len(data),0x200)
 headers=bytearray(0x200);headers[:2]=b'MZ';struct.pack_into('<I',headers,60,0x80)
 headers[0x80:0x84]=b'PE\0\0';struct.pack_into('<HHIIIHH',headers,0x84,0x14C,2,0,0,0,224,0x2103)
 opt=0x98;struct.pack_into('<H',headers,opt,0x10B)
 for off,value in [(4,rawtext),(8,rawdata),(16,0x1000),(20,0x1000),(24,0x2000),(28,base),(32,0x1000),(36,0x200),
   (56,ALIGN(0x2000+len(data),0x1000)),(60,0x200),(72,0x100000),(76,0x1000),(80,0x100000),(84,0x1000),(92,16)]:
  struct.pack_into('<I',headers,opt+off,value)
 struct.pack_into('<HH',headers,opt+40,6,0);struct.pack_into('<HH',headers,opt+48,6,0)
 struct.pack_into('<HH',headers,opt+68,3,0)
 for i,(rva,size)in dirs.items():struct.pack_into('<2I',headers,opt+96+8*i,rva,size)
 st=opt+224
 struct.pack_into('<8s6I2HI',headers,st,b'.text\0\0\0',len(text),0x1000,rawtext,0x200,0,0,0,0,0x60000020)
 struct.pack_into('<8s6I2HI',headers,st+40,b'.data\0\0\0',len(data),0x2000,rawdata,0x200+rawtext,0,0,0,0,0xC0000040)
 return bytes(headers)+bytes(text).ljust(rawtext,b'\0')+bytes(data).ljust(rawdata,b'\0')

class Code:
 def __init__(self,base,exit_iat):self.base=base;self.exit=exit_iat;self.b=bytearray();self.strings=[]
 def emit(self,b):self.b+=b
 def failure(self,condition,number):
  # condition means success: skip the no-return ExitProcess failure body.
  body=b'\x68'+P(number)+b'\xFF\x15'+P(self.exit)
  self.emit(bytes([condition,len(body)])+body)
 def module(self,name,expected,getmodule):
  self.emit(b'\x68');at=len(self.b);self.emit(P(0));self.strings.append((at,name.encode()+b'\0'))
  self.emit(b'\xFF\x15'+P(getmodule)+b'\x85\xC0')
  self.failure(0x75 if expected else 0x74,20)
 def finish(self):
  for at,blob in self.strings:
   struct.pack_into('<I',self.b,at,self.base+len(self.b));self.b+=blob
  return bytes(self.b)

def probe_image(source,imports,negative):
 b=bytearray(source);pe=PE(b);rva=ALIGN(U(b,pe.opt+56),0x1000)
 kernel=next(x for x in imports if x['name'].lower()=='kernel32.dll')
 funcs={f['name']:f['iat']for f in kernel['functions']if f['name']}
 exit_iat=funcs['ExitProcess'];module_iat=funcs['GetModuleHandleA']
 allimports=list(imports)
 if negative:
  descriptor=P(0x8A184C,0,0,0x8A28B4,0x7C7764)
  old=PE(b);assert old.cstring(0x8A28B4).lower()=='xinput1_3.dll'
  assert U(b,old.raw(0x8A184C,8))==0x80000002 and U(b,old.raw(0x8A184C+4,4))==0
  allimports.insert(10,{'name':'XINPUT1_3.dll','descriptor':descriptor,'functions':[{'name':None,'ordinal':2,'iat':0xBC7764}]})
  start=old.raw(U(b,old.opt+104),20*(len(allimports)+1))
  payload=b''.join(x['descriptor']for x in allimports)+bytes(20)
  b[start:start+len(payload)]=payload;struct.pack_into('<I',b,old.opt+108,len(payload))
 # Original static constructors/TLS and CRT manifest are deliberately bypassed.
 for directory in (2,9):struct.pack_into('<2I',b,pe.opt+96+8*directory,0,0)
 c=Code(pe.base+rva,exit_iat)
 c.module('XINPUT1_3.dll',negative,module_iat)
 for module in allimports:c.module(module['name'],True,module_iat)
 # Every original retained IAT entry must have been populated by the real loader.
 for module in allimports:
  for f in module['functions']:
   c.emit(b'\x83\x3D'+P(f['iat'])+b'\x00');c.failure(0x75,21)
 # Native stdcall signature: GetState(DWORD, 16-byte XINPUT_STATE*).
 c.emit(bytes.fromhex('83ec1889e5'))
 for i,value in enumerate((0x1234ABCD,0xA5A5A5A5,0xB6B6B6B6,0xC7C7C7C7,0xD8D8D8D8,0xCAFEBABE)):
  c.emit(bytes.fromhex('c745')+bytes([i*4])+P(value))
 c.emit(bytes.fromhex('8d4504506a00'))
 call=pe.base+rva+len(c.b);c.emit(b'\xE8'+struct.pack('<i',THUNK-call-5))
 c.emit(b'\x3D'+P(1167));c.failure(0x74,22)
 c.emit(bytes.fromhex('39ec'));c.failure(0x74,23)
 for i,value in enumerate((0x1234ABCD,0xA5A5A5A5,0xB6B6B6B6,0xC7C7C7C7,0xD8D8D8D8,0xCAFEBABE)):
  c.emit(bytes.fromhex('817d')+bytes([i*4])+P(value));c.failure(0x74,24)
 c.emit(b'\x6A\x00\xFF\x15'+P(exit_iat));code=c.finish()
 st=pe.st+40*pe.count;assert st+40<=U(b,pe.opt+60)
 raw=ALIGN(len(b),U(b,pe.opt+36));rawsize=ALIGN(len(code),U(b,pe.opt+36))
 b.extend(bytes(raw-len(b)));b.extend(code.ljust(rawsize,b'\0'))
 struct.pack_into('<8s6I2HI',b,st,b'.xprobe\0',len(code),rva,rawsize,raw,0,0,0,0,0x60000020)
 struct.pack_into('<H',b,pe.pe+6,pe.count+1);struct.pack_into('<I',b,pe.opt+16,rva)
 struct.pack_into('<I',b,pe.opt+56,ALIGN(rva+len(code),U(b,pe.opt+32)))
 struct.pack_into('<I',b,pe.opt+64,0)
 return bytes(b)

def main(runtime,destination):
 source=Path(runtime).read_bytes();p=PE(source);imports=p.imports()
 assert p.base==0x400000 and U(source,p.opt+136)==0 and U(source,p.opt+200)==0
 assert source[p.raw(THUNK-p.base,8):p.raw(THUNK-p.base,8)+8]==STUB
 assert [x['name']for x in imports]==EXPECTED_DLLS
 assert not any(x['name'].lower()=='xinput1_3.dll'for x in imports)
 root=Path(destination);root.mkdir(parents=True,exist_ok=True);cwd=root/'game-Data';cwd.mkdir(exist_ok=True)
 sentinel=make_dll('XINPUT1_3.dll',[{'name':None,'ordinal':2}],True)
 (cwd/'XINPUT1_3.dll').write_bytes(sentinel)
 inert={'msvcr80.dll','msvcp80.dll','d3dx9_35.dll'}
 fixtures={}
 for name,negative in [('negative',True),('positive',False)]:
  app=root/(name+'-private');app.mkdir(exist_ok=True)
  (app/'XINPUT1_3.dll').write_bytes(sentinel)
  for module in imports:
   if module['name'].lower()in inert:(app/module['name']).write_bytes(make_dll(module['name'],module['functions']))
  image=probe_image(source,imports,negative);path=app/'loader-probe.exe';path.write_bytes(image)
  fixtures[name]={'path':str(path.resolve()),'sha256':H(image),'imports':len(PE(image).imports()),'expected_exit':0}
 report={'source_runtime_sha256':H(source),'retained_imports':[x['name']for x in imports],
  'retained_import_descriptors_sha256':H(b''.join(x['descriptor']for x in imports)),
  'retained_IAT_entries':sum(len(x['functions'])for x in imports),
  'stub_va':THUNK,'stub_hex':STUB.hex(),'sentinel_sha256':H(sentinel),
  'game_data_directory':str(cwd.resolve()),'fixtures':fixtures,
  'scope':'Loader-only derivatives of actual runtime; original TLS/CRT manifest and entry bypassed; inert legacy CRT/D3DX export providers. Not RA3 gameplay.'}
 (root/'fixtures.json').write_text(json.dumps(report,indent=2)+'\n')
 print('XINPUT_LOADER_FIXTURES_READY',H(source),len(imports),report['retained_IAT_entries'])

if __name__=='__main__':
 assert len(sys.argv)==3
 if sys.argv[1]=='--sentinel':
  Path(sys.argv[2]).write_bytes(make_dll('XINPUT1_3.dll',[{'name':None,'ordinal':2}],True))
 else:main(*sys.argv[1:])
