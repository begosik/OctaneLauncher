"""Reconstruct an already signed public launcher. No signing keys or source code."""
from pathlib import Path
import base64,hashlib,json,struct,sys,tempfile,subprocess,zipfile,lzma,shutil
import assemble_signed_v2 as signed
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(ok):
 if not ok:raise ValueError('Public 1.2.34 integrity check failed')
def assemble(folder,out):
 root=Path.cwd();m=json.loads((folder/'manifest.json').read_text());need(m['version']=='1.2.34'and m['base_version']=='1.2.33')
 oldzip=root/'RA3Octane_1.2.33_Players_Compact.zip';need(oldzip.is_file()and sha(oldzip.read_bytes())==m['base_zip_sha256'])
 names=('RA3Octane.exe','patches.octpack','release.oct')
 with zipfile.ZipFile(oldzip)as z:
  need(sorted(z.namelist())==sorted('RA3Octane/'+n for n in names));oldfiles={n:z.read('RA3Octane/'+n)for n in names}
 old=oldfiles[names[0]];compressed=base64.b64decode((folder/'launcher.b64').read_text().strip(),validate=True)
 need(len(compressed)==m['delta_bytes']and sha(compressed)==m['delta_sha256']and 84<m['delta_clear_bytes']<2*1024*1024)
 dz=lzma.LZMADecompressor(memlimit=128*1024*1024);d=dz.decompress(compressed,max_length=m['delta_clear_bytes']+1)
 need(len(d)==m['delta_clear_bytes']and dz.eof and not dz.unused_data and d[:8]==b'OCTADD02')
 oldn,newn,count,controln=struct.unpack_from('<4I',d,8);need(oldn==len(old)and 0<newn<4*1024*1024 and 0<count<100000 and hashlib.sha256(old).digest()==d[24:56]);at=88;limit=at+controln;pos=limit;previous=0;exe=bytearray();need(limit<=len(d))
 def var():
  nonlocal at
  value=0
  for shift in range(0,35,7):
   need(at<limit);b=d[at];at+=1;value|=(b&127)<<shift
   if b<128:return value
  raise ValueError('Oversize public delta integer')
 for _ in range(count):
  v=var();mode=v&3;n=v>>2;v=var();off=previous+(v//2 if v%2==0 else -(v//2)-1);previous=off+n
  need(n>0 and off>=0 and len(exe)+n<=newn)
  if mode==0:need(off+n<=len(old));exe+=old[off:off+n]
  elif mode==1:
   need(off+n<=len(old)and pos+n<=len(d));exe+=bytes((a+b)&255 for a,b in zip(old[off:off+n],d[pos:pos+n]));pos+=n
  elif mode==2:need(pos+n<=len(d));exe+=d[pos:pos+n];pos+=n
  else:raise ValueError('Invalid public delta opcode')
 need(at==limit and pos==len(d)and len(exe)==newn and hashlib.sha256(exe).digest()==d[56:88]);exe=bytes(exe)
 manifest=base64.b64decode(m['manifest_base64'],validate=True);pack=oldfiles[names[1]]
 openssl=shutil.which('openssl')or 'C:/Program Files/Git/usr/bin/openssl.exe'
 with tempfile.TemporaryDirectory()as td:
  t=Path(td)
  for b in (oldfiles[names[2]],pack,manifest):
   need(len(b)>384);(t/'data').write_bytes(b[:-384]);(t/'sig').write_bytes(b[-384:]);subprocess.run([openssl,'dgst','-sha256','-verify',str(root/'public-release-key.pem'),'-signature',str(t/'sig'),str(t/'data')],check=True,stdout=subprocess.DEVNULL)
 need(manifest[:8]==b'OCTREL02'and struct.unpack_from('<IIII',manifest,8)==(1,2,34,2)and signed.pe_version(exe)==(1,2,34));at=24
 def take(n):
  nonlocal at
  need(n>=0 and at+n<=len(manifest)-384);b=manifest[at:at+n];at+=n;return b
 def text():return take(struct.unpack('<H',take(2))[0]).decode('utf8','strict')
 need(text()=='Octane 1.2.34 / V134Y');data={names[0]:exe,names[1]:pack}
 for name,b in data.items():need(text()==name and struct.unpack('<Q',take(8))[0]==len(b)and take(32)==hashlib.sha256(b).digest())
 need(at==len(manifest)-384);data[names[2]]=manifest;out.mkdir(parents=True,exist_ok=True);archive=out/'RA3Octane_1.2.34_Players_Compact.zip'
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_STORED,allowZip64=False)as z:
  for name,b in data.items():
   i=zipfile.ZipInfo('RA3Octane/'+name,tuple(m['zip_timestamp']));i.create_system=3;i.external_attr=0o100644<<16;i.compress_type=0;z.writestr(i,b)
 need(archive.stat().st_size==m['archive_bytes']and sha(archive.read_bytes())==m['archive_sha256']);(out/'release.oct').write_bytes(manifest)
 print('PUBLIC_PACKAGE_VERIFIED',m['version'],m['archive_sha256']);return m,archive
if __name__=='__main__':
 m,a=assemble(Path(sys.argv[1]),Path(sys.argv[2]))
 if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(m,a)
