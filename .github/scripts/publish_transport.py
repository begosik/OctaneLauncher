"""Reconstruct and publish a signed public release from previously public bytes.
No executable is run by the publication job.
"""
import base64, hashlib, io, json, os, re, struct, subprocess, tempfile, zipfile, zlib
from pathlib import Path
R=Path.cwd();MAX=128*1024*1024
sha=lambda b:hashlib.sha256(b).hexdigest()
def cmd(*a):return subprocess.check_output(list(map(str,a)),text=True).strip()
def version(s):
 if not re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',s):raise ValueError('Invalid version')
 v=tuple(map(int,s.split('.')))
 if max(v)>65535:raise ValueError('Invalid version range')
 return v
paths=list((R/'distribution').glob('*/publish.json'))
if not paths:print('No new public package.');raise SystemExit(0)
p=max(paths,key=lambda p:version(p.parent.name));meta=json.loads(p.read_text());v=meta['version'];base=meta['base_version']
assert v==p.parent.name and version(v)>version(base) and os.environ['GH_REPO']=='begosik/OctaneLauncher'
assert 1<=meta['parts']<=100 and 0<meta['delta_bytes']<2*1024*1024 and 84<meta['delta_clear_bytes']<2*1024*1024
with tempfile.TemporaryDirectory(prefix='octane-publish-')as td:
 t=Path(td)
 # Reuse only the immutable public base asset and confirm its complete hash.
 cmd('gh','release','download','v'+base,'--dir',t,'--pattern','RA3Octane_'+base+'_Players_Compact.zip')
 source=t/('RA3Octane_'+base+'_Players_Compact.zip');assert source.stat().st_size<MAX
 raw=source.read_bytes();assert sha(raw)==meta['base_zip_sha256']
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  assert sorted(z.namelist())==sorted('RA3Octane/'+n for n in ('RA3Octane.exe','patches.octpack','release.oct'))
  old=z.read('RA3Octane/RA3Octane.exe');pack=z.read('RA3Octane/patches.octpack')
 text=''.join((p.parent/('part%02d.b64'%i)).read_text().strip()for i in range(meta['parts']))
 delta=base64.b64decode(text,validate=True);assert len(delta)==meta['delta_bytes'] and sha(delta)==meta['delta_sha256']
 dz=zlib.decompressobj();d=dz.decompress(delta,meta['delta_clear_bytes']+1)
 assert len(d)==meta['delta_clear_bytes'] and dz.eof and not dz.unused_data and not dz.unconsumed_tail
 assert d[:8]==b'OCTBIN01';oldsize,newsize,count=struct.unpack_from('<3I',d,8)
 assert oldsize==len(old) and newsize<4*1024*1024 and 0<count<100000
 assert hashlib.sha256(old).digest()==d[20:52]
 out=bytearray();at=84
 for _ in range(count):
  assert at<len(d);mode=d[at];at+=1
  if mode==0:
   assert at+8<=len(d);o,n=struct.unpack_from('<II',d,at);at+=8
   assert n>0 and o+n<=len(old) and len(out)+n<=newsize;out+=old[o:o+n]
  elif mode==1:
   assert at+4<=len(d);n=struct.unpack_from('<I',d,at)[0];at+=4
   assert n>0 and at+n<=len(d) and len(out)+n<=newsize;out+=d[at:at+n];at+=n
  else:raise ValueError('Invalid binary record')
 assert at==len(d) and len(out)==newsize and hashlib.sha256(out).digest()==d[52:84]
 exe=bytes(out);manifest=base64.b64decode(meta['manifest_base64'],validate=True)
 def verify(b):
  assert len(b)>384
  (t/'signed.bin').write_bytes(b[:-384]);(t/'signature.bin').write_bytes(b[-384:])
  subprocess.run(['openssl','dgst','-sha256','-verify',str(R/'public-release-key.pem'),'-signature',str(t/'signature.bin'),str(t/'signed.bin')],check=True,stdout=subprocess.DEVNULL)
 verify(manifest);verify(pack)
 # Inspect the actual signed manifest, its ordered names, version and hashes.
 assert manifest[:8]==b'OCTREL02' and struct.unpack_from('<4I',manifest,8)==(*version(v),2)
 at=24
 def take(n):
  global at
  assert n>=0 and at+n<=len(manifest)-384
  b=manifest[at:at+n];at+=n;return b
 def txt():return take(struct.unpack('<H',take(2))[0]).decode('utf8','strict')
 assert 1<=len(txt())<=100
 data={'RA3Octane.exe':exe,'patches.octpack':pack}
 for name,b in data.items():
  assert txt()==name and struct.unpack('<Q',take(8))[0]==len(b) and take(32)==hashlib.sha256(b).digest()
 assert at==len(manifest)-384
 # VERSIONINFO must agree with the release. Search the fixed resource key,
 # then verify the complete fixed-value structure rather than a visible title.
 key=('VS_VERSION_INFO\0').encode('utf-16le');positions=[];start=0
 while True:
  x=exe.find(key,start)
  if x<0:break
  positions.append(x);start=x+1
 valid=False
 for x in positions:
  fixed=(x+len(key)+3)&~3
  if fixed+52>len(exe)or struct.unpack_from('<I',exe,fixed)[0]!=0xfeef04bd:continue
  ms,ls=struct.unpack_from('<II',exe,fixed+8)
  if (ms>>16,ms&65535,ls>>16)==version(v)and not(ls&65535):valid=True
 assert valid and exe[:2]==b'MZ'
 data['release.oct']=manifest;archive=t/('RA3Octane_'+v+'_Players_Compact.zip')
 with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED,allowZip64=False)as z:
  for n,b in data.items():
   item=zipfile.ZipInfo('RA3Octane/'+n,tuple(meta['zip_timestamp']));item.external_attr=0o100644<<16;item.compress_type=zipfile.ZIP_STORED;z.writestr(item,b)
 assert archive.stat().st_size==meta['archive_bytes'] and sha(archive.read_bytes())==meta['archive_sha256']
 tag='v'+v;probe=subprocess.run(['gh','api','repos/'+os.environ['GH_REPO']+'/releases/tags/'+tag],capture_output=True,text=True)
 if probe.returncode==0:
  release=json.loads(probe.stdout)
  if not release['draft']:
   print('This version is already published; no existing asset is changed.');raise SystemExit(0)
  raise ValueError('A draft with this version already exists; inspect it before retrying')
 assert '404' in probe.stderr,probe.stderr
 notes=p.parent/'notes.md';assert notes.is_file()
 cmd('gh','release','create',tag,'--draft','--title','RA3 Octane '+v,'--notes-file',notes,'--target','main')
 mf=t/'release.oct';mf.write_bytes(manifest)
 cmd('gh','release','upload',tag,archive,mf)
 check=t/'downloaded';check.mkdir()
 cmd('gh','release','download',tag,'--dir',check,'--pattern',archive.name,'--pattern','release.oct')
 for f in (archive,mf):assert sha((check/f.name).read_bytes())==sha(f.read_bytes()),'Upload verification failed'
 cmd('gh','release','edit',tag,'--draft=false','--latest')
 print('PUBLISHED',cmd('gh','release','view',tag,'--json','url','--jq','.url'))
 print('PACKAGE_SHA256',sha(archive.read_bytes()))
 print('MANIFEST_SHA256',sha(manifest))
