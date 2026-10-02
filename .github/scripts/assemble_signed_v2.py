"""Transport already signed public files. No publisher signing key is used."""
import base64,hashlib,hmac,io,json,os,re,shutil,struct,subprocess,sys,tempfile,zipfile,zlib
from pathlib import Path
MAX=128*1024*1024
NAMES=('RA3Octane.exe','patches.octpack','release.oct')
sha=lambda b:hashlib.sha256(b).hexdigest()
def require(ok):
 if not ok:raise ValueError('Public transport integrity check failed')
def run(*a):return subprocess.check_output(list(map(str,a)),text=True).strip()
def version(s):
 require(bool(re.fullmatch(r'(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)',s)))
 v=tuple(map(int,s.split('.')));require(max(v)<=65535);return v
def delta(old,meta,folder):
 require(84<=meta['delta_bytes']<2*1024*1024)
 text=''.join((folder/f).read_text().strip()for f in meta.get('files',[meta['file']]))
 packed=base64.b64decode(text,validate=True);require(len(packed)==meta['compressed_bytes']and sha(packed)==meta['sha256'])
 z=zlib.decompressobj();d=z.decompress(packed,meta['delta_bytes']+1)
 require(len(d)==meta['delta_bytes']and z.eof and not z.unused_data and not z.unconsumed_tail and d[:8]==b'OCTBIN01')
 oldn,newn,count=struct.unpack_from('<3I',d,8);require(oldn==len(old)and 0<newn<MAX and 0<count<100000 and d[20:52]==hashlib.sha256(old).digest())
 out=bytearray();at=84
 for _ in range(count):
  require(at<len(d));mode=d[at];at+=1
  if mode==0:
   require(at+8<=len(d));off,n=struct.unpack_from('<II',d,at);at+=8;require(n>0 and off+n<=len(old));chunk=old[off:off+n]
  elif mode==1:
   require(at+4<=len(d));n=struct.unpack_from('<I',d,at)[0];at+=4;require(n>0 and at+n<=len(d));chunk=d[at:at+n];at+=n
  else:raise ValueError('Bad transport opcode')
  require(len(out)+n<=newn);out+=chunk
 require(at==len(d)and len(out)==newn and hashlib.sha256(out).digest()==d[52:84]);return bytes(out)
def pe_version(b):
 def u16(o):return struct.unpack_from('<H',b,o)[0]
 def u32(o):return struct.unpack_from('<I',b,o)[0]
 require(len(b)>512 and b[:2]==b'MZ');pe=u32(60);require(pe+264<=len(b)and b[pe:pe+4]==b'PE\0\0'and u16(pe+4)==0x8664)
 op=pe+24;st=op+u16(pe+20);count=u16(pe+6);require(u16(op)==0x20b and 1<=count<=96 and st+40*count<=len(b))
 def rva(a,n):
  for i in range(count):
   s=st+i*40;va=u32(s+12);size=u32(s+16);off=u32(s+20)
   if a>=va and a-va+n<=size and off+a-va+n<=len(b):return off+a-va
  raise ValueError('Unbacked resource RVA')
 rs=u32(op+132);root=rva(u32(op+128),rs);rel=0
 for depth in range(3):
  require(rel+16<=rs);n=u16(root+rel+12)+u16(root+rel+14);require(0<n<=4096 and rel+16+8*n<=rs)
  selected=None
  for i in range(n):
   ident=u32(root+rel+16+i*8);target=u32(root+rel+20+i*8)
   if(depth==0 and ident==16)or(depth>0 and not ident&0x80000000):selected=target;break
  require(selected is not None)
  if depth<2:require(selected&0x80000000);rel=selected&0x7fffffff
  else:
   require(not selected&0x80000000 and selected+16<=rs);n=u32(root+selected+4);at=rva(u32(root+selected),n);key='VS_VERSION_INFO\0'.encode('utf-16le');off=(6+len(key)+3)&~3
   require(n>=off+52 and b[at+6:at+6+len(key)]==key and u32(at+off)==0xfeef04bd);ms=u32(at+off+8);ls=u32(at+off+12);require(not ls&65535);return(ms>>16,ms&65535,ls>>16)
def assemble(folder,root,out):
 m=json.loads((folder/'manifest.json').read_text());v=version(m['version']);require(v>version(m['base_version'])and m['version']==folder.name)
 oldpath=root/('RA3Octane_'+m['base_version']+'_Players_Compact.zip');oldraw=oldpath.read_bytes();require(len(oldraw)<MAX and sha(oldraw)==m['base_zip_sha256'])
 with zipfile.ZipFile(io.BytesIO(oldraw))as z:
  require(sorted(z.namelist())==sorted('RA3Octane/'+n for n in NAMES));old={n:z.read('RA3Octane/'+n)for n in NAMES}
 openssl=shutil.which('openssl')or 'C:/Program Files/Git/usr/bin/openssl.exe'
 with tempfile.TemporaryDirectory(prefix='octane-public-')as tmp:
  t=Path(tmp)
  def verify(b):
   require(len(b)>384);(t/'signed').write_bytes(b[:-384]);(t/'sig').write_bytes(b[-384:]);r=subprocess.run([openssl,'dgst','-sha256','-verify',str(root/'public-release-key.pem'),'-signature',str(t/'sig'),str(t/'signed')],capture_output=True)
   require(r.returncode==0)
  verify(old['release.oct']);verify(old['patches.octpack']);require(sha(old[NAMES[0]])==m['base_exe_sha256'])
  # Both client-side materials are read only from the already public launcher.
  # Neither material nor any signing-private-key file is carried in transport.
  offsets=m['client_material_offsets'];require(len(offsets)==2 and all(isinstance(o,int)and 0<=o<=len(old[NAMES[0]])-32 for o in offsets))
  enc,mac=(old[NAMES[0]][o:o+32]for o in offsets)
  bp=old[NAMES[1]];n=struct.unpack_from('<Q',bp,24)[0];require(bp[:8]==b'OCTPACK1'and n%16==0 and n+448==len(bp)and hmac.compare_digest(bp[32+n:64+n],hmac.new(mac,bp[:32+n],'sha256').digest()))
  def aes(data,iv,decrypt):
   command=[openssl,'enc','-aes-256-cbc','-nopad','-K',enc.hex(),'-iv',iv.hex()]
   if decrypt:command+=['-d']
   p=subprocess.run(command,input=data,capture_output=True);require(p.returncode==0);return p.stdout
  clear=aes(bp[32:32+n],bp[8:24],True)
  changed=delta(clear,m['deltas']['pack'],folder);header=base64.b64decode(m['pack_header'],validate=True);tail=base64.b64decode(m['pack_tail'],validate=True)
  require(len(header)==32 and header[:8]==b'OCTPACK1'and len(tail)==416 and struct.unpack_from('<Q',header,24)[0]==len(changed))
  pack=header+aes(changed,header[8:24],False);require(hmac.compare_digest(tail[:32],hmac.new(mac,pack,'sha256').digest()));pack+=tail;verify(pack)
  exe=delta(old[NAMES[0]],m['deltas']['exe'],folder);manifest=base64.b64decode(m['manifest'],validate=True);verify(manifest)
  require(manifest[:8]==b'OCTREL02'and struct.unpack_from('<4I',manifest,8)==(*v,2)and pe_version(exe)==v)
  at=24
  def take(n):
   nonlocal at
   require(n>=0 and at+n<=len(manifest)-384);b=manifest[at:at+n];at+=n;return b
  def text():
   s=take(struct.unpack('<H',take(2))[0]).decode('utf8','strict');require('\0'not in s);return s
  require(1<=len(text())<=100);data={NAMES[0]:exe,NAMES[1]:pack}
  for name,b in data.items():require(text()==name and struct.unpack('<Q',take(8))[0]==len(b)and take(32)==hashlib.sha256(b).digest())
  require(at==len(manifest)-384);data[NAMES[2]]=manifest
  for name,b in data.items():require(sha(b)==m['files'][name])
  out.mkdir(parents=True,exist_ok=True);archive=out/('RA3Octane_'+m['version']+'_Players_Compact.zip')
  with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_STORED,allowZip64=False)as z:
   for name,b in data.items():
    i=zipfile.ZipInfo('RA3Octane/'+name,tuple(m['zip_timestamp']));i.external_attr=0o100644<<16;i.compress_type=zipfile.ZIP_STORED;z.writestr(i,b)
  require(archive.stat().st_size==m['archive_bytes']and sha(archive.read_bytes())==m['archive_sha256']);(out/'release.oct').write_bytes(manifest)
  print('PUBLIC_PACKAGE_VERIFIED',m['version'],m['archive_sha256']);return m,archive

def publish(m,archive):
 require(os.environ.get('GH_REPO')=='begosik/OctaneLauncher');endpoint='repos/begosik/OctaneLauncher/releases';tag='v'+m['version'];mf=archive.parent/'release.oct'
 def api(method,path,data):
  r=subprocess.run(['gh','api','--method',method,path,'--input','-'],input=json.dumps(data),text=True,capture_output=True,timeout=60)
  require(r.returncode==0);return json.loads(r.stdout)
 probe=subprocess.run(['gh','api',endpoint+'/tags/'+tag],text=True,capture_output=True)
 if probe.returncode==0:
  release=json.loads(probe.stdout);require(not release['draft']and not release.get('body'));existing=True
 else:
  require('404'in probe.stderr);release=api('POST',endpoint,{'tag_name':tag,'target_commitish':os.environ['GITHUB_SHA'],'name':'RA3 Octane '+m['version'],'body':'','draft':True,'prerelease':False,'generate_release_notes':False});require(release['draft']and not release.get('body'));existing=False
  run('gh','release','upload',tag,archive,mf)
 with tempfile.TemporaryDirectory(prefix='octane-readback-')as tmp:
  p=Path(tmp);run('gh','release','download',tag,'--dir',p,'--pattern',archive.name,'--pattern','release.oct')
  for f in(archive,mf):require((p/f.name).read_bytes()==f.read_bytes())
 if not existing:release=api('PATCH',endpoint+'/'+str(release['id']),{'draft':False,'body':'','make_latest':'true'})
 require(not release['draft']and not release.get('body')and not release['prerelease']);latest=json.loads(run('gh','api',endpoint+'/latest'));require(latest['tag_name']==tag and not latest.get('body'))
 print('PUBLIC_RELEASE_READBACK_VERIFIED',release['html_url'],m['archive_sha256'])
if __name__=='__main__':
 folder=Path(sys.argv[1]);root=Path.cwd();out=Path(sys.argv[2]);m,a=assemble(folder,root,out)
 if len(sys.argv)>3 and sys.argv[3]=='publish':publish(m,a)
