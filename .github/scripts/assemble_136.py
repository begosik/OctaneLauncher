"""Receive already-signed public runtime bytes; no private source or signing key."""
from pathlib import Path
import base64,hashlib,json,struct,sys,tempfile,subprocess,zipfile,shutil,io
import assemble_signed_v2 as signed
from assemble_signed_v3 import delta

def need(ok):
 if not ok:raise ValueError('Public 1.2.36 transport verification failed')
def sha(b):return hashlib.sha256(b).hexdigest()
def assemble(folder,out):
 root=Path.cwd();m=json.loads((folder/'manifest.json').read_text())
 need(m['version']=='1.2.36'and m['base_version']=='1.2.35')
 raw=(root/'RA3Octane_1.2.35_Players_Compact.zip').read_bytes();need(sha(raw)==m['base_zip_sha256'])
 names=('RA3Octane.exe','patches.octpack','release.oct')
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  need(sorted(z.namelist())==sorted('RA3Octane/'+n for n in names));old={n:z.read('RA3Octane/'+n)for n in names}
 exe=delta(old[names[0]],m,folder);pack=old[names[1]];manifest=base64.b64decode(m['manifest'],validate=True)
 openssl=shutil.which('openssl')or 'C:/Program Files/Git/usr/bin/openssl.exe'
 with tempfile.TemporaryDirectory()as td:
  t=Path(td)
  for b in (old[names[2]],pack,manifest):
   need(len(b)>384);(t/'data').write_bytes(b[:-384]);(t/'sig').write_bytes(b[-384:])
   subprocess.run([openssl,'dgst','-sha256','-verify',str(root/'public-release-key.pem'),'-signature',str(t/'sig'),str(t/'data')],check=True,stdout=subprocess.DEVNULL)
 need(manifest[:8]==b'OCTREL02'and struct.unpack_from('<4I',manifest,8)==(1,2,36,2)and signed.pe_version(exe)==(1,2,36));at=24
 def take(n):
  nonlocal at
  need(0<=n<=len(manifest)-384-at);v=manifest[at:at+n];at+=n;return v
 def text():return take(struct.unpack('<H',take(2))[0]).decode('utf8','strict')
 need(text()=='Octane 1.2.36 / 4GB');data={names[0]:exe,names[1]:pack}
 for n,b in data.items():need(text()==n and struct.unpack('<Q',take(8))[0]==len(b)and take(32)==hashlib.sha256(b).digest())
 need(at==len(manifest)-384);data[names[2]]=manifest;out.mkdir(parents=True,exist_ok=True);archive=out/'RA3Octane_1.2.36_Players_Compact.zip'
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_STORED,allowZip64=False)as z:
  for n,b in data.items():
   i=zipfile.ZipInfo('RA3Octane/'+n,tuple(m['zip_timestamp']));i.create_system=3;i.external_attr=0o100644<<16;i.compress_type=0;z.writestr(i,b)
 need(archive.stat().st_size==m['archive_bytes']and sha(archive.read_bytes())==m['archive_sha256']);(out/'release.oct').write_bytes(manifest)
 print('PUBLIC_PACKAGE_VERIFIED',m['version'],m['archive_sha256']);return m,archive
if __name__=='__main__':
 m,a=assemble(Path(sys.argv[1]),Path(sys.argv[2]))
 if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(m,a)
