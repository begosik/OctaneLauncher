"""Reconstruct the final signed public release through a hash-bound public checkpoint.
The actual update baseline remains published 1.2.38. The checkpoint is only a
transport compression dictionary; all three archives are independently verified.
"""
import hashlib,json,sys,tempfile,zipfile
from pathlib import Path
import assemble_signed_v2 as a
from assemble_signed_v3 import delta

def main():
 folder=Path(sys.argv[1]);out=Path(sys.argv[2]);root=Path.cwd();m=json.loads((folder/'manifest.json').read_text())
 assert m['version']=='1.2.39' and m['base_version']=='1.2.38'
 assert m['checkpoint_zip_sha256']=='ce6914ab85e2666c73959dd64e6a1f4f79cd4320b80d042c22acbac1ce791079'
 a.delta=delta
 with tempfile.TemporaryDirectory(prefix='verified-public-checkpoint-') as tmp:
  _,checkpoint=a.assemble(root/'transport139/1.2.39',root,Path(tmp))
  assert hashlib.sha256(checkpoint.read_bytes()).hexdigest()==m['checkpoint_zip_sha256']
  with zipfile.ZipFile(checkpoint) as z: dictionary=z.read('RA3Octane/RA3Octane.exe')
  assert hashlib.sha256(dictionary).hexdigest()==m['checkpoint_exe_sha256']
  def final_delta(old,meta,where):
   if meta['sha256']==m['deltas']['exe']['sha256']:
    assert hashlib.sha256(old).hexdigest()==m['base_exe_sha256']
    return delta(dictionary,meta,where)
   assert meta['sha256']==m['deltas']['pack']['sha256']
   return delta(old,meta,where)
  a.delta=final_delta
  verified,archive=a.assemble(folder,root,out)
 if len(sys.argv)>3 and sys.argv[3]=='publish':a.publish(verified,archive)
if __name__=='__main__':main()
