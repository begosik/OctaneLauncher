"""Reconstruct already-signed public EXE/pack changes; no publisher key.

Client AES/HMAC materials are read only from the authenticated public baseline
EXE. New ciphertext is authenticated by the exact supplied signed pack tail.
"""
from pathlib import Path
import hashlib,json,sys,zipfile
import assemble_signed_v2 as signed
from assemble_signed_v3 import delta

class CanonicalZipInfo(signed.zipfile.ZipInfo):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.create_system=3

if __name__=='__main__':
    folder=Path(sys.argv[1]);meta=json.loads((folder/'manifest.json').read_text())
    signed.require(meta['version']=='1.2.46'and meta['base_version']=='1.2.45'and meta['pack_identical_to_base'] is True)
    signed.delta=delta;signed.zipfile.ZipInfo=CanonicalZipInfo
    metadata,archive=signed.assemble(folder,Path.cwd(),Path(sys.argv[2]))
    with zipfile.ZipFile('RA3Octane_1.2.45_Players_Compact.zip')as baseline:
        signed.require(hashlib.sha256(baseline.read('RA3Octane/patches.octpack')).hexdigest()==metadata['files']['patches.octpack'])
    if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(metadata,archive)
