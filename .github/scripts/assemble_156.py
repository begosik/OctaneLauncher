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
    signed.require(meta['version']=='1.2.56'and meta['base_version']=='1.2.55')
    signed.require(meta['base_zip_sha256']=='b84e517f9ae6c97b2bbd27e37fea3d8ceeb23503193c7e8c150d849336007712')
    signed.require(meta['base_exe_sha256']=='4c4ab58d62a3058d0d10c508879706952cce7bef3057736c4bc117906f527d09')
    signed.delta=delta;signed.zipfile.ZipInfo=CanonicalZipInfo
    metadata,archive=signed.assemble(folder,Path.cwd(),Path(sys.argv[2]))
    if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(metadata,archive)
