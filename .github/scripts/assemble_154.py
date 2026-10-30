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
    signed.require(meta['version']=='1.2.54'and meta['base_version']=='1.2.53')
    signed.require(meta['base_zip_sha256']=='8b3158ce1212df110d6bf68c46c2e8cfa628102588b10575f90bdc179caed536')
    signed.require(meta['base_exe_sha256']=='94cf50675d44239764418fe3e1aa0037b54053e92e1041e81543a5dfeea4ab1a')
    signed.delta=delta;signed.zipfile.ZipInfo=CanonicalZipInfo
    metadata,archive=signed.assemble(folder,Path.cwd(),Path(sys.argv[2]))
    if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(metadata,archive)
