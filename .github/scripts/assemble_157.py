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
    signed.require(meta['version']=='1.2.57'and meta['base_version']=='1.2.56')
    signed.require(meta['base_zip_sha256']=='e00b647f2116532a9dc2be6327c9ece4c652e1fc51e2f137905b9d773e8162bd')
    signed.require(meta['base_exe_sha256']=='ac9c86953bcd9dd48a1d4bc5fcb0a02970c010d91730a950a8286ca4c0a1419c')
    signed.delta=delta;signed.zipfile.ZipInfo=CanonicalZipInfo
    metadata,archive=signed.assemble(folder,Path.cwd(),Path(sys.argv[2]))
    if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(metadata,archive)
