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
    signed.require(meta['version']=='1.2.61'and meta['base_version']=='1.2.57')
    signed.require(meta['base_zip_sha256']=='24196904fffd52d00113672c68d2dc6299f59b62fe42cddd13bab440ea7a3025')
    signed.require(meta['base_exe_sha256']=='38d2ca2872915bddf50278a180673a594421a307dfb9049577046e1268cbbb96')
    signed.delta=delta;signed.zipfile.ZipInfo=CanonicalZipInfo
    metadata,archive=signed.assemble(folder,Path.cwd(),Path(sys.argv[2]))
    if len(sys.argv)>3 and sys.argv[3]=='publish':signed.publish(metadata,archive)
