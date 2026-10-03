"""Decode verified public test support; no private source or runtime mutation."""
import base64,hashlib,io,zipfile
from pathlib import Path
r=Path('transport138/1.2.38')
b=base64.b64decode((r/'support.b64').read_text().strip(),validate=True)
assert hashlib.sha256(b).hexdigest()=='f768a1e0389a7624afb0c44e2e9a00eaab17c1d9298b19cb640569ffa809c5a0'
names={'assemble_138.py','layout138.json','bnet_138.ps1','windows_138.ps1','http_bnet_138.ps1'}
with zipfile.ZipFile(io.BytesIO(b)) as z:
    assert set(z.namelist())==names and len(z.infolist())==len(names)
    assert sum(i.file_size for i in z.infolist())<100000
    for n in names:(Path('.github/scripts')/n).write_bytes(z.read(n))
print('PUBLIC_ACCEPTANCE_SUPPORT_VERIFIED')
