"""Report public-package PE metadata only. Do not run or export embedded binaries."""
from pathlib import Path
import hashlib, json, re, runpy, struct, sys
import pefile

sys.argv = ['extract_native141.py', 'RA3Octane_1.2.40_Players_Compact.zip', 'RA3Octane_1.2.41_Players_Compact.zip', 'transport141/1.2.41/manifest.json', 'private-fixture']
state = runpy.run_path('.github/scripts/extract_native141.py')
payload = state['p']
rows = []
for match in re.finditer(b'MZ', payload):
    offset = match.start()
    try:
        header = struct.unpack_from('<I', payload, offset + 60)[0]
        if not 64 <= header < 4096 or payload[offset+header:offset+header+4] != b'PE\0\0':
            continue
        image = pefile.PE(data=payload[offset:], fast_load=True)
        size = max([image.OPTIONAL_HEADER.SizeOfHeaders] + [s.PointerToRawData+s.SizeOfRawData for s in image.sections])
        if size > len(payload)-offset:
            continue
        digest = hashlib.sha256(payload[offset:offset+size]).digest()
        rows.append({'offset': offset, 'size': size, 'image_base': hex(image.OPTIONAL_HEADER.ImageBase), 'sha256': digest.hex(), 'checksum_in_package_header': digest in payload[:256]})
    except (ValueError, struct.error, pefile.PEFormatError):
        continue
out = Path('inspection')
out.mkdir(exist_ok=True)
(out/'pe_metadata.json').write_text(json.dumps(rows, indent=2))
print(json.dumps(rows, indent=2))
