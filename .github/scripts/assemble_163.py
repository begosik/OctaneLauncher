"""Reconstruct signed public163 bytes; upstream DXVK is read only as data.

Only literal byte spans in the existing compressed pack are supplied from the
fixed official renderer archive. No LZ4 re-encoding or game/DLL execution occurs.
The unchanged V2 assembler verifies HMAC, RSA, file hashes and the exact ZIP.
"""
import argparse
import base64
import hashlib
import io
import json
import lzma
import re
import struct
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath
import assemble_signed_v2 as signed
from assemble_signed_v3 import delta as standard_delta

BASE_ZIP_SHA = '24196904fffd52d00113672c68d2dc6299f59b62fe42cddd13bab440ea7a3025'
BASE_EXE_SHA = '38d2ca2872915bddf50278a180673a594421a307dfb9049577046e1268cbbb96'
ARCHIVE_URL = 'https://github.com/doitsujin/dxvk/releases/download/v3.1.1/dxvk-3.1.1.tar.gz'
ARCHIVE_API = 'https://api.github.com/repos/doitsujin/dxvk/releases/assets/566164743'
ARCHIVE_BYTES = 18041512
ARCHIVE_SHA = '40565b4a724aadc4433fa4e010b4b23916d9b1f1baeee64e17186db94f54e608'
MEMBER = 'dxvk-3.1.1/x32/d3d9.dll'
DLL_BYTES = 7856142
DLL_SHA = '265888c31ca78dffa290c39cb7e50bfb02762590e41927906e46fb32f01497fa'
CODEC = 'external-lz4-literals-163-v1'
MAX_DELTA = 16 * 1024 * 1024
MAX_MAP = 16 * 1024 * 1024
MAX_RANGES = 1000000
require = signed.require
sha = signed.sha
_renderer_archive = None
_renderer = None


class CanonicalZipInfo(signed.zipfile.ZipInfo):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.create_system = 3


def renderer_from_archive(archive):
    require(len(archive) == ARCHIVE_BYTES and sha(archive) == ARCHIVE_SHA)
    matches = []
    total = count = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as package:
        for member in package:
            count += 1
            total += member.size
            path = PurePosixPath(member.name)
            require(count <= 256 and 0 <= total <= 128 * 1024 * 1024)
            require(len(member.name.encode('utf-8')) <= 512 and not path.is_absolute())
            require('..' not in path.parts and '\\' not in member.name)
            if str(path) == MEMBER:
                require(member.name == MEMBER and member.isfile() and not member.issym() and not member.islnk())
                require(member.size == DLL_BYTES)
                matches.append(member)
        require(len(matches) == 1)
        stream = package.extractfile(matches[0])
        require(stream is not None)
        with stream:
            renderer = stream.read(DLL_BYTES + 1)
    require(len(renderer) == DLL_BYTES and sha(renderer) == DLL_SHA)
    return renderer


def official_renderer():
    global _renderer
    if _renderer is not None:
        return _renderer
    if _renderer_archive is not None:
        require(_renderer_archive.stat().st_size == ARCHIVE_BYTES)
        archive = _renderer_archive.read_bytes()
    else:
        archive = None
        errors = []
        for url in (ARCHIVE_URL, ARCHIVE_API):
            try:
                request = urllib.request.Request(url, headers={
                    'User-Agent': 'RA3-Octane-public-assembler/1.2.63',
                    'Accept': 'application/octet-stream',
                })
                with urllib.request.urlopen(request, timeout=30) as response:
                    require(response.geturl().startswith('https://'))
                    length = response.headers.get('Content-Length')
                    require(length is None or int(length) == ARCHIVE_BYTES)
                    data = response.read(ARCHIVE_BYTES + 1)
                require(len(data) == ARCHIVE_BYTES and sha(data) == ARCHIVE_SHA)
                archive = data
                break
            except Exception as error:
                errors.append(type(error).__name__)
        if archive is None:
            raise ValueError('Official DXVK archive download failed: ' + ', '.join(errors))
    _renderer = renderer_from_archive(archive)
    return _renderer


def decoded_blob(meta, folder, size_key, maximum):
    size = meta[size_key]
    require(isinstance(size, int) and 16 <= size <= maximum)
    files = meta['files']
    require(isinstance(files, list) and 1 <= len(files) <= 2048)
    require(all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]+\.b64', name) for name in files))
    require(len(files) == len(set(files)))
    text = []
    length = 0
    for name in files:
        path = folder / name
        require(path.stat().st_size <= 16384)
        part = path.read_text().strip()
        length += len(part)
        require(length <= 32 * 1024 * 1024)
        text.append(part)
    packed = base64.b64decode(''.join(text), validate=True)
    require(len(packed) == meta['compressed_bytes'] and sha(packed) == meta['sha256'])
    require(meta.get('compression') == 'xz')
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024 * 1024)
    data = decoder.decompress(packed, max_length=size + 1)
    require(len(data) == size and decoder.eof and not decoder.unused_data)
    return data


def pack_delta(old, meta, folder):
    data = decoded_blob(meta, folder, 'delta_bytes', MAX_DELTA)
    require(len(data) >= 84 and data[:8] == b'OCTBIN01')
    old_size, new_size, count = struct.unpack_from('<3I', data, 8)
    require(old_size == len(old) and 0 < new_size < signed.MAX and 0 < count < 1000000)
    require(data[20:52] == hashlib.sha256(old).digest())
    output = bytearray()
    at = 84
    for _ in range(count):
        require(at < len(data))
        mode = data[at]
        at += 1
        if mode == 0:
            require(at + 8 <= len(data))
            offset, size = struct.unpack_from('<II', data, at)
            at += 8
            require(size > 0 and offset + size <= len(old))
            chunk = old[offset:offset + size]
        elif mode == 1:
            require(at + 4 <= len(data))
            size = struct.unpack_from('<I', data, at)[0]
            at += 4
            require(size > 0 and at + size <= len(data))
            chunk = data[at:at + size]
            at += size
        else:
            raise ValueError('Invalid external transport delta opcode')
        require(len(output) + size <= new_size)
        output += chunk
    require(at == len(data) and len(output) == new_size and hashlib.sha256(output).digest() == data[52:84])
    return output


def fill_renderer(output, ranges, renderer):
    require(ranges[:8] == b'OCTXMAP1' and len(ranges) >= 16)
    count, literal_bytes = struct.unpack_from('<II', ranges, 8)
    require(0 < count <= MAX_RANGES and 0 < literal_bytes <= DLL_BYTES)
    at = 16
    compressed_end = asset_end = total = 0

    def integer():
        nonlocal at
        value = 0
        for shift in range(0, 35, 7):
            require(at < len(ranges))
            byte = ranges[at]
            at += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                require(value <= 0xffffffff and (shift == 0 or byte != 0))
                return value
        raise ValueError('External range integer overflow')

    for _ in range(count):
        offset = compressed_end + integer()
        asset_offset = asset_end + integer()
        size = integer()
        require(size > 0 and offset + size <= len(output) and asset_offset + size <= len(renderer))
        require(not any(output[offset:offset + size]))
        output[offset:offset + size] = renderer[asset_offset:asset_offset + size]
        compressed_end, asset_end = offset + size, asset_offset + size
        total += size
    require(at == len(ranges) and total == literal_bytes)
    return bytes(output)


def delta(old, meta, folder):
    if meta.get('codec') != CODEC:
        return standard_delta(old, meta, folder)
    external = meta['external_renderer']
    require(external['version'] == '3.1.1' and external['archive_url'] == ARCHIVE_URL and external['archive_api'] == ARCHIVE_API)
    require(external['archive_bytes'] == ARCHIVE_BYTES and external['archive_sha256'] == ARCHIVE_SHA)
    require(external['member'] == MEMBER and external['bytes'] == DLL_BYTES and external['sha256'] == DLL_SHA)
    output = pack_delta(old, meta, folder)
    ranges = decoded_blob(external['map'], folder, 'decoded_bytes', MAX_MAP)
    require(sha(ranges) == external['map']['decoded_sha256'])
    require(len(ranges) >= 16 and struct.unpack_from('<II', ranges, 8) == (external['map']['ranges'], external['map']['literal_bytes']))
    result = fill_renderer(output, ranges, official_renderer())
    require(sha(result) == meta['filled_clear_sha256'])
    return result


def main():
    global _renderer_archive
    parser = argparse.ArgumentParser()
    parser.add_argument('folder', type=Path)
    parser.add_argument('out', type=Path)
    parser.add_argument('action', nargs='?', choices=['publish'])
    parser.add_argument('--renderer-archive', type=Path)
    arguments = parser.parse_args()
    metadata = json.loads((arguments.folder / 'manifest.json').read_text())
    require(metadata['version'] == '1.2.63' and metadata['base_version'] == '1.2.57')
    require(metadata['base_zip_sha256'] == BASE_ZIP_SHA and metadata['base_exe_sha256'] == BASE_EXE_SHA)
    require(metadata['deltas']['pack'].get('codec') == CODEC)
    _renderer_archive = arguments.renderer_archive
    signed.delta = delta
    signed.zipfile.ZipInfo = CanonicalZipInfo
    metadata, archive = signed.assemble(arguments.folder, Path.cwd(), arguments.out)
    if arguments.action == 'publish':
        signed.publish(metadata, archive)


if __name__ == '__main__':
    main()
