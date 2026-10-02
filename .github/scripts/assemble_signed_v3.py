"""Bounded transport decoding for already signed public distribution files."""
import base64
import hashlib
import lzma
import re
import struct
import sys
import zlib
from pathlib import Path


def require(ok):
    if not ok:
        raise ValueError('Public transport integrity check failed')


def delta(old, meta, folder):
    size = meta['delta_bytes']
    require(isinstance(size, int) and 84 <= size < 2 * 1024 * 1024)
    files = meta['files'] if 'files' in meta else [meta['file']]
    require(isinstance(files, list) and 1 <= len(files) <= 100)
    require(all(isinstance(n, str) and re.fullmatch(r'[A-Za-z0-9_-]+\.b64', n) for n in files))
    require(all((folder / n).stat().st_size <= 3 * 1024 * 1024 for n in files))
    text = ''.join((folder / n).read_text().strip() for n in files)
    require(len(text) <= 3 * 1024 * 1024)
    packed = base64.b64decode(text, validate=True)
    require(len(packed) == meta['compressed_bytes'] and hashlib.sha256(packed).hexdigest() == meta['sha256'])
    kind = meta.get('compression', 'zlib')
    if kind == 'xz':
        dec = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024 * 1024)
        data = dec.decompress(packed, max_length=size + 1)
        require(dec.eof and not dec.unused_data)
    elif kind == 'zlib':
        dec = zlib.decompressobj()
        data = dec.decompress(packed, size + 1)
        require(dec.eof and not dec.unused_data and not dec.unconsumed_tail)
    else:
        raise ValueError('Unsupported transport compression')
    require(len(data) == size and data[:8] == b'OCTBIN01')
    old_size, new_size, count = struct.unpack_from('<3I', data, 8)
    require(old_size == len(old) and 0 < new_size < 128 * 1024 * 1024 and 0 < count < 100000)
    require(data[20:52] == hashlib.sha256(old).digest())
    out = bytearray()
    at = 84
    for _ in range(count):
        require(at < len(data))
        mode = data[at]
        at += 1
        if mode in (0, 2):
            require(at + 8 <= len(data))
            off, n = struct.unpack_from('<II', data, at)
            at += 8
            require(n > 0 and off + n <= len(old) and len(out) + n <= new_size)
            chunk = old[off:off + n]
            if mode == 2:
                require(at + n <= len(data))
                chunk = bytes((a + b) & 255 for a, b in zip(chunk, data[at:at + n]))
                at += n
        elif mode == 1:
            require(at + 4 <= len(data))
            n = struct.unpack_from('<I', data, at)[0]
            at += 4
            require(n > 0 and at + n <= len(data) and len(out) + n <= new_size)
            chunk = data[at:at + n]
            at += n
        else:
            raise ValueError('Invalid transport opcode')
        out += chunk
    require(at == len(data) and len(out) == new_size and hashlib.sha256(out).digest() == data[52:84])
    return bytes(out)


if __name__ == '__main__':
    import assemble_signed_v2 as signed
    signed.delta = delta
    metadata, archive = signed.assemble(Path(sys.argv[1]), Path.cwd(), Path(sys.argv[2]))
    if len(sys.argv) > 3 and sys.argv[3] == 'publish':
        signed.publish(metadata, archive)
