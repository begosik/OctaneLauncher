"""Reconstruct already signed public bytes using a bounded additive delta."""
import hashlib,lzma,base64,struct,sys
from pathlib import Path
import assemble_signed_v2 as a
original_delta=a.delta

def complete_delta(old,meta,folder):
    if meta.get('codec')!='xz-diff':
        return original_delta(old,meta,folder)
    a.require(92<=meta['delta_bytes']<2*1024*1024)
    names=meta['files']
    a.require(1<=len(names)<=100 and all(__import__('re').fullmatch(r'launcher\d{2}\.b64',n) for n in names))
    text=''.join((folder/n).read_text().strip() for n in names)
    packed=base64.b64decode(text,validate=True)
    a.require(len(packed)==meta['compressed_bytes'] and a.sha(packed)==meta['sha256'])
    z=lzma.LZMADecompressor(memlimit=128*1024*1024)
    d=z.decompress(packed,max_length=meta['delta_bytes']+1)
    a.require(len(d)==meta['delta_bytes'] and z.eof and not z.unused_data and d[:8]==b'OCTDIF02')
    oldn,newn,cn,dn,en=struct.unpack_from('<5I',d,8)
    a.require(oldn==len(old) and newn<a.MAX and cn%12==0 and cn+dn+en+92==len(d) and d[28:60]==hashlib.sha256(old).digest())
    control=d[92:92+cn];diff=d[92+cn:92+cn+dn];extra=d[92+cn+dn:]
    out=bytearray();ap=dp=ep=0
    for x,y,seek in struct.iter_unpack('<iii',control):
        a.require(x>=0 and y>=0 and ap>=0 and ap+x<=len(old) and dp+x<=dn and ep+y<=en and len(out)+x+y<=newn)
        out+=bytes((old[ap+i]+diff[dp+i])&255 for i in range(x))
        out+=extra[ep:ep+y];dp+=x;ep+=y;ap+=x+seek
    a.require(dp==dn and ep==en and len(out)==newn and hashlib.sha256(out).digest()==d[60:92])
    return bytes(out)

a.delta=complete_delta
if __name__=='__main__':
    meta,archive=a.assemble(Path(sys.argv[1]),Path.cwd(),Path(sys.argv[2]))
    if len(sys.argv)>3 and sys.argv[3]=='publish':
        a.publish(meta,archive)
