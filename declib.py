import os

import struct
import hashlib
from ecdsa import PSPECDSA
from pathlib import Path
import subprocess

###################

def hexdump(data: bytes, start_offset: int = 0) -> str:
    if start_offset < 0:
        raise ValueError('start_offset must be >= 0')
    
    fmt = '{:08x}  {:23}  {:23}  |{:16}|'
    base, pad, i, out = start_offset & ~0xF, start_offset & 0xF, 0, []
    
    hx = lambda bs: ' '.join(('  ' if b is None else f'{b:02x}') for b in bs).ljust(23)
    asc = lambda bs: ''.join('.' if b is None else (chr(b) if 32 <= b <= 126 else '.') for b in bs)
    
    while i < len(data):
        take = min(16 - pad, len(data) - i)
        cells = [None] * pad + list(data[i:i + take]) + [None] * (16 - pad - take)
        out.append(fmt.format(base, hx(cells[:8]), hx(cells[8:]), asc(cells)))
        i, base, pad = i + take, base + 16, 0
    
    out.append(f'{start_offset + len(data):08x}')
    return '\n'.join(out)

###################

def free_edata(name: str, buf: bytes):
    if buf[:0x08] != b'\x00PSPEDAT':
        return None
    
    ecdsa = PSPECDSA()
    edata_id = buf[0x10:].split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    # print(f"  EDATA ID: {edata_id}")
    
    sha1_hash = hashlib.sha1(buf[:0x58]).digest()
    signature = buf[0x58:0x6c]
    pubkey    = buf[0x6c:0x80]
    
    ecdsa_verify = ecdsa.verify(sha1_hash, signature, pubkey)
    
    if not ecdsa_verify:
        print('  > ECDSA verify failed!')
        return None
    
    if not os.path.isfile(f'./edat_out/{name}_DOCINFO.EDAT'):
        Path(f'./edat_out/').mkdir(parents=True, exist_ok=True)
        ofile = open(f'./edat_out/{name}_DOCINFO.EDAT', 'wb')
        ofile.write(buf[0x80:])
        ofile.close()
    
    if not os.path.isfile(f'./edat_out/{name}_DOCINFO.EDAT'):
        # TO DO PYTHON EXTRACTOR
        subprocess.run(['./app/pspdecrypt_mod.exe', f'./edat_out/{name}_DOCINFO.EDAT'])
    
    kfile = open(f'./edat_out/{name}_DOCINFO.EDAT.dec', 'rb')
    binkey = kfile.read()
    kfile.close()
    return binkey
