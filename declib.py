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
    
    # PSPEDAT
    # Byte Offset Field        Length    Values (most likely)
    # 0x00-0x07   magic        08 bytes  b'\0PSPEDAT'
    # 0x08-0x0B   key_index    04 bytes  0x02 0x00 0x00 0x00
    # 0x0C-0x0D   data_offset  02 bytes  0x80
    # 0x0E        data_type    01 byte   0x00
    # 0x0F        version      01 byte   0x00
    # 0x10-0x3F   content_id   48 bytes  EP1234-ULUS01234...
    # 0x40-0x4F   key          16 bytes  Key?
    # 0x50-0x57   padding      08 bytes  Padding
    # 0x58-0x7F   ecdsa_sign   40 bytes  ECDSA sign
    # 0x80...     PGD File     ?? bytes  PGD File
    
    # PGD
    # Byte Offset Field        Length    Values (most likely)
    # 0x00-0x03   magic        04 bytes  b'\0PGD'
    # 0x04-0x07   key_index    04 bytes  Key Index?
    # 0x08-0x0B   drm_type     04 bytes  DRM type/version
    # 0x0C-0x0F   padding      04 bytes  Padding
    # 0x10-0x1F                          Header key
    # 0x20-0x2F                          Some hash? (Always same)
    # 0x30-0x3F                          Encrypted data start
    # 0x40-0x4F                          Encrypted data
    # 0x50-0x5F                          Encrypted data end
    # 0x60-0x6F                          File hash?
    # 0x70-0x7F                          Secure Install ID MAC
    # 0x80-0x8F                          DNAS MAC
    # 0x90-0x9F                          Data hash?
    # 0xA0-0xAF                          Encrypted data hash?
    # 0xB0-0xBF                          Garbage? (Can be removed)
    
    if buf[0x0c:0x10] != b'\x80\0\0\0':
        print(f"  > BAD EDAT FILE")
        return None
    
    # Init PSP ECDSA
    ecdsa = PSPECDSA()
    edata_id = buf[0x10:].split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    print(f"  EDAT ID: {edata_id}")
    
    # ECDSA keys
    sha1_hash = hashlib.sha1(buf[:0x58]).digest()
    signature = buf[0x58:0x6c]
    pubkey    = buf[0x6c:0x80]
    
    # ECDSA hash
    ecdsa_verify = ecdsa.verify(sha1_hash, signature, pubkey)
    
    # Check ECDSA verification
    if not ecdsa_verify:
        print('  > ECDSA verify failed!')
        return None
    
    # PGD decrypt
    pgd_data = buf[0x80:]
    
    # Save extracted EDAT
    Path(f'./edat_out/').mkdir(parents=True, exist_ok=True)
    ofile = open(f'./edat_out/{name}_DOCINFO.EDAT', 'wb')
    ofile.write(pgd_data)
    ofile.close()
    
    # TODO: PYTHON EXTRACTOR
    subprocess.run(['./app/pspdecrypt_mod.exe', '-v', f'./edat_out/{name}_DOCINFO.EDAT'])
    kfile = open(f'./edat_out/{name}_DOCINFO.EDAT.dec', 'rb')
    binkey = kfile.read()
    kfile.close()
    
    # Display DOC_KEY
    print(f'  EXTRACTED DOC KEY: {" ".join(f"{v:02X}" for v in binkey)}')
    
    # Return extracted DOC_KEY
    return binkey
