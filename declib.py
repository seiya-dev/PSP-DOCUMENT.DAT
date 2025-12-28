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
    
    pgd_data = buf[0x80:-0x10]
    # pgd_data[0xB0:0xC0] = bytes(0x10)
    
    # pgd_bytes = bytes.fromhex(
    #     "00 50 47 44 01 00 00 00  01 00 00 00 00 00 00 00"  # 0x00-0x0F: Magic " PGD", Key Index, DRMType, Padding (Always same)
    #     "6d 17 0a 64 96 fe 18 d2  e6 61 8d 83 3e 56 93 e3"  # 0x10-0x1F: Header key
    #     "5f d9 d2 e3 89 2c a7 f2  3c 48 d1 4f 18 d8 64 7e"  # 0x20-0x2F: Some hash? (Always same)
    #     "90 28 1d f9 ab 40 7b 0a  29 a3 ad a0 1b 80 1b f4"  # 0x30-0x3F: Encrypted data start
    #     "6c e1 dc 1d b2 c8 31 23  b6 06 b9 b3 f5 65 81 34"  # 0x40-0x4F: Encrypted data
    #     "16 8c 86 85 ba 20 25 6c  40 bb a5 01 c0 5d 78 80"  # 0x50-0x5F: Encrypted data end
    #     "3d 12 a1 6b 61 81 40 dd  a5 4a a2 0e bd 1c 13 65"  # 0x60-0x6F: File hash?
    #     "57 80 31 96 ba 26 64 03  0e 63 c8 d2 8e 24 00 1a"  # 0x70-0x7F: Secure Install ID MAC
    #     "80 fd cb da 39 0c a2 9b  75 31 52 c7 49 c3 a3 6a"  # 0x80-0x8F: DNAS MAC
    #     "64 77 10 d6 63 74 46 08  c9 c5 db 75 39 1a 33 22"  # 0x90-0x9F: Data hash?
    #     "fe de 59 fa 10 f5 40 86  87 21 bf 2f aa 89 a1 fe"  # 0xA0-0xAF: Encrypted data hash?
    #     "9c 28 dd 46 1a ed 57 85  33 85 cc b8 62 40 dc 07"  # 0xB0-0xBF: Garbage? (Can be removed)
    # )
    
    #print(hexdump(pgd_data))
    
    Path(f'./edat_out/').mkdir(parents=True, exist_ok=True)
    ofile = open(f'./edat_out/{name}_DOCINFO.EDAT', 'wb')
    ofile.write(pgd_data)
    ofile.close()
    
    # TO DO PYTHON EXTRACTOR
    subprocess.run(['./app/pspdecrypt_mod.exe', '-v', f'./edat_out/{name}_DOCINFO.EDAT'])
    
    kfile = open(f'./edat_out/{name}_DOCINFO.EDAT.dec', 'rb')
    binkey = kfile.read()
    kfile.close()
    
    print(f'  EXTRACTED DOC KEY: {" ".join(f"{v:02X}" for v in binkey)}')
    return binkey
