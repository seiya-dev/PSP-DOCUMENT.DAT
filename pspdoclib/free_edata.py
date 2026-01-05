import os

import struct
import hashlib
from pathlib import Path

from .ecdsa_psp import PSPECDSA
from .bbox import decrypt_bbox_blob, BBoxException
from .hexdump import hexdump

###################

def free_edata(name: str, buf: bytes):
    if buf[:0x08] != b'\x00PSPEDAT':
        return None
    
    # DOCINFO.EDAT
    # Byte Offset Field        Length     Values (most likely)
    # 0x00-0x07   magic          8 bytes  b'\0PSPEDAT'
    # 0x08-0x0B   key_index      4 bytes  0x02 0x00 0x00 0x00 (MAC type 3), 0x00 0x00 0x00 0x01 (FREE)
    # 0x0C-0x0D   data_offset    2 bytes  0x80
    # 0x0E        data_type      1 byte   0x00
    # 0x0F        version        1 byte   0x00
    # 0x10-0x3F   content_id    48 bytes  EP1234-ULUS01234...
    # 0x40-0x4F   key           16 bytes  Key?..
    # 0x50-0x57   padding        8 bytes  Padding
    # 0x58-0x7F   ecdsa_sign    40 bytes  ECDSA sign
    # 0x80...     PGD File     192 bytes  PGD File
    
    # PGD File inside DOCINFO.EDAT
    # Byte Offset Field          Length    Values (most likely)
    # 0x00-0x03   magic           4 bytes  b'\0PGD'
    # 0x04-0x07   key_index       4 bytes  Always 1 for MAC type 1
    # 0x08-0x0B   drm_type        4 bytes  BB MAC / Cipher key type: 1 common (static driver key)
    # 0x0C-0x0F   reserved        4 bytes  Padding
    # 0x10-0x1F   desc_key       16 bytes  Decryption key of the PGD description structure (desc member)
    # 0x20-0x2F   mac_path       16 bytes  BB MAC of the installed file relative path
    # 0x30-0x5F   desc           48 bytes  PGD description data (encrypted)
    # 0x60-0x6F   mac_table      16 bytes  BB MAC of the BB MAC hashes table.
    # 0x70-0x7F   mac_header_70  16 bytes  BB Mac Header Hash with Secure Install ID (from 0x00 to 0x70)
    # 0x80-0x8F   mac_header_80  16 bytes  BB Mac Header Hash with Static Driver Key (from 0x00 to 0x80)
    # 0x90-0x9F   data_90        16 bytes  Encrypted Data
    # 0xA0-0xAF   data_A0        16 bytes  Encrypted Data (Garbage)
    # 0xB0-0xBF   data_B0        16 bytes  Garbage / Zero Padding
    
    # 0x40 Decrypted Data:
    # NULL        | data size   | chunk size  | data address
    # 00 00 00 00 | 08 00 00 00 | 00 04 00 00 | 90 00 00 00
    
    if buf[0x0c:0x10] != b'\x80\0\0\0':
        print(f"  > BAD EDAT FILE")
        return None
    
    # Init PSP ECDSA
    ecdsa = PSPECDSA()
    edata_id = buf[0x10:].split(b'\x00', 1)[0].decode('utf-8', errors='ignore')
    print(f"  > EDAT ID: {edata_id}")
    
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
    pgd_data = bytearray(buf[0x80:])
    
    # decrypt
    try:
        binkey, install_id = decrypt_bbox_blob(pgd_data)
    except BBoxException as err:
        print(f'  > [ERROR] Code: {err.code}, MSG: {err}')
        print(f"  > BAD EDAT FILE")
        return None
    
    # Display DOC_KEY
    print(f'  > SECURE INSTALL ID: {" ".join(f"{v:02X}" for v in install_id)}')
    print(f'  > EXTRACTED DOC KEY: {" ".join(f"{v:02X}" for v in binkey)}')
    
    return binkey
