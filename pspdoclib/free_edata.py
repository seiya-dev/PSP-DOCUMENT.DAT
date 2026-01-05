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
    
    # PGD File inside DOCINFO.EDAT
    # Byte Offset Field        Length    Values (most likely)
    # 0x00-0x03   magic        04 bytes  b'\0PGD'
    # 0x04-0x07   key_index    04 bytes  Key Index
    # 0x08-0x0B   drm_type     04 bytes  DRM type/version
    # 0x0C-0x0F   padding      04 bytes  Padding
    # 0x10-0x1F                          Header Key
    # 0x20-0x2F                          Hash Key (Always same for Doc Key PGD)
    # 0x30-0x3F                          Encrypted data header start
    # 0x40-0x4F                          Encrypted data header 
    # 0x50-0x5F                          Encrypted data header end
    # 0x60-0x6F                          Data Header BB MAC Hash
    # 0x70-0x7F                          Secure Install ID BB MAC Hash
    # 0x80-0x8F                          DNAS MAC Hash
    # 0x90-0x9F                          Encrypted data
    # 0xA0-0xAF                          Garbage / Padding
    # 0xB0-0xBF                          Garbage / Padding (Not Needed)
    
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
