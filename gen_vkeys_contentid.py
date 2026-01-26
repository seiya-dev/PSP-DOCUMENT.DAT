#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
import hashlib
import re
import sys
import struct
import io
import zlib
import base64

from pathlib import Path

from Crypto.Cipher import AES # pip install pycryptodome
from pspdoclib.hexdump import hexdump

POPS_VER_KEY = bytes.fromhex('2E4117A532E6C473717B0F7A6EC0AAA5')
CID_PATTERN = re.compile(r'^[A-Z]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}$')

class KeyVault:
    DRM_ENC_KEY = {
        0x00: bytes([0xF0, 0x79, 0xD5, 0x19, 0x8F, 0x23, 0xEF, 0xCE, 0xB5, 0x4B, 0x9E, 0xCD, 0xCD, 0xFD, 0xD3, 0xD7]),
        0x01: bytes([0x07, 0x3D, 0x9E, 0x9D, 0xA8, 0xFD, 0x3B, 0x2F, 0x63, 0x18, 0x93, 0x2E, 0xF8, 0x57, 0xA6, 0x64]),
        0x02: bytes([0x37, 0x49, 0xB7, 0x01, 0xCA, 0xE2, 0xE0, 0xC5, 0x44, 0x2E, 0x06, 0xB6, 0x1E, 0xFF, 0x84, 0xF2]),
        0x03: bytes([0x9D, 0x31, 0xB8, 0x5A, 0xC8, 0xFA, 0x16, 0x80, 0x73, 0x60, 0x18, 0x82, 0x18, 0x77, 0x91, 0x9D]),
    }
    
    @staticmethod
    def drm_key(key_type: int) -> bytes:
        return KeyVault.DRM_ENC_KEY[key_type]

class SceNpDrm:
    OK = 0
    ERR_INVALID_TYPE = 0x80550901
    
    @staticmethod
    def transform_version_key(version_key: bytearray, src_key_type: int, dst_key_type: int) -> int:
        ret = SceNpDrm.reverse_gen_version_key(version_key, src_key_type)
        return ret if ret < 0 else SceNpDrm.gen_version_key(version_key, dst_key_type)
    
    @staticmethod
    def reverse_gen_version_key(version_key: bytearray, key_type: int) -> int:
        key_type &= 0xFFFFFF
        if key_type == 0:
            return SceNpDrm.OK
        if key_type >= 4:
            return SceNpDrm.ERR_INVALID_TYPE
        
        cipher = AES.new(KeyVault.drm_key(key_type), AES.MODE_ECB)
        version_key[:16] = cipher.decrypt(version_key[:16])
        return SceNpDrm.OK
    
    @staticmethod
    def gen_version_key(version_key: bytearray, key_type: int) -> int:
        key_type &= 0xFFFFFF
        if key_type == 0:
            return SceNpDrm.OK
        if key_type >= 4:
            return SceNpDrm.ERR_INVALID_TYPE
        
        cipher = AES.new(KeyVault.drm_key(key_type), AES.MODE_ECB)
        version_key[:16] = cipher.encrypt(version_key[:16])
        return SceNpDrm.OK

class NoPspEmuDrmMethod:
    @staticmethod
    def get_version_key(content_id: str, key_index: int):
        vk = bytearray(hashlib.md5(content_id.encode('utf-8')).digest())
        SceNpDrm.transform_version_key(vk, 0, key_index)
        return { 'content_id': content_id, 'key_index': key_index, 'version_key': bytes(vk).hex().upper() }

def create_no_psp_emu_drm_rif(content_id: str) -> bytes:
    rif = io.BytesIO()
    
    # 0x00-0x07 start of rif (uint64, little-endian)
    # Version     : 0x00 0x00
    # Version Flag: 0x00 0x01
    # DRM Type    : 0x00 0x00
    # License Flag: 0x00 0x02
    rif.write(struct.pack('<Q', 0x00))
    
    # 0x08-0x0F fake account ID (uint64, little-endian)
    # EF CD AB 89 67 45 23 01
    rif.write(struct.pack('<Q', 0x0123456789ABCDEF))
    
    # 0x10-0x3F content ID (C-string padded to 0x30 bytes)
    # UP9000-NPUJ00000_00-0000000000000001
    content_bytes = content_id.encode('ascii')[0x00:0x30]
    
    rif.write(content_bytes)
    rif.write(b'\x00' * (0x30 - len(content_bytes)))
    
    # 0x40-0x5F
    # Encrypted Account KeyRing Index
    # Encrypted RIF Key
    rif.write(b'\x00' * 0x20)
    
    # 0x60-0x6F
    # License Start Time
    # License Expiration Time
    rif.write(b'\x00' * 0x10)
    
    # 0x70-0x97
    # Fake ECDSA Signature
    rif.write(b'\xFF' * 0x28)
    
    return rif.getvalue()

def rif_to_zrif(rif: bytes) -> str:
    return base64.b64encode(zlib.compress(rif, 9)).decode('ascii')

def decode_zrif_to_rif(zrif: str) -> bytes:
    return zlib.decompress(base64.b64decode(zrif))

def save_rif(path: str, rif_bytes: bytes) -> None:
    with open(path, "wb") as f:
        f.write(rif_bytes)

def parse_args() -> argparse.Namespace:
    print(':: NP DRM VersionKey Generator ::')
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--cid",
        default="UP9000-NPUJ00000_00-0000000000000001",
        help='Content ID (must match regex: "^[A-Z]{2}[0-9]{4}-[A-Z]{4}[0-9]{5}_[0-9]{2}-[A-Z0-9]{16}$")',
    )
    return parser.parse_args()

def main() -> None:
    args = parse_args()
    cid = args.cid
    
    if not CID_PATTERN.fullmatch(cid):
        print(f'Invalid content ID format:\n  {cid}', file=sys.stderr)
        sys.exit(1)
    
    keys = NoPspEmuDrmMethod.get_version_key(cid, 1)['version_key']
    
    rif_bin = create_no_psp_emu_drm_rif(cid)
    zrif_b64 = rif_to_zrif(rif_bin)
    
    print('CONTENT ID:     :', cid)
    print('PS1 EBOOT DEFKEY:', POPS_VER_KEY.hex().upper())
    print('PS1 EBOOT CIDKEY:', keys)
    print('zRIF STRING     :', zrif_b64)
    
    Path(f'./out_rif').mkdir(parents=True, exist_ok=True)
    save_rif(f'./out_rif/{cid}.rif', rif_bin)
    
    print('\nRIF Data:')
    print(hexdump(rif_bin),'\n')

if __name__ == '__main__':
    main()
