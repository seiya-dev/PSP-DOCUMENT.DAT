#!/usr/bin/env python
# coding: utf-8

import os
import struct
import argparse

import hashlib
from pathlib import Path
from Crypto.Cipher import DES

from pspdoclib.bbox import (
    boxbb_mac_gen_enc
)

###################

DES_KEY = bytes.fromhex('39F7EFA16CCE5F4C')
DES_IV  = bytes.fromhex('A819C4F5E154E30B')
INS_ID  = bytes.fromhex('2E4117A532E6C473717B0F7A6EC0AAA5')

# NOTE 1: INS_ID (Secure Install ID) can be any for custom PS1 PBP.
# For official PS1 PBPs Secure Install ID should match between official PS1 PBP and DOC file
# (if not - you will get message about broken data)

# NOTE 2: PSP with CFW will "crash" if Secure Install ID match between official PS1 PBP and DOC file

###################

def desEncrypt(data: bytes) -> bytes:
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)
    return cipher.encrypt(data)

def sha1hash(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()[:0x10]

def gen_pad(buf: bytes, block_size: int = 8) -> bytes:
    return buf + b'\x00' * (-len(buf) % block_size)

###################

def create_header(gameid):
    buf = bytearray(0x60)
    struct.pack_into('<I', buf, 0x00, 0x20434F44)
    struct.pack_into('<I', buf, 0x04, 0x10000)
    struct.pack_into('<I', buf, 0x08, 0x10000)
    buf[12:21] = bytes(gameid, encoding='utf-8')
    struct.pack_into('<I', buf, 0x1c, 0)
    struct.pack_into('<I', buf, 0x1c, 0 if len(pages) < 100 else 1)
    return buf

def encrypt_document(gameid, pages):
    # PGD header
    pgd_buf = b'\0PGD\1\0\0\0\1\0\0\0\0\0\0\0'
    
    # DOC header
    doc_hdr = desEncrypt(create_header(gameid))
    pgd_buf += doc_hdr + boxbb_mac_gen_enc(doc_hdr, INS_ID) + sha1hash(doc_hdr)
    
    # Info Block
    # file data starts at 0x32b8 / 0x1f4b8
    page_count = len(pages) if len(pages) < 1000 else 999
    
    info_block_size = 0x1f3e8 if page_count >= 100 else 0x31e8
    info_buffer = bytearray(info_block_size)
    
    ps3_page_count_offset = 0x3188 if page_count < 100 else 0x1f388
    page_offset = 0x90 + info_block_size + 0x20
    
    struct.pack_into('<I', info_buffer, 0x00, 0xffffffff)
    struct.pack_into('<I', info_buffer, 0x04, page_count)
    struct.pack_into('<I', info_buffer, ps3_page_count_offset, page_count)
    
    for i, p in enumerate(pages):
        page_len = 0x20 + len(p) + 0x20
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x00, page_offset)
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x0c, page_len)
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x10, page_offset)
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x1c, page_len)
        page_offset += page_len
    
    info_buffer = desEncrypt(info_buffer)
    pgd_buf += info_buffer + boxbb_mac_gen_enc(info_buffer, INS_ID) + sha1hash(info_buffer)
    
    # File data
    for i, p in enumerate(pages):
        print(f'  > ENCRYPTING AND WRITING PAGE {i+1:03d}')
        page_len = 0x20 + len(p) + 0x20
        page_info_head = bytearray(0x20)
        struct.pack_into('<I', page_info_head, 0, page_len)
        
        p = desEncrypt(page_info_head) + p
        pgd_buf += p + boxbb_mac_gen_enc(p, INS_ID) + sha1hash(p)
    
    return pgd_buf

if __name__ == "__main__":
    print(':: PSP DOCUMENT.DAT Creator ::')
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--document', help='Name of DOCUMENT.DAT')
    parser.add_argument('--output',   help='Output file')
    parser.add_argument('--directory',help='Directory containing the source PNGs')
    parser.add_argument('--gameid',   help='GameID')
    args = parser.parse_args()

    if not args.directory:
        print('  > MUST SPECIFY --directory')
        os._exit(1)
    if not args.document:
        print('  > MUST SPECIFY --document')
        os._exit(1)
    
    print('  > ENCRYPT: ', args.document)
    
    pages = []
    for i, png in enumerate(sorted(Path(args.directory).glob('*.png'))):
        if i+1 < 1000:
            buffer = Path(png).read_bytes()
            pages.append(gen_pad(buffer))
    
    if len(pages) > 0:
        pgd = encrypt_document(args.gameid if args.gameid else 'UNKN00000', pages)
        Path(args.document).write_bytes(pgd)
