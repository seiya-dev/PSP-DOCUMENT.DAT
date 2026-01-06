#!/usr/bin/env python
# coding: utf-8

import os
import struct
import argparse

import hmac
import hashlib
from pathlib import Path
from Crypto.Cipher import DES

###################

HMAC_KEY_PSP = bytes([0x4D, 0x1B, 0x6B, 0x12, 0x69, 0xDD, 0xD2, 0x2F, 0xAA, 0xE1, 0xF5, 0x42, 0x07, 0xE7, 0x98, 0xB5])
HMAC_KEY_PS3 = bytes([0xEF, 0x69, 0x0E, 0xC0, 0xE0, 0xBF, 0xA4, 0x1F, 0x08, 0x45, 0x5B, 0xD0, 0x38, 0xEB, 0x87, 0x62])
DES_KEY = bytes([0xDA, 0x39, 0x23, 0xEF, 0x9C, 0x61, 0xB9, 0x30])
DES_IV  = bytes([0x2D, 0xEE, 0x89, 0x50, 0x96, 0x91, 0x12, 0xD9])

###################

def desEncrypt(data: bytes) -> bytes:
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)
    return cipher.encrypt(data)

def sha1hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()[:0x10]

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
    pgd_buf += doc_hdr + bytes(0x10) + sha1hmac(HMAC_KEY_PSP, doc_hdr) + sha1hmac(HMAC_KEY_PS3, doc_hdr)
    
    # Info Block
    # file data starts at 0x32b8 / 0x1f4b8
    page_count = len(pages) if len(pages) < 1000 else 999
    
    info_block_size = 0x1f3e8 if page_count >= 100 else 0x31e8
    info_buffer = bytearray(info_block_size)
    
    ps3_page_count_offset = 0x3188 if page_count < 100 else 0x1f388
    page_offset = 0xA0 + info_block_size + 0x30
    
    struct.pack_into('<I', info_buffer, 0x00, 0xffffffff)
    struct.pack_into('<I', info_buffer, 0x04, page_count)
    struct.pack_into('<I', info_buffer, ps3_page_count_offset, page_count)
    
    for i, p in enumerate(pages):
        page_len = 0x20 + len(p) + 0x30
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x00, page_offset)
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x0c, page_len)
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x10, page_offset)
        struct.pack_into('<I', info_buffer, 0x08 + i * 0x80 + 0x1c, page_len)
        page_offset += page_len
    
    info_buffer = desEncrypt(info_buffer)
    pgd_buf += info_buffer + bytes(0x10) + sha1hmac(HMAC_KEY_PSP, info_buffer) + sha1hmac(HMAC_KEY_PS3, info_buffer)
    
    # File data
    for i, p in enumerate(pages):
        print(f'  > ENCRYPTING AND WRITING PAGE {i+1:03d}')
        page_len = 0x20 + len(p) + 0x30
        page_info_head = bytearray(0x20)
        struct.pack_into('<I', page_info_head, 0, page_len)
        
        p = desEncrypt(page_info_head) + p
        pgd_buf += p + bytes(0x10) + sha1hmac(HMAC_KEY_PSP, p) + sha1hmac(HMAC_KEY_PS3, p)
    
    return pgd_buf

if __name__ == "__main__":
    print(':: PSP DOCUMENT.DAT Creator ::')
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--document', help='Name of DOCUMENT.DAT')
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
