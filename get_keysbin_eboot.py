#!/usr/bin/env python
# coding: utf-8

from pathlib import Path
import argparse
import struct
import os

from pspdoclib.hexdump import hexdump
from pspdoclib.bbox import get_secure_install_id

needle = bytes.fromhex('00 50 47 44 01 00 00 00 01 00 00 00 00 00 00 00')
cut_size = 0x80

def is_eboot(path):
    return os.path.basename(path).upper() == "EBOOT.PBP"

def save_keysbin(path: str, key_bytes: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(key_bytes)

def search_secure_install_id(data):
    offset = 0
    hits = 0
    
    offsets_hex = [
        ('PARAM.SFO', '0x08'),
        ('ICON0.PNG', '0x0C'),
        ('ICON1.PMF', '0x10'),
        ('PIC0.PNG',  '0x14'),
        ('PIC1.PNG',  '0x18'),
        ('SND0.AT3',  '0x1C'),
        ('DATA.PSP',  '0x20'),
        ('DATA.PSAR', '0x24'),
    ]
    
    entries = []
    for name, header_hex in offsets_hex:
        header_off = int(header_hex, 16)
        file_off = struct.unpack_from("<I", data, header_off)[0]
        entries.append((name, file_off))
    
    for i, (name, off) in enumerate(entries):
        if i + 1 < len(entries) and off == entries[i + 1][1]:
            continue
        print(f"{name:9} offset = 0x{off:08X} ({off})")
    
    while True:
        pos = data.find(needle, offset)
        if pos == -1:
            break
        
        chunk = data[pos:pos + cut_size]
        
        if len(chunk) >= cut_size:
            hits += 1
            print(f'  > Hit #{hits} at offset 0x{pos:08X}')
            
            keys_bin = get_secure_install_id(chunk, 0)
            print(f'  KEY FOUND: {keys_bin.hex().upper()}')
            
            if hits == 1:
                Path(f'./out_key').mkdir(parents=True, exist_ok=True)
                save_keysbin('./out_key/KEYS.BIN', keys_bin)
                print('  SAVED to out_key folder!')
            
            # move past this match
            offset = pos + 1
    
    if hits == 0:
        print('\\x00PGD header not found')

if __name__ == "__main__":
    print(':: GET KEYS.BIN FROM EBOOT.PBP ::')
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--eboot',  help='Path to EBOOT.PBP file')
    args = parser.parse_args()
    
    if not args.eboot:
        print('  > MUST SPECIFY --eboot')
        os._exit(1)
    
    if not is_eboot(args.eboot):
        print('  > MUST SPECIFY EBOOT.PBP')
        os._exit(1)
    
    with open(args.eboot, "rb") as f:
        data = f.read()
        
        print('\nFile:', args.eboot)
        search_secure_install_id(data)
