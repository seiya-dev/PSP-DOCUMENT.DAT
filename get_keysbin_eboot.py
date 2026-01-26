#!/usr/bin/env python
# coding: utf-8

import argparse
import os

from pspdoclib.hexdump import hexdump
from pspdoclib.bbox import get_secure_install_id

needle = bytes.fromhex('00 50 47 44 01 00 00 00 01 00 00 00 00 00 00 00')
cut_size = 0x80

def is_eboot(path):
    return os.path.basename(path).upper() == "EBOOT.PBP"

def search_secure_install_id(data):
    offset = 0
    hits = 0
    
    while True:
        pos = data.find(needle, offset)
        if pos == -1:
            break
        
        chunk = data[pos:pos + cut_size]
        
        if len(chunk) >= cut_size:
            hits += 1
            print(f'Hit #{hits} at offset 0x{pos:08X}')
            
            keys_bin = get_secure_install_id(chunk, 0)
            print(f'{hexdump(chunk)} \n\t KEY FOUND: {keys_bin.hex().upper()}')
            
            # move past this match
            offset = pos + 1
    
    if hits == 0:
        print('\\x00PGD header not found')

if __name__ == "__main__":
    print(':: GET KEYS.BIN FROM EBOOT.PBP ::')
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--eboot',  help='Path to EBOOT.PBP file')
    args = parser.parse_args()
    
    search_secure_install_id(_startdatfooter)
    
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
