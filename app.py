import os

import hmac
import hashlib
from io import BytesIO
from pathlib import Path

from Crypto.Cipher import DES
from elib import free_edata, hexdump

###################

HMAC_KEY_PSP = bytes([0x4D, 0x1B, 0x6B, 0x12, 0x69, 0xDD, 0xD2, 0x2F, 0xAA, 0xE1, 0xF5, 0x42, 0x07, 0xE7, 0x98, 0xB5])
HMAC_KEY_PS3 = bytes([0xEF, 0x69, 0x0E, 0xC0, 0xE0, 0xBF, 0xA4, 0x1F, 0x08, 0x45, 0x5B, 0xD0, 0x38, 0xEB, 0x87, 0x62])
DES_KEY = bytes([0xDA, 0x39, 0x23, 0xEF, 0x9C, 0x61, 0xB9, 0x30])
DES_IV  = bytes([0x2D, 0xEE, 0x89, 0x50, 0x96, 0x91, 0x12, 0xD9])

###################

class attrdict(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.__dict__ = self

###################

def sliceBuf(buf, offset, length):
    return buf[offset:offset + length]

###################

def desDecrypt(key, input_data):
    cipher = DES.new(key, DES.MODE_CBC, DES_IV)
    return cipher.decrypt(input_data)

def desChangeKey(doc_key: bytes) -> bytes:
    doc_xor = bytes([0xF9, 0x32, 0xFF, 0x26, 0x47, 0x4A, 0x8D, 0xC0])
    des_key = bytes(d ^ x for d, x in zip(doc_key, doc_xor))
    return des_key

def sha1hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha1).digest()[:0x10]

def b2i(input_data: bytes) -> int:
    return int.from_bytes(input_data, byteorder = 'little')

def i2b(value: int, size: int) -> bytes:
    return value.to_bytes(size, byteorder='little')

###################

class PSPDoc(object):
    def __init__(self, file):
        self.data = attrdict()
        self.udata = attrdict()
        
        self.data.header = attrdict()
        self.data.pages = attrdict()
        
        self.data.pages.info = list()
        self.data.pages.data = list()
        
        self.data.file_info = attrdict()
        self.data.file_info.prefix = file[:-0x0d]
        self.data.file_info.name = file[:-0x0d].split('/')[-1]
        
        self.f_dat = bytearray()
        self.f_edat = bytearray()
        
        edat = f'{file[:-0x0d]}_DOCINFO.EDAT'
        dat = f'{file[:-0x0d]}_DOCUMENT.DAT'
        
        if Path(edat).is_file():
            self.f_edat = open(edat, 'rb')
            self_b_edat = self.f_edat.read()
            self.f_edat.close()
            self.f_edat = bytearray(self_b_edat)
        
        if Path(dat).is_file():
            self.f_dat = open(file, 'rb')
            self_b_dat = self.f_dat.read()
            self.f_dat.close()
            self.f_dat = bytearray(self_b_dat)
    
    def readDocData(self):
        print(f'\n[:INFO:] Reading: {self.data.file_info.prefix}_DOCUMENT.DAT')
        dec_key = DES_KEY
        
        if len(self.f_edat) > 0:
            print(f'[:INFO:] Reading: {self.data.file_info.prefix}_DOCINFO.EDAT')
            if len(self.f_edat) != 0x140:
                print('[:ERROR:] BAD DOCINFO.EDAT SIZE!')
                return None
            
            free_edata(self.f_edat)
            
            print(' > NOT SUPPORTED YET, SKIPPING...')
            return None
        
        header = self.f_dat[0x00:0x10]
        if header != b'\0PGD\1\0\0\0\1\0\0\0\0\0\0\0':
            print(f'[:ERROR:] ONLY ENCRYPTED DOCUMENT.DAT SUPPORTED.')
            return None
        
        header_padding = self.f_dat[0x70:0x80]
        if header_padding != bytes(0x10):
            print(f'[:ERROR:] PADDING AT 0x00000070 IS MISSING.')
            return None
        
        check_header_psp = sha1hmac(HMAC_KEY_PSP, self.f_dat[0x10:0x70])
        check_header_ps3 = sha1hmac(HMAC_KEY_PS3, self.f_dat[0x10:0x70])
        
        if check_header_psp != self.f_dat[0x80:0x90] or check_header_ps3 != self.f_dat[0x90:0xa0]:
            print(f'[:ERROR:] SHA1-HMAC HEADER MISMATCH.')
            return None
        
        header_out = desDecrypt(dec_key, self.f_dat[0x10:0x70])
        
        if sliceBuf(header_out, 0x0, 0x4) != b'DOC ':
            print(f'[:ERROR:] NOT PROPER DOC HEADER')
            return None
        
        # if sliceBuf(header_out, 0x4, 0x8) != b'\0\0\1\0\0\0\1\0':
        #     print(f'[:ERROR:] BAD FILE VERSION ID')
        #     return None
        
        self.data.header.sig     = sliceBuf(header_out, 0x0000, 0x0004).decode('utf-8')
        self.data.header.version = sliceBuf(header_out, 0x0004, 0x0008).hex()
        self.data.header.code    = sliceBuf(header_out, 0x000c, 0x0010).decode('utf-8').rstrip('\0')
        
        self.data.header.pages_total = 0
        self.data.header.pages_total_ps3 = 0
        
        self.data.header.page_limit  = b2i(sliceBuf(header_out, 0x001c, 0x0004))
        self.data.header.page_limit  = (10 ** (2 + self.data.header.page_limit)) - 1
        
        metadata_size = 0x32b8 - 0x00a0 - 0x0030
        if self.data.header.page_limit > 99:
            metadata_size = 0x1f4b8 - 0x00a0 - 0x0030
        
        check_metadata_psp = sha1hmac(HMAC_KEY_PSP, self.f_dat[0x00a0:0x00a0+metadata_size])
        check_metadata_ps3 = sha1hmac(HMAC_KEY_PS3, self.f_dat[0x00a0:0x00a0+metadata_size])
        sum_metadata_offset = 0x00a0 + metadata_size
        
        if sliceBuf(self.f_dat, sum_metadata_offset, 0x10) != bytes(0x10):
            print(f'[:ERROR:] PADDING AT 0x{sum_metadata_offset:08x} IS MISSING.')
            return None
        
        if (
            check_metadata_psp != sliceBuf(self.f_dat, sum_metadata_offset + 0x10, 0x10) 
            or check_metadata_ps3 != sliceBuf(self.f_dat, sum_metadata_offset + 0x20, 0x10)
        ):
            print(f'[:ERROR:] SHA1-HMAC METADATA MISMATCH.')
            return None
        
        pages_metadata = desDecrypt(dec_key, self.f_dat[0x00a0:0x00a0+metadata_size])
        
        if sliceBuf(pages_metadata, 0x0, 0x4) != bytes.fromhex('FFFFFFFF'):
            print('[:ERROR:] MARKER MISMATCH')
            return None
        
        ps3_pages_count_offset = 0x3188
        if self.data.header.page_limit > 99:
            ps3_pages_count_offset = 0x1f388
        
        self.data.header.pages_total     = b2i(pages_metadata[0x04:0x08])
        self.data.header.pages_total_ps3 = b2i(sliceBuf(pages_metadata, ps3_pages_count_offset, 0x04))
        
        for i in range(self.data.header.pages_total):
            entry_data = sliceBuf(pages_metadata, 0x08 + i * 0x80, 0x80)
            
            page_info = attrdict()
            page_info.offset     = b2i(sliceBuf(entry_data, 0x0000, 0x0008))
            page_info.size       = b2i(sliceBuf(entry_data, 0x000c, 0x0004))
            page_info.offset_ps3 = b2i(sliceBuf(entry_data, 0x0010, 0x0008))
            page_info.size_ps3   = b2i(sliceBuf(entry_data, 0x001c, 0x0004))
            
            if page_info.offset != page_info.offset_ps3 or page_info.size != page_info.size_ps3:
                print(f'[:ERROR:] PAGE {i+1:03d} DATA MISMATCH!')
                return None
            
            if page_info.offset > 0:
                self.data.pages.info.append(page_info)
        
        print(self.data.header)
        #print(self.data.pages.info)
        
        for page_index, info in enumerate(self.data.pages.info):
            page_buf = bytearray(sliceBuf(self.f_dat, info.offset, info.size))
            page_hash = page_buf[-0x30:]
            page_buf = page_buf[:-0x30]
            
            if page_hash[0x00:0x10] != bytes(0x10):
                print(f'[:ERROR:] PAGE {page_index+1:03d} PADDING IS MISSING.')
                return None
            
            check_page_psp = sha1hmac(HMAC_KEY_PSP, page_buf)
            check_page_ps3 = sha1hmac(HMAC_KEY_PS3, page_buf)
            
            if check_page_psp != page_hash[0x10:0x20] or check_page_ps3 != page_hash[0x20:0x30]:
                print(f'[:ERROR:] PAGE {page_index+1:03d} HASH MISMATCH')
            
            page_info_head = desDecrypt(dec_key, sliceBuf(page_buf, 0x00, 0x20))
            page_size  = b2i(sliceBuf(page_info_head, 0x00, 0x04))
            enc_chunks = b2i(sliceBuf(page_info_head, 0x08, 0x04))
            payload_offset = 0x20 + enc_chunks * 0x08
            
            if page_size != info.size:
                print(f'[:ERROR:] PAGE {page_index+1:03d} SIZE MISMATCH!')
                return None
            
            subheader_out = desDecrypt(dec_key, sliceBuf(page_buf, 0x20, enc_chunks * 0x08))
            page_buf = page_buf[payload_offset:]
            
            for j in range(enc_chunks):
                enc_chunk_offset = b2i(sliceBuf(subheader_out, j * 0x08 + 0x00, 0x04))
                enc_chunk_size   = b2i(sliceBuf(subheader_out, j * 0x08 + 0x04, 0x04))
                
                dec_chunk = desDecrypt(dec_key, sliceBuf(page_buf, enc_chunk_offset, enc_chunk_size))
                page_buf[enc_chunk_offset:enc_chunk_offset + enc_chunk_size] = dec_chunk
            
            self.data.pages.data.append(page_buf)
            if not os.path.isfile(f'./png_out/{self.data.file_info.name}/{self.data.header.code}_DOC_{page_index+1:03d}.png'):
                needle_buf = b'IEND\xAE\x42\x60\x82'
                needle_idx = page_buf.rfind(needle_buf)
                png_min_size = 0x43
                
                if needle_idx == -1:
                    print(f'[:WARN:] PAGE {page_index+1:03d}: PNG trailer not found')
                    continue
                
                png_size = needle_idx + len(needle_buf)
                if png_size < png_min_size:
                    print(f'[:WARN:] PAGE {page_index+1:03d}: PNG too small or trailer found too early (size={png_size})')
                    continue
                    
                Path(f'./png_out/{self.data.file_info.name}').mkdir(parents=True, exist_ok=True)
                ofile = open(f'./png_out/{self.data.file_info.name}/{self.data.header.code}_DOC_{page_index+1:03d}.png', 'wb')
                ofile.write(page_buf[:png_size])
                ofile.close()

###################

def readDocs():
    docs = [p.as_posix() for p in Path('./dat_docs').glob('*.dat')]
    
    for di in range(len(docs)):
        PSPDoc(f'{docs[di]}').readDocData()

readDocs()
