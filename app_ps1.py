import os

import hashlib
from io import BytesIO
from pathlib import Path
from Crypto.Cipher import DES
from pspdoclib.hexdump import hexdump

DES_KEY = bytes.fromhex('39F7EFA16CCE5F4C')
DES_IV  = bytes.fromhex('A819C4F5E154E30B')

class attrdict(dict):
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        self.__dict__ = self

def sliceBuf(buf, offset, length):
    return buf[offset:offset + length]

def desDecrypt(input_data: bytes) -> bytes:
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)
    return cipher.decrypt(input_data)

def desEncrypt(data: bytes) -> bytes:
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)
    return cipher.encrypt(data)

def sha1hash(data: bytes) -> bytes:
    return hashlib.sha1(data).digest()[:0x10]

def b2i(input_data: bytes) -> int:
    return int.from_bytes(input_data, byteorder = 'little')

def i2b(value: int, size: int) -> bytes:
    return value.to_bytes(size, byteorder='little')

class PS1Doc(object):
    def __init__(self, file):
        self.data = attrdict()
        self.udata = attrdict()
        
        self.data.header = attrdict()
        self.data.sha1sum = attrdict()
        self.data.pages = attrdict()
        
        self.data.pages.info = list()
        self.data.pages.data = list()
        
        self.data.file_info = attrdict()
        self.data.file_info.name = file.split('/')[-1][:-4]
        
        self.f = open(file, 'rb')
        buf = self.f.read()
        self.f.close()
        
        self.f = BytesIO(buf)
        self.data.file_info.size = self.f.getbuffer().nbytes
    
    def readDocData(self):
        self.f.seek(0x0)
        header = self.f.read(0x10)
        data_buf = bytearray()
        in_buf = bytearray()
        is_enc = 0
        
        print(f'\n[:INFO:] Reading: {self.data.file_info.name}.DAT')
        
        if header == b'\0PGD\1\0\0\0\1\0\0\0\0\0\0\0':
            is_enc = 1
        
        if is_enc == 1:
            in_buf = self.f.read()
        else:
            self.f.seek(0x0)
            in_buf = self.f.read()
        self.f.close()
        
        # DOC HEADER
        header_out = sliceBuf(in_buf, 0x00, 0x60)
        header_hash = sliceBuf(in_buf, 0x70, 0x10)
        
        if is_enc == 1:
            if header_hash != sha1hash(header_out):
                print(f'  > BAD ENCRYPTED BLOB: DOC HEADER')
                return None
            
            header_out = desDecrypt(header_out)
        
        if sliceBuf(header_out, 0x0, 0x4) != b'DOC ':
            print(f'  > BAD DOC HEADER MAGIC')
            return None
        
        if sliceBuf(header_out, 0x0004, 0x0008) != b'\0\0\1\0\0\0\1\0':
            print(f'  > BAD FILE VERSION ID')
            return None
        
        if is_enc != 1 and sliceBuf(header_out, 0x0060, 0x0020) != bytes(0x0020):
            print(f'[:ERROR:] BAD DOC NULL HASH DATA')
            return None
        
        header_hash = sha1hash(desEncrypt(header_out))
        header_out += bytes(0x20)
        data_buf += header_out
        
        self.data.header.sig     = sliceBuf(data_buf, 0x0000, 0x0004).decode('utf-8')
        self.data.header.version = sliceBuf(data_buf, 0x0004, 0x0008).hex()
        self.data.header.code    = sliceBuf(data_buf, 0x000c, 0x0010).decode('utf-8').rstrip('\0')
        self.data.sha1sum.header = header_hash.hex()
        
        self.data.header.pages_total = 0
        self.data.header.pages_total_ps3 = 0
        self.data.header.page_limit  = b2i(sliceBuf(data_buf, 0x001c, 0x0004))
        self.data.header.page_limit  = (10 ** (2 + self.data.header.page_limit)) - 1
        
        if self.data.header.page_limit not in (99, 999):
            print(f'  > BAD DOC PAGE LIMIT')
            return None
        
        info_block_size = 0x1f3e8 if self.data.header.page_limit == 999 else 0x31e8
        info_block = sliceBuf(in_buf, 0x80, info_block_size)
        info_hash  = sliceBuf(in_buf, 0x80 + info_block_size + 0x10, 0x10)
        
        if is_enc == 1:
            if sha1hash(info_block) != info_hash:
                print(f'  > BAD ENCRYPTED BLOB: INFO BLOCK')
                return None
            
            self.data.sha1sum.info_block = info_hash.hex()
            info_block = desDecrypt(info_block)
        
        if sliceBuf(info_block, 0x0, 0x4) != bytes.fromhex('FFFFFFFF'):
            print('  > MARKER MISMATCH')
            return None
        
        data_buf += sliceBuf(info_block, 0x0000, 0x0008)
        self.data.header.pages_total = b2i(sliceBuf(data_buf, 0x0084, 0x0004))
        info_block = info_block[0x0008:]
        
        if self.data.header.pages_total > self.data.header.page_limit:
            print('  > BAD DOC PAGE COUNT')
            return None
        
        for i in range(self.data.header.pages_total):
            entry_data = sliceBuf(info_block, i * 0x80, 0x80)
            data_buf += entry_data
            
            page_info = attrdict()
            page_info.offset     = b2i(sliceBuf(entry_data, 0x0000, 0x0008))
            page_info.size       = b2i(sliceBuf(entry_data, 0x000c, 0x0004))
            page_info.offset_ps3 = b2i(sliceBuf(entry_data, 0x0010, 0x0008))
            page_info.size_ps3   = b2i(sliceBuf(entry_data, 0x001c, 0x0004))
            
            if page_info.offset > 0:
                self.data.pages.info.append(page_info)
        
        if len(data_buf) > self.data.pages.info[0].offset:
            print(f'  > BAD DOC OFFSET DATA')
            return None
        
        stuffing_len = self.data.pages.info[0].offset - len(data_buf)
        data_buf += bytes(stuffing_len)
        
        if len(data_buf) == info_block_size + 0x88 + 0x28:
            offset_block_len = 0x80 * self.data.header.page_limit
            offset_block_end = 0x88 + offset_block_len
            data_buf[offset_block_end:offset_block_end + 0x04] = sliceBuf(info_block, offset_block_len, 0x0004)
            self.data.header.pages_total_ps3 = b2i(sliceBuf(data_buf, offset_block_end, 0x0004))
        
        if self.data.header.pages_total_ps3 == 0:
            print(f'  > WARN: BAD DOCUMENT.DAT FORMAT!')
        
        self.data.header.pop('sig')
        self.data.header.pop('version')
        print('  > HEADER: ', self.data.header)
        # print('  > SHA1SUM:', self.data.sha1sum)
        
        for page_index, info in enumerate(self.data.pages.info):
            page_buf = bytearray(sliceBuf(in_buf, info.offset, info.size))
            
            if is_enc == 1:
                page_buf = bytearray(sliceBuf(in_buf, info.offset-0x10, info.size))
                page_hash = page_buf[-0x20:]
                page_buf = page_buf[:-0x20]
                
                if sha1hash(page_buf) != page_hash[-0x10:]:
                    print(f'  > PAGE {page_index+1:03d} SHA1 HASH MISMATCH')
                    data_buf += page_buf + page_hash
                    continue
                
                page_buf += bytes(0x20)
                page_info_head = desDecrypt(sliceBuf(page_buf, 0x00, 0x20))
                page_buf[0x00:0x20] = bytes(0x20)
                
                page_size  = b2i(sliceBuf(page_info_head, 0x00, 0x04))
                enc_chunks = b2i(sliceBuf(page_info_head, 0x08, 0x04))
                payload_offset = 0x20 + enc_chunks * 0x08
                
                if page_size != info.size:
                    print(f'  > PAGE {page_index+1:03d} SIZE MISMATCH!')
                    continue
                
                subheader_out = desDecrypt(sliceBuf(page_buf, 0x20, enc_chunks * 0x08))
                page_buf = page_buf[payload_offset:]
                
                for j in range(enc_chunks):
                    enc_chunk_offset = b2i(sliceBuf(subheader_out, j * 0x08 + 0x00, 0x04))
                    enc_chunk_size   = b2i(sliceBuf(subheader_out, j * 0x08 + 0x04, 0x04))
                    
                    dec_chunk = desDecrypt(sliceBuf(page_buf, enc_chunk_offset, enc_chunk_size))
                    page_buf[enc_chunk_offset:enc_chunk_offset + enc_chunk_size] = dec_chunk
                
                page_buf += bytes(payload_offset)
                
            # data_buf += page_buf
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
        
        # if is_enc == 1 and not os.path.isfile(f'./dat_out/{self.data.file_info.name}_DEC.DAT'):
        #     Path(f'./dat_out').mkdir(parents=True, exist_ok=True)
        #     ofile = open(f'./dat_out/{self.data.file_info.name}_DEC.DAT', 'wb')
        #     ofile.write(data_buf)
        #     ofile.close()
        
        return self.data

###################

def readDocs():
    docs = [p.as_posix() for p in Path('./dat_ps1docs').glob('*.dat')]
    
    for di in range(len(docs)):
        PS1Doc(f'{docs[di]}').readDocData()

readDocs()
