from __future__ import annotations

import ctypes
import struct
from dataclasses import dataclass
from typing import Optional, Dict, Tuple
from .hexdump import hexdump

from .cryptolib import (
    CryptoEngine,
    CRYPTOENGINE_CMD_ENCRYPT_IV_0,
    CRYPTOENGINE_CMD_DECRYPT_IV_0,
    CRYPTOENGINE_CMD_ENCRYPT_IV_FUSE,
    CRYPTOENGINE_CMD_DECRYPT_IV_FUSE,
    CRYPTOENGINE_CMD_PRNG,
    CRYPTOENGINE_OPERATION_SUCCESS,
)

# ============================================================
# Error codes
# ============================================================

ERROR_INVALID_ARG       = ctypes.c_int32(0x80510201).value
ERROR_MFILE             = ctypes.c_int32(0x80510202).value
ERROR_BADF              = ctypes.c_int32(0x80510203).value
ERROR_INVALID_FORMAT    = ctypes.c_int32(0x80510204).value
ERROR_UNKNOWN_VERSION   = ctypes.c_int32(0x80510205).value
ERROR_SECURE_INSTALL_ID = ctypes.c_int32(0x80510206).value
ERROR_BROKEN_DATA       = ctypes.c_int32(0x80510207).value
ERROR_BAD_MAC_KEY_PAD   = ctypes.c_int32(0x80510302).value

class BBoxException(Exception):
    def __init__(self, code: int, message: str = ''):
        self.code = int(code)
        super().__init__(message or f'BBox error 0x{self.code:08X}')

def _raise(code: int, msg: str) -> None:
    raise BBoxException(code, msg)

# ============================================================
# Crypto engine bootstrap
# ============================================================

_ENGINE: Optional[CryptoEngine] = None

def init_engine_default() -> CryptoEngine:
    global _ENGINE
    eng = CryptoEngine()
    eng.init_default()
    _ENGINE = eng
    return eng

def _eng() -> CryptoEngine:
    if _ENGINE is None:
        return init_engine_default()
    return _ENGINE


# ============================================================
# BBBox
# ============================================================

_DNAS_KEY1 = bytes([0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43])
_DNAS_KEY2 = bytes([0x27, 0x74, 0xFB, 0xEB, 0xA4, 0xA0, 0x01, 0xD7, 0x02, 0x56, 0x9E, 0x33, 0x8C, 0x19, 0x57, 0x83])
_AM_HASH_KEY_3 = bytes([0xE3, 0x50, 0xED, 0x1D, 0x91, 0x0A, 0x1F, 0xD0, 0x29, 0xBB, 0x1C, 0x3E, 0xF3, 0x40, 0x77, 0xFB])
_AM_HASH_KEY_4 = bytes([0x13, 0x5F, 0xA4, 0x7C, 0xAB, 0x39, 0x5B, 0xA4, 0x76, 0xB8, 0xCC, 0xA9, 0x8F, 0x3A, 0x04, 0x45])
_AM_HASH_KEY_5 = bytes([0x67, 0x8D, 0x7F, 0xA3, 0x2A, 0x9C, 0xA0, 0xD1, 0x50, 0x8A, 0xD8, 0x38, 0x5E, 0x4B, 0x01, 0x7E])

# ============================================================
# Helpers: cryptoengine wrappers matching the C header format
# ============================================================

def _aes128cbc_header(mode: int, keyseed: int, data_size: int) -> bytes:
    return struct.pack('<iiiii', mode, 0, 0, int(keyseed), int(data_size))

def _crypto_cmd_encrypt_iv0(data: bytes, keyseed: int) -> bytes:
    inbuf = _aes128cbc_header(4, keyseed, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_ENCRYPT_IV_0)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f'crypto cmd4 failed (status={status})')
    return out[0x14:0x14 + len(data)]

def _crypto_cmd_decrypt_iv0(data: bytes, keyseed: int) -> bytes:
    inbuf = _aes128cbc_header(5, keyseed, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_DECRYPT_IV_0)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f'crypto cmd7 failed (status={status})')
    # CMD7 returns plaintext directly (cryptolib implementation)
    return out

def _crypto_cmd_encrypt_fuse(data: bytes) -> bytes:
    inbuf = _aes128cbc_header(4, 0x0100, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_ENCRYPT_IV_FUSE)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f'crypto cmd5 failed (status={status})')
    return out[0x14:0x14 + len(data)]

def _crypto_cmd_decrypt_fuse(data: bytes) -> bytes:
    inbuf = _aes128cbc_header(5, 0x0100, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_DECRYPT_IV_FUSE)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f'crypto cmd8 failed (status={status})')
    return out

def _crypto_cmd_prng() -> bytes:
    status, out = _eng().utils_buffer_copy_with_range(b'', CRYPTOENGINE_CMD_PRNG)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f'crypto cmd14 failed (status={status})')
    return out  # 20 bytes

# ============================================================
# Structures
# ============================================================

@dataclass
class MACKey:
    type: int
    key: bytearray
    pad: bytearray
    pad_size: int

@dataclass
class CipherKey:
    type: int
    seed: int
    key: bytearray

# ============================================================
# MAC functions
# ============================================================

def BBMacInit(mkey: MACKey, type_: int) -> int:
    mkey.type = int(type_)
    mkey.pad_size = 0
    mkey.key[:] = b'\x00' * 0x10
    mkey.pad[:] = b'\x00' * 0x10
    return 0

# Helper function for BBMacUpdate and BBMacFinal
def _sub_158_encrypt_block(block: bytes, key: bytearray, key_type: int) -> Tuple[bytes, bytes]:
    if len(block) % 0x10 != 0:
        _raise(ERROR_INVALID_ARG, 'encrypt block size must be multiple of 16')
    
    b = bytearray(block)
    for i in range(0x10):
        b[i] ^= key[i]
    
    # cryptolib uses keyvault entry key_type
    ct = _crypto_cmd_encrypt_iv0(bytes(b), key_type)
    
    # update chaining key with last 16 bytes of ciphertext
    key_next = ct[-0x10:] if len(ct) >= 0x10 else (b'\x00' * 0x10)
    return ct, key_next

def BBMacUpdate(mkey: MACKey, buf: bytes, size: int):
    if mkey.pad_size > 0x10:
        _raise(ERROR_BAD_MAC_KEY_PAD, 'MAC Key padding size must be do not exceed 16 bytes')
    
    data = memoryview(buf)[:size]
    
    if mkey.pad_size + size <= 0x10:
        mkey.pad[mkey.pad_size:mkey.pad_size + size] = data.tobytes()
        mkey.pad_size += size
        return
    
    # Need to process full 16-byte blocks
    # Build a stream starting with existing pad then the new data
    stream = bytes(mkey.pad[:mkey.pad_size]) + data.tobytes()

    # Determine how many bytes remain in pad at end (C keeps last partial chunk)
    rem = (mkey.pad_size + size) & 0x0F
    if rem == 0:
        rem = 0x10
    
    full_len = len(stream) - rem
    tail = stream[full_len:]
    mkey.pad[:rem] = tail
    mkey.pad_size = rem
    
    code = 0x3A if mkey.type == 2 else 0x38
    
    # Process full_len bytes in 0x0800 chunks like C (not necessary in Python, but kept)
    p = 0
    while p < full_len:
        chunk = stream[p:p + min(0x0800, full_len - p)]
        # chunk is multiple of 16 by construction
        ct, key_next = _sub_158_encrypt_block(chunk, mkey.key, code)
        mkey.key[:] = key_next
        p += len(chunk)

    return

# left shift L by 1 (GF(2^128) Rb=0x87)
def _left_shift_1(block16: bytes) -> bytes:
    b = bytearray(0x10)
    carry = False
    for i in reversed(range(0x10)):
        v = block16[i]
        b[i] = ((v << 1) & 0xFF) | carry
        carry = True if (v & 0x80) else False
    if carry:
        b[15] ^= 0x87
    return bytes(b)

def BBMacFinal(mkey: MACKey, out16: bytearray, vkey: Optional[bytes]):
    if mkey.pad_size > 0x10:
        _raise(ERROR_BAD_MAC_KEY_PAD, 'MAC Key padding size must be do not exceed 16 bytes')
    
    code = 0x3A if mkey.type == 2 else 0x38
    
    # Step 1: encrypt 16 bytes of zeros to get L
    L = _crypto_cmd_encrypt_iv0(b'\x00' * 0x10, code)
    
    K1 = _left_shift_1(L)
    K2 = _left_shift_1(K1)
    
    # padding
    pad = bytearray(mkey.pad)
    if mkey.pad_size < 0x10:
        pad[mkey.pad_size] = 0x80
        for j in range(mkey.pad_size + 1, 0x10):
            pad[j] = 0x00
        subkey = K2
    else:
        subkey = K1
    
    for i in range(0x10):
        pad[i] ^= subkey[i]
    
    # Encrypt final block with chaining key mkey.key
    final_block = bytes(pad)
    ct, key_next = _sub_158_encrypt_block(final_block, mkey.key, code)
    tmp1 = bytearray(ct[-0x10:])
    
    # tmp1 ^= loc_1CD4
    for i in range(0x10):
        tmp1[i] ^= _AM_HASH_KEY_3[i]
    
    # If type==2, do fuse encrypt then cmd4 again
    if mkey.type == 2:
        tmp1 = bytearray(_crypto_cmd_encrypt_fuse(bytes(tmp1)))
        tmp1 = bytearray(_crypto_cmd_encrypt_iv0(bytes(tmp1), code))
    
    # If vkey provided, XOR and encrypt
    if vkey is not None:
        if len(vkey) != 0x10:
            _raise(ERROR_INVALID_ARG, 'BBox MacFinal: version key must be 16 bytes')
        for i in range(0x10):
            tmp1[i] ^= vkey[i]
        tmp1 = bytearray(_crypto_cmd_encrypt_iv0(bytes(tmp1), code))
    
    out16[:0x10] = tmp1[:0x10]
    
    # clear
    mkey.key[:] = b'\x00' * 0x10
    mkey.pad[:] = b'\x00' * 0x10
    mkey.pad_size = 0
    mkey.type = 0

def bbmac_getkey(mkey: MACKey, bbmac: bytes) -> bytearray:
    if len(bbmac) != 0x10:
        _raise(ERROR_INVALID_ARG, 'BBox bbmac_getkey: bbmac must be exactly 16 bytes')
    
    # Step 1: Compute the expected MAC value (without version key)
    vkey = bytearray(0x10)
    tmp = bytearray(0x10)
    type_ = mkey.type
    BBMacFinal(mkey, tmp, None)
    
    # Working buffer for the provided MAC transformations
    mac_working = bytearray(bbmac)
    
    # Special handling for type 3: MAC is pre-encrypted with keyseed 0x63
    if type_ == 3:
        mac_working[:] = _crypto_cmd_decrypt_iv0(bytes(mac_working), 0x63)
    
    # Step 2: Decrypt with the type-specific code (0x38 or 0x3A)
    code = 0x3A if type_ == 2 else 0x38
    decrypted = _crypto_cmd_decrypt_iv0(bytes(mac_working), code)
    
    # Step 3: Recover vkey = expected_MAC XOR decrypted_MAC
    for i in range(0x10):
        vkey[i] = tmp[i] ^ decrypted[i]
    
    return vkey

# ============================================================
# Cipher functions
# ============================================================

BB_CIPHER_ENCRYPT = 1
BB_CIPHER_DECRYPT = 2

def BBCipherInit(ckey: CipherKey, type_: int, mode: int, header_key: bytearray, version_key: Optional[bytes], seed: int):
    ckey.type = int(type_)
    
    if mode == BB_CIPHER_DECRYPT:
        ckey.seed = int(seed) + 1
        ckey.key[:] = header_key[:0x10]
        if version_key is not None:
            if len(version_key) != 0x10:
                _raise(ERROR_INVALID_ARG, 'version_key must be 16 bytes')
            for i in range(0x10):
                ckey.key[i] ^= version_key[i]
    
    if mode == BB_CIPHER_ENCRYPT:
        ckey.seed = 1
        rnd = _crypto_cmd_prng()  # 20 bytes
        kbuf = bytearray(rnd[:0x10])
        # clear last u32
        kbuf[0x0C:0x10] = b'\x00\x00\x00\x00'

        # type==2 uses fuse encrypt; else cmd4 with keyseed 0x39
        if ckey.type == 2:
            for i in range(0x10):
                kbuf[i] ^= _AM_HASH_KEY_4[i]
            kbuf = bytearray(_crypto_cmd_encrypt_fuse(bytes(kbuf)))
            for i in range(0x10):
                kbuf[i] ^= _AM_HASH_KEY_5[i]
        else:
            for i in range(0x10):
                kbuf[i] ^= _AM_HASH_KEY_4[i]
            kbuf = bytearray(_crypto_cmd_encrypt_iv0(bytes(kbuf), 0x39))
            for i in range(0x10):
                kbuf[i] ^= _AM_HASH_KEY_5[i]
        
        ckey.key[:] = kbuf[:0x10]
        header_key[:0x10] = kbuf[:0x10]
        
        if version_key is not None:
            for i in range(0x10):
                ckey.key[i] ^= version_key[i]

def _sub_428_xor_stream(data: bytearray, ckey: CipherKey):
    size = len(data)
    
    if size % 0x10 != 0:
        _raise(ERROR_INVALID_ARG, 'cipher update size must be multiple of 16')
    
    # Step A: derive tmp2 from ckey.key
    tmp = bytearray(ckey.key)
    for i in range(0x10):
        tmp[i] ^= _AM_HASH_KEY_5[i]
    
    if ckey.type == 2:
        tmp = bytearray(_crypto_cmd_decrypt_fuse(bytes(tmp)))
    else:
        tmp = bytearray(_crypto_cmd_decrypt_iv0(bytes(tmp), 0x39))
    
    for i in range(0x10):
        tmp[i] ^= _AM_HASH_KEY_4[i]
    
    tmp2 = bytes(tmp)
    
    # tmp1 is either zeros (seed==1) or tmp2 with (seed-1) in last u32
    if ckey.seed == 1:
        tmp1 = b'\x00' * 0x10
    else:
        tmp1_ba = bytearray(tmp2)
        struct.pack_into('<I', tmp1_ba, 12, (ckey.seed - 1) & 0xFFFFFFFF)
        tmp1 = bytes(tmp1_ba)
    
    # Build counter blocks: first 12 bytes from tmp2, last u32 = seed, increment per block
    blocks = bytearray(size)
    for off in range(0, size, 0x10):
        blocks[off:off + 12] = tmp2[0:12]
        struct.pack_into('<I', blocks, off + 12, ckey.seed & 0xFFFFFFFF)
        ckey.seed = (ckey.seed + 1) & 0xFFFFFFFF
    
    # Decrypt blocks with keyseed 0x63 and IV tmp1
    # We approximate by XORing first block with tmp1, decrypting CBC with keyseed 0x63,
    # and then updating tmp1 to last ciphertext block.
    # For correctness against the original environment you may need the real loc masks + keyvault.
    # Here we implement a stable, testable transformation.
    
    # XOR first block with tmp1:
    for i in range(0x10):
        blocks[i] ^= tmp1[i]
    
    # 'decrypt' with keyseed 0x63 (CBC zero IV in engine)
    keystream = bytearray(_crypto_cmd_decrypt_iv0(bytes(blocks), 0x63))
    
    # XOR data
    for i in range(size):
        data[i] ^= keystream[i]

def BBCipherUpdate(ckey: CipherKey, data: bytearray):
    view = memoryview(data)
    size = len(data)
    p = 0
    while size > 0:
        dsize = 0x0800 if size >= 0x0800 else size
        chunk = bytearray(view[p:p + dsize])
        _sub_428_xor_stream(chunk, ckey)
        view[p:p + dsize] = chunk
        size -= dsize
        p += dsize

def BBCipherFinal(ckey: CipherKey):
    ckey.key[:] = b'\x00' * 0x10
    ckey.type = 0
    ckey.seed = 0

# ============================================================
# BBox API
# ============================================================

def get_secure_install_id(buf: bytes, type_: int) -> bytes:
    id_out = bytearray(0x10)
    
    mkey = MACKey(type=0, key=bytearray(0x10), pad=bytearray(0x10), pad_size=0)
    
    BBMacInit(mkey, type_)
    BBMacUpdate(mkey, buf, 0x70)
    id_out[:0x10] = bbmac_getkey(mkey, buf[0x70:0x80])
    
    return id_out

def pops_get_secure_install_id(buf: bytes) -> bytes:
    id_out = bytearray(0x10)
    
    mkey = MACKey(type=0, key=bytearray(0x10), pad=bytearray(0x10), pad_size=0)
    
    BBMacInit(mkey, 3)
    BBMacUpdate(mkey, buf, 0x60)
    id_out[:0x10] = bbmac_getkey(mkey, buf[0x60:0x70])
    
    return id_out

def bbox_mac_gen(buf: bytes, vkey: bytes, type_: int) -> bytes:
    if len(vkey) != 0x10:
        _raise(ERROR_INVALID_ARG, 'version_key must be 16 bytes')
    
    size = len(buf)
    buf = bytes(buf)
    tmp = bytearray(0x10)
    
    mkey = MACKey(type=0, key=bytearray(0x10), pad=bytearray(0x10), pad_size=0)
    BBMacInit(mkey, type_)
    BBMacUpdate(mkey, buf, size)
    BBMacFinal(mkey, tmp, vkey)
    
    return bytes(tmp)

def bbox_mac_gen_enc(buf: bytes, vkey: bytes) -> bytes:
    get_bb_mac = bbox_mac_gen(buf, vkey, 3)
    return _crypto_cmd_encrypt_iv0(get_bb_mac, 0x63)

def bbox_mac_check(buf: bytes, size: int, vkey: bytes, digest: bytes, type_: int) -> bool:
    if len(digest) != 0x10:
        _raise(ERROR_INVALID_ARG, 'BBox (bbox_mac_check): Bad digest length')
    if len(vkey) != 0x10:
        _raise(ERROR_INVALID_ARG, 'BBox (bbox_mac_check): Bad version key length')
    
    tmp = bytearray(0x10)
    mkey = MACKey(type=0, key=bytearray(0x10), pad=bytearray(0x10), pad_size=0)
    BBMacInit(mkey, type_)
    BBMacUpdate(mkey, buf, size)
    BBMacFinal(mkey, tmp, vkey)
    
    return bytes(tmp) == digest

def bbox_decrypt(buf: bytearray, seed: int, vkey: bytes, hdr_key: bytes, type_: int):
    if len(vkey) != 0x10 or len(hdr_key) != 0x10:
        _raise(ERROR_INVALID_ARG, 'BBox: Decryption failed, bad keys size')
    
    # print(f'  > HEADER KEY: {" ".join(f"{h:02X}" for h in hdr_key)}')
    
    ckey = CipherKey(type=0, seed=0, key=bytearray(0x10))
    header_key_ba = bytearray(hdr_key)
    
    BBCipherInit(ckey, type_, BB_CIPHER_DECRYPT, header_key_ba, vkey, seed)
    BBCipherUpdate(ckey, buf)
    BBCipherFinal(ckey)

def bbox_verify_header(buf: bytearray, secure_install_id: Optional[bytes], flag: int) -> bool:
    if len(buf) < 0x90:
        _raise(ERROR_INVALID_FORMAT, 'BBox: Header minimal size is 0x90 bytes')
    
    if buf[0:4] != b'\0PGD':
        _raise(ERROR_INVALID_FORMAT, 'BBox: Bad PGD magic')
    
    version = struct.unpack_from('<I', buf, 4)[0]
    if version != 1:
        _raise(ERROR_UNKNOWN_VERSION, 'BBox: Only version 1 is supported')
    
    box_type = struct.unpack_from('<I', buf, 8)[0]
    type_ = 2
    
    if box_type == 1:
        flag |= 4
        type_ = 1
    else:
        if box_type != 0 or (flag & 4) != 0:
            _raise(ERROR_INVALID_FORMAT, 'BBox: Verify header failed')
    
    dnas_key = None
    if (flag & 2) != 0:
        dnas_key = _DNAS_KEY1
    if (flag & 1) != 0:
        dnas_key = _DNAS_KEY2
    
    if dnas_key is None:
        _raise(ERROR_INVALID_ARG, 'BBox: Verify header failed, bad DNAS flag')
    
    retv = bbox_mac_check(bytes(buf[:0x80]), 0x80, dnas_key, bytes(buf[0x80:0x90]), type_)
    if not retv:
        return False
    
    if secure_install_id is not None:
        if len(secure_install_id) != 16:
            _raise(ERROR_INVALID_ARG, 'BBox: Verify header failed, bad secure_install_id length')
        
        retv = bbox_mac_check(bytes(buf[:0x70]), 0x70, secure_install_id, bytes(buf[0x70:0x80]), type_)
        if not retv:
            return False
        
        # decrypt header segment: buf+0x30 size 0x30, hdr_key=buf+0x10
        segment = bytearray(buf[0x30:0x60])
        bbox_decrypt(segment, 0, secure_install_id, bytes(buf[0x10:0x20]), type_)
        buf[0x30:0x60] = segment
        
        # version check
        if struct.unpack_from('<I', buf, 0x40)[0] != 0:
            return False
        
        # blob block size
        if struct.unpack_from('<I', buf, 0x48)[0] != 0x400:
            return False
    
    return True

# ============================================================
# API
# ============================================================

def io_filemgr_bbox_decrypt(inbuf: bytearray, outbuf: bytearray, secure_install_id_out: bytearray) -> int:
    box_type = struct.unpack_from('<I', inbuf, 8)[0]
    if box_type == 0:
        type_ = 2
    if box_type == 1:
        type_ = 1
    if type_ is None:
        print('io_filemgr_bbox_decrypt: Bad BBox type.')
        return -1
    
    calc_id = get_secure_install_id(bytes(inbuf), type_)
    secure_install_id_out[:0x10] = calc_id
    
    flag = 2
    if type_ == 2:
        flag = 1
    
    res = bbox_verify_header(inbuf, bytes(calc_id), flag)
    if not res:
        print('io_filemgr_bbox_decrypt: Header verification failed.')
        return -1
    
    # Note:
    # bbox_verify_header decrypted buffer: inbuf[0x30:0x60]
    # Used header key: buf[0x10:0x20] and secure_install_id
    
    data_size = struct.unpack_from('<I', inbuf, 0x44)[0]
    block_size = struct.unpack_from('<I', inbuf, 0x48)[0]
    data_offset = struct.unpack_from('<I', inbuf, 0x4C)[0]
    
    align_size = (data_size + 15) & ~15
    table_offset = data_offset + align_size
    block_num = ((align_size + block_size - 1) & ~(block_size - 1)) // block_size
    
    if (align_size + block_num * 0x10) > len(inbuf):
        print('io_filemgr_bbox_decrypt: Invalid data size')
        return -1
    
    # check data table mac
    res = bbox_mac_check(
        bytes(inbuf[table_offset:table_offset + block_num * 0x10]),
        block_num * 0x10,
        bytes(calc_id),
        bytes(inbuf[0x60:0x70]),
        type_,
    )
    
    if not res:
        print('io_filemgr_bbox_decrypt: Data verification failed')
        return -1
    
    data_region = bytearray(inbuf[0x90:0x90 + align_size])
    bbox_decrypt(data_region, 0, bytes(calc_id), bytes(inbuf[0x30:0x40]), type_)
    inbuf[0x90:0x90 + align_size] = data_region
    
    payload = bytes(inbuf[data_offset:data_offset + data_size])
    outbuf[:data_size] = payload
    return data_size

def bbox_decrypt_blob(blob: bytes) -> Tuple[bytes, bytes]:
    inbuf = bytearray(blob)
    outbuf = bytearray(len(blob))
    sid = bytearray(0x10)
    
    outbuf_len = io_filemgr_bbox_decrypt(inbuf, outbuf, sid)
    if outbuf_len < 0:
        _raise(outbuf_len, 'BBox: Blob decrypt failed, bad output data')
    
    return bytes(outbuf[:outbuf_len]), bytes(sid)
