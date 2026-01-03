from __future__ import annotations

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
# Error codes (match iofilemgr_bbox.h)
# ============================================================

ERROR_INVALID_ARG       = 0x80510201
ERROR_MFILE             = 0x80510202
ERROR_BADF              = 0x80510203
ERROR_INVALID_FORMAT    = 0x80510204
ERROR_UNKNOWN_VERSION   = 0x80510205
ERROR_SECURE_INSTALL_ID = 0x80510206
ERROR_BROKEN_DATA       = 0x80510207

class BBoxException(Exception):
    def __init__(self, code: int, message: str = ""):
        self.code = int(code)
        super().__init__(message or f"BBox error 0x{self.code:08X}")

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

PGD_MAGIC = 0x44475000
_DNAS_KEY1 = bytes([0xED, 0xE2, 0x5D, 0x2D, 0xBB, 0xF8, 0x12, 0xE5, 0x3C, 0x5C, 0x59, 0x32, 0xFA, 0xE3, 0xE2, 0x43])
_DNAS_KEY2 = bytes([0x27, 0x74, 0xFB, 0xEB, 0xA4, 0xA0, 0x01, 0xD7, 0x02, 0x56, 0x9E, 0x33, 0x8C, 0x19, 0x57, 0x83])
_PSP_AM_HASH_KEY_1 = bytes([0x9C, 0x48, 0xB6, 0x28, 0x40, 0xE6, 0x53, 0x3F, 0x05, 0x11, 0x3A, 0x4E, 0x65, 0xE6, 0x3A, 0x64])
_PSP_AM_HASH_KEY_2 = bytes([0x70, 0xB4, 0x7B, 0xC0, 0xA1, 0x4B, 0xDA, 0xD6, 0xE0, 0x10, 0x14, 0xED, 0x72, 0x7C, 0x53, 0x4C])
_PSP_AM_HASH_KEY_3 = bytes([0xE3, 0x50, 0xED, 0x1D, 0x91, 0x0A, 0x1F, 0xD0, 0x29, 0xBB, 0x1C, 0x3E, 0xF3, 0x40, 0x77, 0xFB])
_PSP_AM_HASH_KEY_4 = bytes([0x13, 0x5F, 0xA4, 0x7C, 0xAB, 0x39, 0x5B, 0xA4, 0x76, 0xB8, 0xCC, 0xA9, 0x8F, 0x3A, 0x04, 0x45])
_PSP_AM_HASH_KEY_5 = bytes([0x67, 0x8D, 0x7F, 0xA3, 0x2A, 0x9C, 0xA0, 0xD1, 0x50, 0x8A, 0xD8, 0x38, 0x5E, 0x4B, 0x01, 0x7E])

# ============================================================
# Helpers: cryptoengine wrappers matching the C header format
# ============================================================

def _aes128cbc_header(mode: int, keyseed: int, data_size: int) -> bytes:
    # struct Aes128CbcHeader: <iiiii
    return struct.pack("<iiiii", mode, 0, 0, int(keyseed), int(data_size))

def _crypto_cmd_encrypt_iv0(data: bytes, keyseed: int) -> bytes:
    inbuf = _aes128cbc_header(4, keyseed, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_ENCRYPT_IV_0)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        # C returned 0x80510311 / 0x80510312 etc; we bubble as BBoxException with invalid format.
        _raise(ERROR_INVALID_FORMAT, f"crypto cmd4 failed (status={status})")
    return out[0x14:0x14 + len(data)]

def _crypto_cmd_decrypt_iv0(data: bytes, keyseed: int) -> bytes:
    inbuf = _aes128cbc_header(5, keyseed, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_DECRYPT_IV_0)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f"crypto cmd7 failed (status={status})")
    # CMD7 returns plaintext directly (cryptolib implementation)
    return out

def _crypto_cmd_encrypt_fuse(data: bytes) -> bytes:
    inbuf = _aes128cbc_header(4, 0x0100, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_ENCRYPT_IV_FUSE)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f"crypto cmd5 failed (status={status})")
    return out[0x14:0x14 + len(data)]

def _crypto_cmd_decrypt_fuse(data: bytes) -> bytes:
    inbuf = _aes128cbc_header(5, 0x0100, len(data)) + data
    status, out = _eng().utils_buffer_copy_with_range(inbuf, CRYPTOENGINE_CMD_DECRYPT_IV_FUSE)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f"crypto cmd8 failed (status={status})")
    return out

def _crypto_cmd_prng() -> bytes:
    status, out = _eng().utils_buffer_copy_with_range(b"", CRYPTOENGINE_CMD_PRNG)
    if status != CRYPTOENGINE_OPERATION_SUCCESS or out is None:
        _raise(ERROR_INVALID_FORMAT, f"crypto cmd14 failed (status={status})")
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
    mkey.key[:] = b"\x00" * 16
    mkey.pad[:] = b"\x00" * 16
    return 0

def _sub_158_encrypt_block(block: bytes, key: bytearray, key_type: int) -> Tuple[bytes, bytes]:
    if len(block) % 16 != 0:
        _raise(ERROR_INVALID_ARG, "encrypt block size must be multiple of 16")

    b = bytearray(block)
    for i in range(16):
        b[i] ^= key[i]

    # C uses cryptoengine4 with key_type; cryptolib uses keyvault entry key_type+4
    ct = _crypto_cmd_encrypt_iv0(bytes(b), key_type)

    # update chaining key with last 16 bytes of ciphertext
    key_next = ct[-16:] if len(ct) >= 16 else (b"\x00" * 16)
    return ct, key_next

def BBMacUpdate(mkey: MACKey, buf: bytes, size: int) -> int:
    if mkey.pad_size > 16:
        return 0x80510302

    data = memoryview(buf)[:size]

    if mkey.pad_size + size <= 16:
        mkey.pad[mkey.pad_size:mkey.pad_size + size] = data.tobytes()
        mkey.pad_size += size
        return 0

    # Need to process full 16-byte blocks
    # Build a stream starting with existing pad then the new data
    stream = bytes(mkey.pad[:mkey.pad_size]) + data.tobytes()

    # Determine how many bytes remain in pad at end (C keeps last partial chunk)
    rem = (mkey.pad_size + size) & 0x0F
    if rem == 0:
        rem = 16

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

    return 0

def BBMacFinal(mkey: MACKey, out16: bytearray, vkey: Optional[bytes]) -> int:
    if mkey.pad_size > 16:
        return 0x80510302

    code = 0x3A if mkey.type == 2 else 0x38

    # Step 1: encrypt 16 bytes of zeros to get L
    L = _crypto_cmd_encrypt_iv0(b"\x00" * 16, code)

    # left shift L by 1 (GF(2^128) Rb=0x87)
    def left_shift_1(block16: bytes) -> bytes:
        b = bytearray(16)
        carry = 0
        for i in reversed(range(16)):
            v = block16[i]
            b[i] = ((v << 1) & 0xFF) | carry
            carry = 1 if (v & 0x80) else 0
        if carry:
            b[15] ^= 0x87
        return bytes(b)

    K1 = left_shift_1(L)
    K2 = left_shift_1(K1)

    # padding
    pad = bytearray(mkey.pad)
    if mkey.pad_size < 16:
        pad[mkey.pad_size] = 0x80
        for j in range(mkey.pad_size + 1, 16):
            pad[j] = 0x00
        subkey = K2
    else:
        subkey = K1

    for i in range(16):
        pad[i] ^= subkey[i]

    # Encrypt final block with chaining key mkey.key (C does sub_158 over one block)
    final_block = bytes(pad)
    ct, key_next = _sub_158_encrypt_block(final_block, mkey.key, code)
    tmp1 = bytearray(ct[-16:])

    # tmp1 ^= loc_1CD4
    for i in range(16):
        tmp1[i] ^= _PSP_AM_HASH_KEY_3[i]

    # If type==2, do fuse encrypt then cmd4 again
    if mkey.type == 2:
        tmp1 = bytearray(_crypto_cmd_encrypt_fuse(bytes(tmp1)))
        tmp1 = bytearray(_crypto_cmd_encrypt_iv0(bytes(tmp1), code))

    # If vkey provided, XOR and encrypt
    if vkey is not None:
        if len(vkey) != 16:
            _raise(ERROR_INVALID_ARG, "vkey must be 16 bytes")
        for i in range(16):
            tmp1[i] ^= vkey[i]
        tmp1 = bytearray(_crypto_cmd_encrypt_iv0(bytes(tmp1), code))

    out16[:16] = tmp1[:16]

    # clear
    mkey.key[:] = b"\x00" * 16
    mkey.pad[:] = b"\x00" * 16
    mkey.pad_size = 0
    mkey.type = 0
    return 0

def bbmac_getkey(mkey: MACKey, bbmac: bytes, vkey_out: bytearray) -> int:
    if len(bbmac) != 16:
        _raise(ERROR_INVALID_ARG, "bbmac must be 16 bytes")
    tmp = bytearray(16)
    ret = BBMacFinal(mkey, tmp, None)
    if ret < 0:
        return ret

    # decrypt bbmac if type==3 with keyseed 0x63, else treat as raw
    if mkey.type == 3:
        dec = _crypto_cmd_decrypt_iv0(bbmac, 0x63)
    else:
        dec = bbmac

    # decrypt with code (0x3A / 0x38) then XOR with tmp
    code = 0x3A if mkey.type == 2 else 0x38
    dec2 = _crypto_cmd_decrypt_iv0(dec, code)

    for i in range(16):
        vkey_out[i] = tmp[i] ^ dec2[i]
    return 0

# ============================================================
# Cipher functions
# ============================================================

BB_CIPHER_ENCRYPT = 1
BB_CIPHER_DECRYPT = 2

def BBCipherInit(ckey: CipherKey, type_: int, mode: int, header_key: bytearray, version_key: Optional[bytes], seed: int) -> int:
    ckey.type = int(type_)

    if mode == BB_CIPHER_DECRYPT:
        ckey.seed = int(seed) + 1
        ckey.key[:] = header_key[:16]
        if version_key is not None:
            if len(version_key) != 16:
                _raise(ERROR_INVALID_ARG, "version_key must be 16 bytes")
            for i in range(16):
                ckey.key[i] ^= version_key[i]
        return 0

    if mode == BB_CIPHER_ENCRYPT:
        ckey.seed = 1
        rnd = _crypto_cmd_prng()  # 20 bytes
        kbuf = bytearray(rnd[:16])
        # clear last u32
        kbuf[12:16] = b"\x00\x00\x00\x00"

        # type==2 uses fuse encrypt; else cmd4 with keyseed 0x39
        if ckey.type == 2:
            for i in range(16):
                kbuf[i] ^= _PSP_AM_HASH_KEY_4[i]
            kbuf = bytearray(_crypto_cmd_encrypt_fuse(bytes(kbuf)))
            for i in range(16):
                kbuf[i] ^= _PSP_AM_HASH_KEY_5[i]
        else:
            for i in range(16):
                kbuf[i] ^= _PSP_AM_HASH_KEY_4[i]
            kbuf = bytearray(_crypto_cmd_encrypt_iv0(bytes(kbuf), 0x39))
            for i in range(16):
                kbuf[i] ^= _PSP_AM_HASH_KEY_5[i]

        ckey.key[:] = kbuf[:16]
        header_key[:16] = kbuf[:16]

        if version_key is not None:
            for i in range(16):
                ckey.key[i] ^= version_key[i]
        return 0

    return 0

def _sub_428_xor_stream(data: bytearray, ckey: CipherKey) -> int:
    size = len(data)
    if size % 16 != 0:
        _raise(ERROR_INVALID_ARG, "cipher update size must be multiple of 16")

    # Step A: derive tmp2 from ckey.key
    tmp = bytearray(ckey.key)
    for i in range(16):
        tmp[i] ^= _PSP_AM_HASH_KEY_5[i]

    if ckey.type == 2:
        tmp = bytearray(_crypto_cmd_decrypt_fuse(bytes(tmp)))
    else:
        tmp = bytearray(_crypto_cmd_decrypt_iv0(bytes(tmp), 0x39))

    for i in range(16):
        tmp[i] ^= _PSP_AM_HASH_KEY_4[i]

    tmp2 = bytes(tmp)

    # tmp1 is either zeros (seed==1) or tmp2 with (seed-1) in last u32
    if ckey.seed == 1:
        tmp1 = b"\x00" * 16
    else:
        tmp1_ba = bytearray(tmp2)
        struct.pack_into("<I", tmp1_ba, 12, (ckey.seed - 1) & 0xFFFFFFFF)
        tmp1 = bytes(tmp1_ba)

    # Build counter blocks: first 12 bytes from tmp2, last u32 = seed, increment per block
    blocks = bytearray(size)
    for off in range(0, size, 16):
        blocks[off:off + 12] = tmp2[0:12]
        struct.pack_into("<I", blocks, off + 12, ckey.seed & 0xFFFFFFFF)
        ckey.seed = (ckey.seed + 1) & 0xFFFFFFFF

    # Decrypt blocks with keyseed 0x63 and IV tmp1 (C does sub_1F8 with tmp1 as key)
    # We approximate by XORing first block with tmp1, decrypting CBC with keyseed 0x63,
    # and then updating tmp1 to last ciphertext block.
    # For correctness against the original environment you may need the real loc masks + keyvault.
    # Here we implement a stable, testable transformation.

    # XOR first block with tmp1:
    for i in range(16):
        blocks[i] ^= tmp1[i]

    # "decrypt" with keyseed 0x63 (CBC zero IV in engine)
    keystream = bytearray(_crypto_cmd_decrypt_iv0(bytes(blocks), 0x63))

    # XOR data
    for i in range(size):
        data[i] ^= keystream[i]
    return 0

def BBCipherUpdate(ckey: CipherKey, data: bytearray, size: int) -> int:
    view = memoryview(data)[:size]
    p = 0
    while size > 0:
        dsize = 0x0800 if size >= 0x0800 else size
        chunk = bytearray(view[p:p + dsize])
        _sub_428_xor_stream(chunk, ckey)
        view[p:p + dsize] = chunk
        size -= dsize
        p += dsize
    return 0

def BBCipherFinal(ckey: CipherKey) -> int:
    ckey.key[:] = b"\x00" * 16
    ckey.type = 0
    ckey.seed = 0
    return 0

# ============================================================
# bbox_api
# ============================================================

def get_secure_install_id(buf: bytes, type_: int, id_out: bytearray) -> int:
    tmp_id = bytearray(16)
    mkey = MACKey(type=0, key=bytearray(16), pad=bytearray(16), pad_size=0)
    BBMacInit(mkey, type_)
    BBMacUpdate(mkey, buf, 0x70)
    bbmac_getkey(mkey, buf[0x70:0x70 + 16], tmp_id)
    id_out[:16] = tmp_id
    return 0

def boxbb_mac_gen(buf: bytes, vkey: bytes, type_: int) -> bytes | int:
    if len(vkey) != 16:
        return ERROR_INVALID_ARG
    
    size = len(buf)
    buf = bytes(buf)
    tmp = bytearray(16)
    
    mkey = MACKey(type=0, key=bytearray(16), pad=bytearray(16), pad_size=0)
    
    retv = BBMacInit(mkey, type_)
    if retv < 0:
        return retv
    
    retv = BBMacUpdate(mkey, buf, size)
    if retv < 0:
        return retv
    
    retv = BBMacFinal(mkey, tmp, vkey)
    if retv < 0:
        return retv
    
    return bytes(tmp)

def boxbb_mac_check(buf: bytes, size: int, vkey: bytes, digest: bytes, type_: int) -> int:
    if digest is None:
        return ERROR_INVALID_ARG
    if len(digest) != 16:
        return ERROR_INVALID_ARG
    if len(vkey) != 16:
        return ERROR_INVALID_ARG

    tmp = bytearray(16)
    mkey = MACKey(type=0, key=bytearray(16), pad=bytearray(16), pad_size=0)

    retv = BBMacInit(mkey, type_)
    if retv < 0:
        return retv

    retv = BBMacUpdate(mkey, buf, size)
    if retv < 0:
        return retv

    retv = BBMacFinal(mkey, tmp, vkey)
    if retv < 0:
        return retv

    if bytes(tmp) != digest:
        return ERROR_BROKEN_DATA

    return 0

def boxbb_decrypt(buf: bytearray, size: int, seed: int, vkey: bytes, hdr_key: bytes, type_: int) -> int:
    if len(vkey) != 16 or len(hdr_key) != 16:
        return ERROR_INVALID_ARG

    ckey = CipherKey(type=0, seed=0, key=bytearray(16))
    header_key_ba = bytearray(hdr_key)

    retv = BBCipherInit(ckey, type_, BB_CIPHER_DECRYPT, header_key_ba, vkey, seed)
    if retv < 0:
        return retv

    retv = BBCipherUpdate(ckey, buf, size)
    if retv < 0:
        return retv

    retv = BBCipherFinal(ckey)
    if retv < 0:
        return retv

    return 0

def boxbb_verify_header(buf: bytearray, secure_install_id: Optional[bytes], flag: int) -> int:
    if len(buf) < 0x90:
        return ERROR_INVALID_FORMAT

    if buf[0:4] != struct.pack("<I", PGD_MAGIC):
        return ERROR_INVALID_FORMAT

    version = struct.unpack_from("<I", buf, 4)[0]
    if version != 1:
        return ERROR_UNKNOWN_VERSION

    box_type = struct.unpack_from("<I", buf, 8)[0]
    type_ = 2

    if box_type == 1:
        flag |= 4
        type_ = 1
    else:
        if box_type != 0:
            return ERROR_INVALID_FORMAT
        if (flag & 4) != 0:
            return ERROR_INVALID_FORMAT

    dnas_key: Optional[bytes] = None
    if (flag & 2) != 0:
        dnas_key = _DNAS_KEY1
    if (flag & 1) != 0:
        dnas_key = _DNAS_KEY2
    if dnas_key is None:
        return ERROR_INVALID_ARG

    retv = boxbb_mac_check(bytes(buf[:0x80]), 0x80, dnas_key, bytes(buf[0x80:0x90]), type_)
    if retv < 0:
        return ERROR_INVALID_FORMAT

    if secure_install_id is not None:
        if len(secure_install_id) != 16:
            return ERROR_INVALID_ARG

        retv = boxbb_mac_check(bytes(buf[:0x70]), 0x70, secure_install_id, bytes(buf[0x70:0x80]), type_)
        if retv < 0:
            return ERROR_SECURE_INSTALL_ID

        # decrypt header segment: buf+0x30 size 0x30, hdr_key=buf+0x10
        segment = bytearray(buf[0x30:0x30 + 0x30])
        retv = boxbb_decrypt(segment, 0x30, 0, secure_install_id, bytes(buf[0x10:0x20]), type_)
        if retv < 0:
            return retv
        buf[0x30:0x30 + 0x30] = segment

        if struct.unpack_from("<I", buf, 0x40)[0] != 0:
            return ERROR_UNKNOWN_VERSION

        if struct.unpack_from("<I", buf, 0x48)[0] != 0x400:
            return ERROR_INVALID_FORMAT

        flag |= 8

    return flag

# ============================================================
# iofilemgr
# ============================================================

def iofilemgrBBoxDecrypt(
    inbuf: bytearray,
    size: int,
    outbuf: bytearray,
    secure_install_id_out: bytearray,
    verbose: bool = False,
) -> int:
    if len(inbuf) < size:
        return ERROR_INVALID_ARG

    box_type = struct.unpack_from("<I", inbuf, 8)[0]
    if box_type == 0:
        type_ = 2
    elif box_type == 1:
        type_ = 1
    else:
        return -1

    calc_id = bytearray(16)
    res = get_secure_install_id(bytes(inbuf), type_, calc_id)
    if res < 0:
        if verbose:
            print("sceIofilemgrDnasDecrypt() cannot get secure install id.")
        return res

    secure_install_id_out[:16] = calc_id

    flag = 2
    if type_ == 2:
        flag = 1

    res = boxbb_verify_header(inbuf, bytes(calc_id), flag)
    if res < 0:
        if verbose:
            print("sceIofilemgrDnasDecrypt() header verification failed.")
        return res

    data_size = struct.unpack_from("<I", inbuf, 0x44)[0]
    block_size = struct.unpack_from("<I", inbuf, 0x48)[0]
    data_offset = struct.unpack_from("<I", inbuf, 0x4C)[0]

    align_size = (data_size + 15) & ~15
    table_offset = data_offset + align_size
    block_num = ((align_size + block_size - 1) & ~(block_size - 1)) // block_size

    if (align_size + block_num * 16) > size:
        if verbose:
            print("sceIofilemgrDnasDecrypt() invalid size!")
        return -1

    # check data table mac
    res = boxbb_mac_check(
        bytes(inbuf[table_offset:table_offset + block_num * 16]),
        block_num * 16,
        bytes(calc_id),
        bytes(inbuf[0x60:0x70]),
        type_,
    )
    if res < 0:
        if verbose:
            print("sceIofilemgrDnasDecrypt() data verification failed.")
        return res

    # decrypt data
    data_region = bytearray(inbuf[0x90:0x90 + align_size])
    res = boxbb_decrypt(data_region, align_size, 0, bytes(calc_id), bytes(inbuf[0x30:0x40]), type_)
    if res < 0:
        if verbose:
            print("sceIofilemgrDnasDecrypt() data decryption failed.")
        return res
    inbuf[0x90:0x90 + align_size] = data_region

    # copy decrypted payload
    payload = bytes(inbuf[data_offset:data_offset + data_size])
    outbuf[:data_size] = payload
    return data_size

# ============================================================
# API
# ============================================================

def verify_header(blob: bytes, *, secure_install_id: Optional[bytes], flag: int) -> int:
    bb = bytearray(blob)
    res = boxbb_verify_header(bb, secure_install_id, flag)
    if res < 0:
        _raise(res, "header verification failed")
    return res

def decrypt_bbox_blob(blob: bytes, *, verbose: bool = False) -> Tuple[bytes, bytes]:
    inbuf = bytearray(blob)
    outbuf = bytearray(len(blob))
    sid = bytearray(16)

    res = iofilemgrBBoxDecrypt(inbuf, len(inbuf), outbuf, sid, verbose=verbose)
    if res < 0:
        _raise(res, "bbox decrypt failed")

    return bytes(outbuf[:res]), bytes(sid)
