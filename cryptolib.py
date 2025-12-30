from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from typing import Optional, Tuple, Union

from Crypto.Cipher import AES
from Crypto.Hash import CMAC, SHA1
import ecdsa

# Return values
CRYPTOENGINE_OPERATION_SUCCESS = 0
CRYPTOENGINE_NOT_ENABLED = 1
CRYPTOENGINE_INVALID_MODE = 2
CRYPTOENGINE_HEADER_HASH_INVALID = 3
CRYPTOENGINE_DATA_HASH_INVALID = 4
CRYPTOENGINE_SIG_CHECK_INVALID = 5
CRYPTOENGINE_NOT_INITIALIZED = 0xC
CRYPTOENGINE_INVALID_OPERATION = 0xD
CRYPTOENGINE_INVALID_SIZE = 0xF
CRYPTOENGINE_DATA_SIZE_ZERO = 0x10

# BufferCopyWithRange command ids
CRYPTOENGINE_CMD_0_DEVKIT_DECRYPT = 0
CRYPTOENGINE_CMD_1_DECRYPT_VERIFY = 1
CRYPTOENGINE_CMD_3_DECRYPT_VERIFY = 3
CRYPTOENGINE_CMD_ENCRYPT_IV_0 = 4
CRYPTOENGINE_CMD_ENCRYPT_IV_FUSE = 5
CRYPTOENGINE_CMD_ENCRYPT_IV_USER = 6
CRYPTOENGINE_CMD_DECRYPT_IV_0 = 7
CRYPTOENGINE_CMD_DECRYPT_IV_FUSE = 8
CRYPTOENGINE_CMD_DECRYPT_IV_USER = 9
CRYPTOENGINE_CMD_PRIV_SIGN_CHECK = 10
CRYPTOENGINE_CMD_SHA1_HASH = 11
CRYPTOENGINE_CMD_ECDSA_GEN_KEYS = 12
CRYPTOENGINE_CMD_ECDSA_MULTIPLY_POINT = 13
CRYPTOENGINE_CMD_PRNG = 14
CRYPTOENGINE_CMD_ECDSA_SIGN = 16
CRYPTOENGINE_CMD_ECDSA_VERIFY = 17
CRYPTOENGINE_CMD_CERT_VERIFY = 18

# "mode in header"
CRYPTOENGINE_MODE_CMD1 = 1
CRYPTOENGINE_MODE_CMD2 = 2
CRYPTOENGINE_MODE_CMD3 = 3
CRYPTOENGINE_MODE_ENCRYPT_CBC = 4
CRYPTOENGINE_MODE_DECRYPT_CBC = 5

# ZERO IVs
ZERO_IV_16 = b"\x00" * 16

# =============================
# Crypto helpers
# =============================

def _round_up(x: int, n: int) -> int:
    return ((x + (n - 1)) // n) * n

def _aes_ecb_encrypt(key16: bytes, block16: bytes) -> bytes:
    if len(key16) != 16 or len(block16) != 16:
        raise ValueError("ECB requires 16-byte key and 16-byte block")
    return AES.new(key16, AES.MODE_ECB).encrypt(block16)

def _aes_ecb_decrypt(key16: bytes, block16: bytes) -> bytes:
    if len(key16) != 16 or len(block16) != 16:
        raise ValueError("ECB requires 16-byte key and 16-byte block")
    return AES.new(key16, AES.MODE_ECB).decrypt(block16)

def _aes_cbc_encrypt_zero_iv(key16: bytes, data: bytes) -> bytes:
    if len(key16) != 16:
        raise ValueError("CBC requires 16-byte key")
    if len(data) % 16 != 0:
        raise ValueError("CBC encrypt requires 16-byte multiple")
    return AES.new(key16, AES.MODE_CBC, iv=ZERO_IV_16).encrypt(data)

def _aes_cbc_decrypt_zero_iv(key16: bytes, data: bytes) -> bytes:
    if len(key16) != 16:
        raise ValueError("CBC requires 16-byte key")
    if len(data) % 16 != 0:
        raise ValueError("CBC decrypt requires 16-byte multiple")
    return AES.new(key16, AES.MODE_CBC, iv=ZERO_IV_16).decrypt(data)

def _aes_cmac(key16: bytes, data: bytes) -> bytes:
    if len(key16) != 16:
        raise ValueError("CMAC requires 16-byte key")
    c = CMAC.new(key16, ciphermod=AES)
    c.update(data)
    return c.digest()  # 16 bytes

def _sha1(data: bytes) -> bytes:
    h = SHA1.new()
    h.update(data)
    return h.digest()  # 20 bytes

# =============================
# Struct parsing helpers
# =============================

@dataclass
class Cmd1Header:
    AES_key: bytes              # 0x00..0x0F (encrypted in input)
    CMAC_key: bytes             # 0x10..0x1F (encrypted in input)
    CMAC_header_hash: bytes     # 0x20..0x2F
    CMAC_data_hash: bytes       # 0x30..0x3F
    mode: int                   # 0x60 (u32)
    ecdsa_hash: int             # 0x64 (u8)
    data_size: int              # 0x70 (u32)
    data_offset: int            # 0x74 (u32)
    
    @staticmethod
    def parse(buf: bytes) -> "Cmd1Header":
        if len(buf) < 0x90:
            raise ValueError("CMD1 header buffer too small")
        return Cmd1Header(
            AES_key=buf[0x00:0x10],
            CMAC_key=buf[0x10:0x20],
            CMAC_header_hash=buf[0x20:0x30],
            CMAC_data_hash=buf[0x30:0x40],
            mode=struct.unpack_from("<I", buf, 0x60)[0],
            ecdsa_hash=buf[0x64],
            data_size=struct.unpack_from("<I", buf, 0x70)[0],
            data_offset=struct.unpack_from("<I", buf, 0x74)[0],
        )

@dataclass
class Cmd1EcdsaHeader:
    AES_key: bytes
    header_sig_r: bytes
    header_sig_s: bytes
    data_sig_r: bytes
    data_sig_s: bytes
    mode: int
    ecdsa_hash: int
    data_size: int
    data_offset: int
    
    @staticmethod
    def parse(buf: bytes) -> "Cmd1EcdsaHeader":
        if len(buf) < 0x90:
            raise ValueError("CMD1 ECDSA header buffer too small")
        return Cmd1EcdsaHeader(
            AES_key=buf[0x00:0x10],
            header_sig_r=buf[0x10:0x24],
            header_sig_s=buf[0x24:0x38],
            data_sig_r=buf[0x38:0x4C],
            data_sig_s=buf[0x4C:0x60],
            mode=struct.unpack_from("<I", buf, 0x60)[0],
            ecdsa_hash=buf[0x64],
            data_size=struct.unpack_from("<I", buf, 0x70)[0],
            data_offset=struct.unpack_from("<I", buf, 0x74)[0],
        )

@dataclass
class Aes128CbcHeader:
    mode: int
    unk_4: int
    unk_8: int
    keyseed: int
    data_size: int
    
    @staticmethod
    def parse(buf: bytes) -> "Aes128CbcHeader":
        if len(buf) < 0x14:
            raise ValueError("AES128CBC header too small")
        mode, unk4, unk8, keyseed, data_size = struct.unpack_from("<iiiii", buf, 0)
        return Aes128CbcHeader(mode, unk4, unk8, keyseed, data_size)

@dataclass
class Aes128CbcUserHeader:
    mode: int
    unk_4: int
    unk_8: int
    keyseed: int
    data_size: int
    userkey: bytes
    
    @staticmethod
    def parse(buf: bytes) -> "Aes128CbcUserHeader":
        if len(buf) < 0x24:
            raise ValueError("AES128CBC USER header too small")
        mode, unk4, unk8, keyseed, data_size = struct.unpack_from("<iiiii", buf, 0)
        userkey = buf[0x14:0x24]
        if len(userkey) != 16:
            raise ValueError("userkey must be 16 bytes")
        return Aes128CbcUserHeader(mode, unk4, unk8, keyseed, data_size, userkey)

@dataclass
class Sha1Header:
    data_size: int
    
    @staticmethod
    def parse(buf: bytes) -> "Sha1Header":
        if len(buf) < 4:
            raise ValueError("SHA1 header too small")
        (data_size,) = struct.unpack_from("<I", buf, 0)
        return Sha1Header(data_size=data_size)

# =============================
# Engine
# =============================

class CryptoEngine:
    def __init__(self) -> None:
        self.keyvault = bytearray(0x84 * 0x10)  # 0x84 entries * 16 bytes
        self.MASTER_KEY = bytes([0] * 16)
        
        self.g_fuse1: int = 0
        self.g_fuse2: int = 0
        self.g_mesh = bytearray(0x40)
        
        self.PRNG_DATA = bytearray(0x14)  # 20 bytes
        self.is_initialized = False
        
        self._aes_cryptoengine1_key = bytes(16)  # keyvault[2] once set
    
    # ---------- keyvault ----------
    def set_keyvault_entry(self, idx: int, key16: bytes) -> None:
        if len(key16) != 16:
            raise ValueError("key16 must be 16 bytes")
        if not (0 <= idx < 0x84):
            raise ValueError("idx out of range")
        off = idx * 16
        self.keyvault[off:off + 16] = key16
        if idx == 2:
            self._aes_cryptoengine1_key = bytes(key16)
    
    def _keyvault_entry(self, idx: int) -> bytes:
        if not (0 <= idx < 0x84):
            raise ValueError("idx out of range")
        off = idx * 16
        return bytes(self.keyvault[off:off + 16])
    
    # ---------- mesh / per-console key derivation ----------
    def init_mesh(self) -> None:
        fuseid = bytearray(8)
        fuseid[7] = self.g_fuse1 & 0xFF
        fuseid[6] = (self.g_fuse1 >> 8) & 0xFF
        fuseid[5] = (self.g_fuse1 >> 16) & 0xFF
        fuseid[4] = (self.g_fuse1 >> 24) & 0xFF
        fuseid[3] = self.g_fuse2 & 0xFF
        fuseid[2] = (self.g_fuse2 >> 8) & 0xFF
        fuseid[1] = (self.g_fuse2 >> 16) & 0xFF
        fuseid[0] = (self.g_fuse2 >> 24) & 0xFF
        
        subkey_1 = bytearray(16)
        subkey_2 = bytearray(16)
        for i in range(16):
            subkey_1[i] = fuseid[i % 8]
            subkey_2[i] = fuseid[i % 8]
        
        mk = self.MASTER_KEY
        for _ in range(3):
            subkey_1[:] = _aes_ecb_encrypt(mk, bytes(subkey_1))
            subkey_2[:] = _aes_ecb_decrypt(mk, bytes(subkey_2))
        
        newkey = bytes(subkey_1)
        
        self.g_mesh[:] = b"\x00" * 0x40
        cur = bytes(subkey_2)
        for i in range(3):
            for _k in range(3):
                cur = _aes_ecb_encrypt(newkey, cur)
            self.g_mesh[i * 16:(i + 1) * 16] = cur
    
    def generate_key_from_mesh(self, param: int) -> bytes:
        rounds = (param >> 1) + 1
        base = bytes(self.g_mesh[(param & 1) * 0x10:(param & 1) * 0x10 + 0x10])
        mesh_key = bytes(self.g_mesh[0x20:0x30])
        cur = base
        for _ in range(rounds):
            cur = _aes_ecb_encrypt(mesh_key, cur)
        return cur
    
    def decrypt_cmd16_private(self, enc: bytes) -> bytes:
        if len(enc) != 0x20:
            raise ValueError("enc private must be 0x20 bytes")
        genkey = self.generate_key_from_mesh(3)
        return _aes_cbc_decrypt_zero_iv(genkey, enc)
    
    def encrypt_cmd16_private(self, dec: bytes) -> bytes:
        if len(dec) != 0x20:
            raise ValueError("dec private must be 0x20 bytes")
        genkey = self.generate_key_from_mesh(3)
        return _aes_cbc_encrypt_zero_iv(genkey, dec)
    
    # ---------- init / PRNG ----------
    def init2(self, rnd_seed: bytes, fuseid_1: int, fuseid_2: int) -> int:
        if rnd_seed:
            self.PRNG_DATA[:] = _sha1(rnd_seed)
        
        temp = bytearray(0x104)
        temp[4:4 + 0x14] = self.PRNG_DATA
        
        curtime = int(time.time()) & 0xFFFFFFFF
        temp[0x18] = curtime & 0xFF
        temp[0x19] = (curtime >> 8) & 0xFF
        temp[0x1A] = (curtime >> 16) & 0xFF
        temp[0x1B] = (curtime >> 24) & 0xFF
        
        key = bytes([0] * 16)
        temp[0x1C:0x1C + 16] = key
        struct.pack_into("<I", temp, 0, 0x100)
        
        self.PRNG_DATA[:] = _sha1(bytes(temp[4:4 + 0x100]))
        
        self.g_fuse1 = fuseid_1 & 0xFFFFFFFF
        self.g_fuse2 = fuseid_2 & 0xFFFFFFFF
        self.init_mesh()
        
        self._aes_cryptoengine1_key = self._keyvault_entry(2)
        
        self.is_initialized = True
        return 0
    
    def init_default(self) -> int:
        return self.init2(b"Lazy Dev should have initialized!", 0xBABEF00D, 0xDEADBEEF)
    
    def CMD14_prng(self) -> bytes:
        if not self.is_initialized:
            raise RuntimeError("Engine not initialized (CMD14 requires init).")
    
        temp = bytearray(0x104)
        temp[4:4 + 0x14] = self.PRNG_DATA
    
        curtime = int(time.time()) & 0xFFFFFFFF
        temp[0x18] = curtime & 0xFF
        temp[0x19] = (curtime >> 8) & 0xFF
        temp[0x1A] = (curtime >> 16) & 0xFF
        temp[0x1B] = (curtime >> 24) & 0xFF
    
        key = bytes([0] * 16)
        temp[0x1C:0x1C + 16] = key
        struct.pack_into("<I", temp, 0, 0x100)
    
        digest = _sha1(bytes(temp[4:4 + 0x100]))
        self.PRNG_DATA[:] = digest
        return bytes(digest)
    
    # ---------- commands ----------
    def CMD11_sha1(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Sha1Header.parse(inbuf)
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        data = inbuf[4:4 + hdr.data_size]
        return _sha1(data)
    
    def CMD0(self, inbuf: bytes) -> Union[bytes, int]:
        # header: cmac[16], length u16 at offset 0x10, then data
        if len(inbuf) < 0x12:
            return CRYPTOENGINE_INVALID_SIZE
        
        cmac_expected = inbuf[0:16]
        length = struct.unpack_from("<H", inbuf, 0x10)[0]
        body = inbuf[0x12:0x12 + length]
        
        cmac_key = self._keyvault_entry(1)
        body_key = self._keyvault_entry(0)
        
        cmac_calc = _aes_cmac(cmac_key, body)
        if cmac_calc != cmac_expected:
            return CRYPTOENGINE_NOT_ENABLED
        
        if len(body) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        return _aes_cbc_decrypt_zero_iv(body_key, body)
    
    def CMD10_priv_sign_check(self, inbuf: bytes) -> int:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        
        h = Cmd1Header.parse(inbuf)
        if h.mode not in (CRYPTOENGINE_MODE_CMD1, CRYPTOENGINE_MODE_CMD2, CRYPTOENGINE_MODE_CMD3):
            return CRYPTOENGINE_INVALID_MODE
        if h.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        if h.mode == CRYPTOENGINE_MODE_CMD1:
            keys_plain = _aes_cbc_decrypt_zero_iv(self._aes_cryptoengine1_key, inbuf[0:32])
        elif h.mode == CRYPTOENGINE_MODE_CMD3:
            gen0 = self.generate_key_from_mesh(0)
            keys_plain = _aes_cbc_decrypt_zero_iv(gen0, inbuf[0:32])
        else:
            # CMD2 not implemented
            return CRYPTOENGINE_SIG_CHECK_INVALID
        
        cmac_key = keys_plain[16:32]
        
        cmac_header = _aes_cmac(cmac_key, inbuf[0x60:0x60 + 0x30])
        
        chk_size = _round_up(h.data_size, 16)
        cmac_data = _aes_cmac(cmac_key, inbuf[0x60:0x60 + 0x30 + chk_size + h.data_offset])
        
        if cmac_header != h.CMAC_header_hash:
            return CRYPTOENGINE_HEADER_HASH_INVALID
        if cmac_data != h.CMAC_data_hash:
            return CRYPTOENGINE_DATA_HASH_INVALID
        return CRYPTOENGINE_OPERATION_SUCCESS
    
    def CMD1(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        
        h = Cmd1Header.parse(inbuf)
        if h.mode != CRYPTOENGINE_MODE_CMD1:
            return CRYPTOENGINE_INVALID_MODE
        
        keys_plain = _aes_cbc_decrypt_zero_iv(self._aes_cryptoengine1_key, inbuf[0:32])
        aes_key = keys_plain[0:16]
        
        if h.ecdsa_hash == 1:
            eh = Cmd1EcdsaHeader.parse(inbuf)
            
            # CMD1 uses curve set "b1/N1/G1" and pub "Px1/Py1"
            ecdsa.ecdsa_set_curve(ecdsa.ec_p, ecdsa.ec_a, ecdsa.ec_b1, ecdsa.ec_N1, ecdsa.Gx1, ecdsa.Gy1)
            cryptoengine1_pub = ecdsa.Px1 + ecdsa.Py1  # 40 bytes expected
            ecdsa.ecdsa_set_pub(cryptoengine1_pub)
            
            chk_size = _round_up(eh.data_size, 16)
            
            header_hash = _sha1(inbuf[0x60:0x60 + 0x30])
            if not ecdsa.ecdsa_verify(header_hash, eh.header_sig_r, eh.header_sig_s):
                return CRYPTOENGINE_HEADER_HASH_INVALID
            
            data_hash = _sha1(inbuf[0x60:0x60 + 0x30 + chk_size + h.data_offset])
            if not ecdsa.ecdsa_verify(data_hash, eh.data_sig_r, eh.data_sig_s):
                return CRYPTOENGINE_DATA_HASH_INVALID
        else:
            ret = self.CMD10_priv_sign_check(inbuf)
            if ret != CRYPTOENGINE_OPERATION_SUCCESS:
                return ret
        
        payload_off = 0x90 + h.data_offset
        payload = inbuf[payload_off:payload_off + h.data_size]
        if len(payload) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        return _aes_cbc_decrypt_zero_iv(aes_key, payload)
    
    def CMD3(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        
        h = Cmd1Header.parse(inbuf)
        if h.mode != CRYPTOENGINE_MODE_CMD3:
            return CRYPTOENGINE_INVALID_MODE
        
        genkey0 = self.generate_key_from_mesh(0)
        keys_plain = _aes_cbc_decrypt_zero_iv(genkey0, inbuf[0:32])
        aes_key = keys_plain[0:16]
        
        if h.ecdsa_hash == 1:
            return CRYPTOENGINE_INVALID_MODE  # not supported in your C
        else:
            ret = self.CMD10_priv_sign_check(inbuf)
            if ret != CRYPTOENGINE_OPERATION_SUCCESS:
                return ret
        
        payload_off = 0x90 + h.data_offset
        payload = inbuf[payload_off:payload_off + h.data_size]
        if len(payload) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        return _aes_cbc_decrypt_zero_iv(aes_key, payload)
    
    def _get_key_4_7(self, key_type: int) -> Union[bytes, int]:
        if key_type < 0 or key_type >= 0x80:
            return CRYPTOENGINE_INVALID_SIZE
        return self._keyvault_entry(key_type + 4)
    
    def CMD4_encrypt_iv0(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Aes128CbcHeader.parse(inbuf)
        if hdr.mode != CRYPTOENGINE_MODE_ENCRYPT_CBC:
            return CRYPTOENGINE_INVALID_MODE
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        key = self._get_key_4_7(hdr.keyseed)
        if isinstance(key, int):
            return key
        
        data = inbuf[0x14:0x14 + hdr.data_size]
        if len(data) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        
        enc = _aes_cbc_encrypt_zero_iv(key, data)
        return inbuf[0:0x14] + enc
    
    def CMD5_encrypt_ivfuse(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Aes128CbcHeader.parse(inbuf)
        if hdr.mode != CRYPTOENGINE_MODE_ENCRYPT_CBC or hdr.keyseed != 0x100:
            return CRYPTOENGINE_INVALID_MODE
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        key = self.generate_key_from_mesh(1)
        data = inbuf[0x14:0x14 + hdr.data_size]
        if len(data) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        
        enc = _aes_cbc_encrypt_zero_iv(key, data)
        return inbuf[0:0x14] + enc
    
    def CMD6_encrypt_ivuser(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Aes128CbcUserHeader.parse(inbuf)
        if hdr.mode != CRYPTOENGINE_MODE_ENCRYPT_CBC or hdr.keyseed != 0x200:
            return CRYPTOENGINE_INVALID_MODE
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        key_mesh = self.generate_key_from_mesh(2)
        
        randbuf = self.CMD14_prng()  # 20 bytes
        rand16 = randbuf[0:16]
        
        keyseed = _aes_ecb_encrypt(key_mesh, rand16)
        key = _aes_ecb_encrypt(hdr.userkey, rand16)
        
        data = inbuf[0x24:0x24 + hdr.data_size]
        if len(data) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        
        enc = _aes_cbc_encrypt_zero_iv(key, data)
        
        out = bytearray()
        out += inbuf[0:0x24]
        out[0] = 5  # matches your C behavior
        out += keyseed
        out += enc
        return bytes(out)
    
    def CMD7_decrypt_iv0(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Aes128CbcHeader.parse(inbuf)
        if hdr.mode != CRYPTOENGINE_MODE_DECRYPT_CBC:
            return CRYPTOENGINE_INVALID_MODE
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        key = self._get_key_4_7(hdr.keyseed)
        if isinstance(key, int):
            return key
        
        data = inbuf[0x14:0x14 + hdr.data_size]
        if len(data) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        return _aes_cbc_decrypt_zero_iv(key, data)
    
    def CMD8_decrypt_ivfuse(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Aes128CbcHeader.parse(inbuf)
        if hdr.mode != CRYPTOENGINE_MODE_DECRYPT_CBC or hdr.keyseed != 0x100:
            return CRYPTOENGINE_INVALID_MODE
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        key = self.generate_key_from_mesh(1)
        data = inbuf[0x14:0x14 + hdr.data_size]
        if len(data) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        return _aes_cbc_decrypt_zero_iv(key, data)
    
    def CMD9_decrypt_ivuser(self, inbuf: bytes) -> Union[bytes, int]:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        hdr = Aes128CbcUserHeader.parse(inbuf)
        if hdr.mode != CRYPTOENGINE_MODE_DECRYPT_CBC or hdr.keyseed != 0x200:
            return CRYPTOENGINE_INVALID_MODE
        if hdr.data_size == 0:
            return CRYPTOENGINE_DATA_SIZE_ZERO
        
        key_mesh = self.generate_key_from_mesh(2)
        
        keyseed_enc = inbuf[0x24:0x24 + 0x10]
        if len(keyseed_enc) != 16:
            return CRYPTOENGINE_INVALID_SIZE
        
        rand16 = _aes_ecb_decrypt(key_mesh, keyseed_enc)
        key = _aes_ecb_encrypt(hdr.userkey, rand16)
        
        data_off = 0x34  # matches C
        data = inbuf[data_off:data_off + hdr.data_size]
        if len(data) % 16 != 0:
            return CRYPTOENGINE_INVALID_SIZE
        return _aes_cbc_decrypt_zero_iv(key, data)
    
    def CMD12_ecdsa_gen_keys(self) -> bytes:
        ecdsa.ecdsa_set_curve(ecdsa.ec_p, ecdsa.ec_a, ecdsa.ec_b2, ecdsa.ec_N2, ecdsa.Gx2, ecdsa.Gy2)
        
        rnd = self.CMD14_prng()
        priv = rnd[0:0x14]
        k = b"\x00" + priv  # 0x15
        
        pub = ecdsa.ec_priv_to_pub(k)  # expected 40 bytes (x||y)
        if len(pub) != 40:
            raise ValueError("ecdsa.ec_priv_to_pub(k) must return 40 bytes (x||y)")
        
        return priv + pub
    
    def CMD13_ecdsa_multiply_point(self, inbuf: bytes) -> bytes:
        if len(inbuf) < 0x3C:
            raise ValueError("CMD13 buffer too small")
        
        multiplier = inbuf[0:0x14]
        pub = inbuf[0x14:0x14 + 0x28]
        
        ecdsa.ecdsa_set_curve(ecdsa.ec_p, ecdsa.ec_a, ecdsa.ec_b2, ecdsa.ec_N2, ecdsa.Gx2, ecdsa.Gy2)
        ecdsa.ecdsa_set_pub(pub)
        
        k = b"\x00" + multiplier
        outQ = ecdsa.ec_pub_mult(k)  # expected 40 bytes
        if len(outQ) != 40:
            raise ValueError("ecdsa.ec_pub_mult(k) must return 40 bytes (x||y)")
        return outQ
    
    def CMD16_ecdsa_sign(self, inbuf: bytes) -> bytes:
        if len(inbuf) < 0x34:
            raise ValueError("CMD16 buffer too small")
        
        enc_private = inbuf[0:0x20]
        msg_hash = inbuf[0x20:0x20 + 0x14]
        
        dec_private = bytearray(self.decrypt_cmd16_private(enc_private))
        dec_private[0x14:0x20] = b"\x00" * 0x0C  # clear padding
        
        ecdsa.ecdsa_set_curve(ecdsa.ec_p, ecdsa.ec_a, ecdsa.ec_b2, ecdsa.ec_N2, ecdsa.Gx2, ecdsa.Gy2)
        ecdsa.ecdsa_set_priv(bytes(dec_private))
        
        r, s = ecdsa.ecdsa_sign(msg_hash)  # expected each 20 bytes
        if len(r) != 20 or len(s) != 20:
            raise ValueError("ecdsa.ecdsa_sign(hash) must return (r,s) each 20 bytes")
        return r + s
    
    def CMD17_ecdsa_verify(self, inbuf: bytes) -> int:
        if len(inbuf) < 0x64:
            return CRYPTOENGINE_INVALID_SIZE
        
        pub = inbuf[0:0x28]
        msg_hash = inbuf[0x28:0x28 + 0x14]
        r = inbuf[0x3C:0x3C + 0x14]
        s = inbuf[0x50:0x50 + 0x14]
        
        ecdsa.ecdsa_set_curve(ecdsa.ec_p, ecdsa.ec_a, ecdsa.ec_b2, ecdsa.ec_N2, ecdsa.Gx2, ecdsa.Gy2)
        ecdsa.ecdsa_set_pub(pub)
        
        ok = ecdsa.ecdsa_verify(msg_hash, r, s)
        return CRYPTOENGINE_OPERATION_SUCCESS if ok else CRYPTOENGINE_SIG_CHECK_INVALID
    
    def CMD18_cert_verify(self, inbuf: bytes) -> int:
        if not self.is_initialized:
            return CRYPTOENGINE_NOT_INITIALIZED
        
        if len(inbuf) < 0xB8:
            return CRYPTOENGINE_INVALID_SIZE
        
        key = self.generate_key_from_mesh(4)
        cmac_calc = _aes_cmac(key, inbuf[0:0xA8])
        if cmac_calc != inbuf[0xA8:0xB8]:
            return CRYPTOENGINE_SIG_CHECK_INVALID
        return CRYPTOENGINE_OPERATION_SUCCESS
    
    # ---------- dispatcher ----------
    def utils_buffer_copy_with_range(
        self, inbuf: bytes, cmd: int
    ) -> Tuple[int, Optional[bytes]]:
        """
        Returns (status, out_bytes_or_None).
        """
        try:
            if cmd == CRYPTOENGINE_CMD_0_DEVKIT_DECRYPT:
                out = self.CMD0(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_1_DECRYPT_VERIFY:
                out = self.CMD1(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_3_DECRYPT_VERIFY:
                out = self.CMD3(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_ENCRYPT_IV_0:
                out = self.CMD4_encrypt_iv0(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_ENCRYPT_IV_FUSE:
                out = self.CMD5_encrypt_ivfuse(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_ENCRYPT_IV_USER:
                out = self.CMD6_encrypt_ivuser(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_DECRYPT_IV_0:
                out = self.CMD7_decrypt_iv0(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)

            if cmd == CRYPTOENGINE_CMD_DECRYPT_IV_FUSE:
                out = self.CMD8_decrypt_ivfuse(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_DECRYPT_IV_USER:
                out = self.CMD9_decrypt_ivuser(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_PRIV_SIGN_CHECK:
                return (self.CMD10_priv_sign_check(inbuf), None)
            
            if cmd == CRYPTOENGINE_CMD_SHA1_HASH:
                out = self.CMD11_sha1(inbuf)
                return (out if isinstance(out, int) else CRYPTOENGINE_OPERATION_SUCCESS,
                        None if isinstance(out, int) else out)
            
            if cmd == CRYPTOENGINE_CMD_ECDSA_GEN_KEYS:
                return (CRYPTOENGINE_OPERATION_SUCCESS, self.CMD12_ecdsa_gen_keys())
            
            if cmd == CRYPTOENGINE_CMD_ECDSA_MULTIPLY_POINT:
                return (CRYPTOENGINE_OPERATION_SUCCESS, self.CMD13_ecdsa_multiply_point(inbuf))
            
            if cmd == CRYPTOENGINE_CMD_PRNG:
                return (CRYPTOENGINE_OPERATION_SUCCESS, self.CMD14_prng())
            
            if cmd == CRYPTOENGINE_CMD_ECDSA_SIGN:
                return (CRYPTOENGINE_OPERATION_SUCCESS, self.CMD16_ecdsa_sign(inbuf))
            
            if cmd == CRYPTOENGINE_CMD_ECDSA_VERIFY:
                return (self.CMD17_ecdsa_verify(inbuf), None)
            
            if cmd == CRYPTOENGINE_CMD_CERT_VERIFY:
                return (self.CMD18_cert_verify(inbuf), None)
            
            return (CRYPTOENGINE_INVALID_OPERATION, None)
        
        except Exception:
            return (CRYPTOENGINE_INVALID_OPERATION, None)
