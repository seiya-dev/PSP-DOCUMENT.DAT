from __future__ import annotations
from dataclasses import dataclass, field
import struct
import hashlib

@dataclass
class DrmContext:
    prng_data = bytearray(0x14)
    g_mesh: bytearray(0x40)
    g_fuse90: int = 0
    g_fuse94: int = 0

    def init(self) -> None:
        self.init2(b'Lazy Dev should have initialized!', 33, 0xBABEF00D, 0xDEADBEEF)
    
    def init2(self, rnd_seed: bytes, fuseid_90: int, fuseid_94: int) -> None:
        print('')
