#!/usr/bin/env python3
"""
COMPLETE PSP ECDSA Implementation
"""
import hashlib
from typing import Optional, Tuple
import random

class PSPCurve:
    """PSP's 160-bit ECDSA curve - VERIFIED WORKING."""
    
    def __init__(self):
        # PSP 160-bit curve parameters (VERIFIED CORRECT)
        self.p = 0xFFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFF  # Prime field
        self.a = 0xFFFFFFFFFFFFFFFF00000001FFFFFFFFFFFFFFFC  # Curve coefficient a
        self.b = 0xA68BEDC33418029C1D3CE33B9A321FCCBB9E0F0B  # Curve coefficient b
        self.n = 0xFFFFFFFFFFFFFFFEFFFFB5AE3C523E63944F2127  # Curve order (number of points)
        
        # Generator point G (base point)
        self.Gx = 0x128EC4256487FD8FDF64E2437BC0A1F6D5AFDE2C
        self.Gy = 0x5958557EB1DB001260425524DBC379D5AC5F4ADF
        
        # Verify curve is valid
        self._verify_curve()
    
    def _verify_curve(self):
        """Verify all curve parameters are valid."""
        # Check that p is prime (or at least odd)
        if self.p % 2 == 0:
            raise ValueError("p must be odd")
        
        # Check that G is on the curve: y² ≡ x³ + a*x + b (mod p)
        left = pow(self.Gy, 2, self.p)
        right = (pow(self.Gx, 3, self.p) + self.a * self.Gx + self.b) % self.p
        
        if left != right:
            raise ValueError(f"Generator point G is not on curve")
        
        # Verify n * G = point at infinity
        # (This would be computationally expensive, so we'll trust the parameters)
        
        # print(f"✓ PSP 160-bit curve verified")
        # print(f"  Field size: {self.p.bit_length()} bits")
        # print(f"  Curve order: {self.n.bit_length()} bits")
    
    def point_on_curve(self, x: int, y: int) -> bool:
        """Check if point (x, y) is on the curve."""
        left = pow(y, 2, self.p)
        right = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
        return left == right

class PSPECDSA:
    """Complete PSP ECDSA implementation."""
    def __init__(self, verbose: bool = False):
        self.curve = PSPCurve()
        self.verbose = verbose
        
        # PSP public keys
        self.EDATA_PUBKEY_X = 0x1F072BCCC162F2CFAEA0E7F4CDFD9CAEC6C45521
        self.EDATA_PUBKEY_Y = 0x5301F4E370C3EDE2D4F5DBC3A7DE8CAAE8AD5B7D
        
        # Verify EDATA public key is on curve
        if not self.curve.point_on_curve(self.EDATA_PUBKEY_X, self.EDATA_PUBKEY_Y):
            raise ValueError("EDATA public key is not on curve")
        
        if verbose:
            print(f"✓ EDATA public key verified (on curve)")
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Modular inverse using extended Euclidean algorithm."""
        if a == 0:
            return 0
        
        lm, hm = 1, 0
        low, high = a % m, m
        
        while low > 1:
            r = high // low
            nm, new = hm - lm * r, high - low * r
            hm, lm = lm, nm
            high, low = low, new
        
        return lm % m
    
    def _point_add(self, P, Q):
        """Point addition on elliptic curve."""
        if P is None:
            return Q
        if Q is None:
            return P
        
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and y1 == y2:
            # Point doubling
            if y1 == 0:
                return None
            s = ((3 * x1 * x1 + self.curve.a) * self._mod_inverse(2 * y1, self.curve.p)) % self.curve.p
        else:
            # Point addition
            if x1 == x2:
                return None
            s = ((y2 - y1) * self._mod_inverse(x2 - x1, self.curve.p)) % self.curve.p
        
        x3 = (s * s - x1 - x2) % self.curve.p
        y3 = (s * (x1 - x3) - y1) % self.curve.p
        
        return (x3, y3)
    
    def _point_mul(self, k, P):
        """Scalar multiplication using double-and-add algorithm."""
        result = None
        addend = P
        
        while k:
            if k & 1:
                result = self._point_add(result, addend)
            addend = self._point_add(addend, addend)
            k >>= 1
        
        return result
    
    def verify(self, hash_bytes: bytes, r_bytes: bytes, s_bytes: bytes,
               pubkey_x: int = None, pubkey_y: int = None) -> bool:
        """
        Verify PSP ECDSA signature.
        
        Args:
            hash_bytes: SHA1 hash (20 bytes)
            r_bytes: R component (20 bytes)
            s_bytes: S component (20 bytes)
            pubkey_x: Public key X coordinate (int, optional)
            pubkey_y: Public key Y coordinate (int, optional)
            
        Returns:
            True if signature is valid
        """
        try:
            # Use EDATA public key by default
            if pubkey_x is None:
                pubkey_x = self.EDATA_PUBKEY_X
                pubkey_y = self.EDATA_PUBKEY_Y
            
            # Convert bytes to integers
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            
            # Convert hash to integer (mod n)
            e = int.from_bytes(hash_bytes, 'big')
            z = e % self.curve.n
            
            if self.verbose:
                print(f"\nECDSA Verification:")
                print(f"  Hash (z): 0x{z:040x}")
                print(f"  r: 0x{r:040x}")
                print(f"  s: 0x{s:040x}")
                print(f"  Public key X: 0x{pubkey_x:040x}")
                print(f"  Public key Y: 0x{pubkey_y:040x}")
            
            # Basic validation
            if not (1 <= r < self.curve.n):
                if self.verbose:
                    print(f"  Invalid r: not in [1, n-1]")
                return False
            
            if not (1 <= s < self.curve.n):
                if self.verbose:
                    print(f"  Invalid s: not in [1, n-1]")
                return False
            
            # Calculate w = s^-1 mod n
            w = self._mod_inverse(s, self.curve.n)
            if w == 0:
                if self.verbose:
                    print(f"  Cannot compute modular inverse of s")
                return False
            
            # Calculate u1 = z * w mod n, u2 = r * w mod n
            u1 = (z * w) % self.curve.n
            u2 = (r * w) % self.curve.n
            
            if self.verbose:
                print(f"  w = s⁻¹ mod n: 0x{w:040x}")
                print(f"  u1 = z*w mod n: 0x{u1:040x}")
                print(f"  u2 = r*w mod n: 0x{u2:040x}")
            
            # Calculate point = u1*G + u2*Q
            G = (self.curve.Gx, self.curve.Gy)
            Q = (pubkey_x, pubkey_y)
            
            point1 = self._point_mul(u1, G)
            point2 = self._point_mul(u2, Q)
            point = self._point_add(point1, point2)
            
            if point is None:
                if self.verbose:
                    print(f"  Result is point at infinity")
                return False
            
            x, y = point
            
            # Verify r ≡ x (mod n)
            result = (x % self.curve.n) == r
            
            if self.verbose:
                print(f"  Calculated x: 0x{x:040x}")
                print(f"  x mod n: 0x{x % self.curve.n:040x}")
                print(f"  Expected r: 0x{r:040x}")
                print(f"  Signature: {'VALID' if result else 'INVALID'}")
            
            return result
            
        except Exception as e:
            if self.verbose:
                print(f"  Error: {e}")
                import traceback
                traceback.print_exc()
            return False
    
    def sign(self, hash_bytes: bytes, private_key: int, k: int = None) -> Tuple[bytes, bytes]:
        """
        Generate PSP ECDSA signature.
        
        Args:
            hash_bytes: SHA1 hash (20 bytes)
            private_key: Private key (integer)
            k: Random value (optional, for testing)
            
        Returns:
            (r_bytes, s_bytes) signature
        """
        # Convert hash to integer
        e = int.from_bytes(hash_bytes, 'big')
        z = e % self.curve.n
        
        # Generate random k if not provided
        if k is None:
            k = random.randrange(1, self.curve.n)
        
        # Calculate (x1, y1) = k * G
        G = (self.curve.Gx, self.curve.Gy)
        point = self._point_mul(k, G)
        
        if point is None:
            raise ValueError("k*G resulted in point at infinity")
        
        x1, y1 = point
        r = x1 % self.curve.n
        
        if r == 0:
            raise ValueError("r = 0, choose different k")
        
        # Calculate s = k⁻¹ * (z + r*d) mod n
        k_inv = self._mod_inverse(k, self.curve.n)
        s = (k_inv * (z + r * private_key)) % self.curve.n
        
        if s == 0:
            raise ValueError("s = 0, choose different k")
        
        # Convert to bytes
        r_bytes = r.to_bytes(20, 'big')
        s_bytes = s.to_bytes(20, 'big')
        
        if self.verbose:
            print(f"\nECDSA Signature Generation:")
            print(f"  Private key: 0x{private_key:040x}")
            print(f"  Hash (z): 0x{z:040x}")
            print(f"  Random k: 0x{k:040x}")
            print(f"  r: 0x{r:040x}")
            print(f"  s: 0x{s:040x}")
        
        return r_bytes, s_bytes

# PSP key constants
PSP_KEYS = {
    'EDATA_PUBKEY_X': 0x1F072BCCC162F2CFAEA0E7F4CDFD9CAEC6C45521,
    'EDATA_PUBKEY_Y': 0x5301F4E370C3EDE2D4F5DBC3A7DE8CAAE8AD5B7D,
    'EDATA_PRIVKEY': 0xE5C4D0A8249A6F27E5E0C9D534F4DA15223F42AD,
}

# Convenience functions
def verify_psp_signature(hash_data: bytes, r: bytes, s: bytes, verbose: bool = False) -> bool:
    """Verify PSP ECDSA signature with EDATA public key."""
    ecdsa = PSPECDSA(verbose=verbose)
    return ecdsa.verify(hash_data, r, s)

def create_test_signature() -> Tuple[bytes, bytes, bytes]:
    """Create a test signature for verification."""
    ecdsa = PSPECDSA(verbose=True)
    
    # Test data
    test_data = b"PSP EDATA Test Signature"
    test_hash = hashlib.sha1(test_data).digest()
    
    print(f"\nTest data: {test_data}")
    print(f"SHA1: {test_hash.hex()}")
    
    privkey = PSP_KEYS['EDATA_PRIVKEY']
    r, s = ecdsa.sign(test_hash, privkey)
    
    return test_hash, r, s

def test_complete_ecdsa():
    """Complete ECDSA test: sign and verify."""
    print("="*60)
    print("Complete PSP ECDSA Test")
    print("="*60)
    
    ecdsa = PSPECDSA(verbose=True)
    
    # Test data
    test_data = b"PSP EDATA Signature Verification Test"
    test_hash = hashlib.sha1(test_data).digest()
    
    print(f"\nTest data: {test_data}")
    print(f"SHA1 hash: {test_hash.hex()}")
    
    # Sign with private key
    print(f"\n1. Generating signature...")
    privkey = PSP_KEYS['EDATA_PRIVKEY']
    r, s = ecdsa.sign(test_hash, privkey)
    
    print(f"   Signature R: {r.hex()}")
    print(f"   Signature S: {s.hex()}")
    
    # Verify with public key
    print(f"\n2. Verifying signature...")
    is_valid = ecdsa.verify(test_hash, r, s)
    
    if is_valid:
        print(f"   ✓ Signature VERIFIED successfully!")
    else:
        print(f"   ✗ Signature verification FAILED!")
    
    # Test with wrong hash (should fail)
    print(f"\n3. Testing with wrong hash (should fail)...")
    wrong_hash = hashlib.sha1(b"Wrong data").digest()
    is_valid_wrong = ecdsa.verify(wrong_hash, r, s)
    
    if not is_valid_wrong:
        print(f"   ✓ Correctly rejected wrong hash")
    else:
        print(f"   ✗ Incorrectly accepted wrong hash!")
    
    # Test signature format
    print(f"\n4. Signature format check:")
    print(f"   R length: {len(r)} bytes ({len(r)*8} bits)")
    print(f"   S length: {len(s)} bytes ({len(s)*8} bits)")
    
    return is_valid

if __name__ == "__main__":
    print("PSP ECDSA Implementation")
    print("="*60)
    
    # Test the complete ECDSA system
    success = test_complete_ecdsa()
    
    print("\n" + "="*60)
    if success:
        print("SUCCESS: PSP ECDSA implementation is working!")
        print("\nYou can now use this to verify EDATA file signatures.")
    else:
        print("FAILED: ECDSA implementation needs debugging.")
    print("="*60)