from datetime import datetime, timezone
from PGPy.pgpy import PGPKey, PGPUID
from PGPy.pgpy.constants import (
    PubKeyAlgorithm,
    KeyFlags,
    EllipticCurveOID,
    HashAlgorithm,
    SymmetricKeyAlgorithm,
    CompressionAlgorithm,
)
from PGPy.pgpy.packet.fields import ECPoint

KEY_ALGORITHM = PubKeyAlgorithm.ECDSA

# secp256r1
# KEY_CURVE = EllipticCurveOID.NIST_P256

KEY_CURVE = EllipticCurveOID.SECP256K1

KEY_CREATION_TIME = datetime(2009, 1, 3, 18, 5, 5, tzinfo=timezone.utc)
UID_PARAMS = {
    "usage": {KeyFlags.Sign},
    "hashes": [HashAlgorithm.SHA256],
    "ciphers": [SymmetricKeyAlgorithm.AES256],
    "compression": [CompressionAlgorithm.ZLIB],
    "created": KEY_CREATION_TIME,
}


class KeyManager:
    """Class to manage the creation and injection of keys"""

    def __init__(self):
        self.uid = None
        self.key = None
        self.cert_sig = None

    def load_key(self, pubkey):
        """Create a new key pair and inject a pubkey point from an existing key"""
        key = PGPKey.new(KEY_ALGORITHM, KEY_CURVE, created=KEY_CREATION_TIME)
        key._key.keymaterial.p = pubkey._key.keymaterial.p
        key.add_uid(
            pubkey.userids[0],
            selfsign=False,
            usage={KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
        )
        return key

    def _reverse64(self, b: bytes) -> bytes:
        """Converts (a,b) from little (secp256k1) to big endian to be consistent with PGPy"""
        if len(b) != 64:
            raise ValueError(f"Expected 64 bytes for reversal, got {len(b)}")
        x = b[:32]
        y = b[32:]
        return x[::-1] + y[::-1]

    def create_key(
        self,
        name: str,
        email: str,
        ext_key_material: bytes,
        curve: EllipticCurveOID = KEY_CURVE,
    ) -> bytes:
        """Create a new key pair and inject a pubkey point from an existing key"""

        # Validate key length
        if len(ext_key_material) != 64:
            raise ValueError(
                f"Expected 64 bytes key material, got {len(ext_key_material)} bytes"
            )

        # Process key material according to curve requirements
        if curve == EllipticCurveOID.SECP256K1:
            # SECP256K1 needs conversion to big endian
            ext_key_material = self._reverse64(ext_key_material)
        elif curve == EllipticCurveOID.NIST_P256:
            pass  # No conversion needed
        else:
            raise ValueError(f"Unsupported curve: {curve}")

        # Create key with processed material
        self.key = PGPKey.new(KEY_ALGORITHM, curve, created=KEY_CREATION_TIME)
        original_key_point = self.key._key.keymaterial.p.to_mpibytes()
        injected_key_point = original_key_point[:3] + ext_key_material
        self.key._key.keymaterial.p = ECPoint(injected_key_point)
        self.uid = PGPUID.new(name, email=email)
        sig_data = self.key.add_uid(self.uid, extract=True, **UID_PARAMS)
        return sig_data

    def inject_key(self, injected_cert: bytes) -> None:
        """Inject a pubkey point from an existing key"""
        self.cert_sig = self.key.add_uid(self.uid, inject=injected_cert, **UID_PARAMS)
