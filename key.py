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

    def _reverse64(self, b):
        """Converts (a,b) from little (secp256k1) to big endian to be consistent with PGPy"""
        x = b[:32]
        y = b[32:]
        return x[::-1] + y[::-1]

    def create_key(self, name, email, hex_key_material):
        """Create a new key pair and inject a pubkey point from an existing key"""
        # secp256r1
        # ext_key_material = bytes.fromhex(hex_key_material)

        # secp256k1
        ext_key_material = self._reverse64(hex_key_material)

        self.key = PGPKey.new(KEY_ALGORITHM, KEY_CURVE, created=KEY_CREATION_TIME)
        original_key_point = self.key._key.keymaterial.p.to_mpibytes()
        injected_key_point = original_key_point[:3] + ext_key_material
        self.key._key.keymaterial.p = ECPoint(injected_key_point)
        self.uid = PGPUID.new(name, email=email)
        sig_data = self.key.add_uid(
            self.uid,
            extract=True,
            usage={KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            created=KEY_CREATION_TIME,
        )
        return sig_data

    def inject_key(self, inject, ext_sig_data):
        """Inject a pubkey point from an existing key"""
        self.cert_sig = self.key.add_uid(
            self.uid,
            inject=inject,
            ext_sig_data=ext_sig_data,
            usage={KeyFlags.Sign},
            hashes=[HashAlgorithm.SHA256],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB],
            created=KEY_CREATION_TIME,
        )
