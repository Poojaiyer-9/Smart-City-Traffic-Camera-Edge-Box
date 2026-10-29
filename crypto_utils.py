"""
crypto_utils.py
===============
Shared cryptographic utilities for the Smart-City Traffic Camera Edge Box.

Covers:
  4.1 CIA  – AES + HMAC
  4.2 Confidentiality – AES-128-CBC at rest
  4.3 IBE  – identity-to-key mapping
  4.4 ABE  – CP-ABE policy checker
  4.5 PRE  – key-transformation stub
  4.6 FE   – functional encryption (count-only)
  4.7 HE   – Honey Encryption (wrong-password decoy)
  4.8 SSE  – Searchable Symmetric Encryption
  4.9 HOM  – Paillier homomorphic addition
"""

import os
import json
import hmac
import hashlib
import base64
import struct
import time
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import phe as paillier  # python-paillier

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
load_dotenv()

AES_KEY_LEN = 16          # AES-128
HMAC_KEY_LEN = 32
BLOCK_SIZE   = 16
_edge_secret = os.getenv("EDGE_SECRET", "")
if len(_edge_secret.encode()) < HMAC_KEY_LEN:
    raise RuntimeError("Set EDGE_SECRET to at least 32 characters in your local .env file.")
EDGE_SECRET = _edge_secret.encode()


# ===========================================================================
# 4.2  AES-128-CBC helpers
# ===========================================================================

def aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    AES-128-CBC encrypt.
    Returns  iv || ciphertext  (raw bytes).
    """
    iv = os.urandom(BLOCK_SIZE)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return iv + ciphertext


def aes_decrypt(token: bytes, key: bytes) -> bytes:
    """
    AES-128-CBC decrypt.  token = iv || ciphertext.
    """
    iv, ciphertext = token[:BLOCK_SIZE], token[BLOCK_SIZE:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def derive_aes_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Derive a 16-byte AES key from a password using HKDF-SHA256."""
    if salt is None:
        salt = os.urandom(16)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LEN,
        salt=salt,
        info=b"aes-key-derivation",
        backend=default_backend(),
    )
    key = hkdf.derive(password.encode())
    return key, salt


# ===========================================================================
# 4.1  HMAC-SHA256 – sign / verify
# ===========================================================================

def hmac_sign(data: bytes, key: bytes = EDGE_SECRET) -> str:
    """Return base64-encoded HMAC-SHA256 signature."""
    mac = hmac.new(key, data, hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def hmac_verify(data: bytes, signature: str, key: bytes = EDGE_SECRET) -> bool:
    """Constant-time HMAC verification."""
    expected = hmac.new(key, data, hashlib.sha256).digest()
    try:
        received = base64.b64decode(signature, validate=True)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, received)


# ===========================================================================
# 4.3  IBE – Identity-Based Encryption simulation
#       (maps an identity string → ephemeral ECC key pair)
# ===========================================================================

_IBE_REGISTRY: Dict[str, Dict[str, str]] = {}

def ibe_register_identity(identity: str) -> Dict[str, str]:
    """
    Generate and store an ECC key pair for *identity*.
    Returns the public key in PEM form.
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key  = private_key.public_key()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    _IBE_REGISTRY[identity] = {"private": priv_pem, "public": pub_pem}
    return {"identity": identity, "public_key": pub_pem}


def ibe_get_public_key(identity: str) -> Optional[str]:
    """Look up the public key PEM for a registered identity."""
    rec = _IBE_REGISTRY.get(identity)
    return rec["public"] if rec else None


def ibe_get_private_key(identity: str) -> Optional[str]:
    return _IBE_REGISTRY.get(identity, {}).get("private")


def ibe_encrypt(plaintext: bytes, identity: str) -> Optional[bytes]:
    """
    Encrypt plaintext under the public key bound to *identity*.
    Uses ECDH ephemeral + AES-128-CBC (hybrid encryption).
    """
    pub_pem = ibe_get_public_key(identity)
    if not pub_pem:
        return None
    recipient_pub = serialization.load_pem_public_key(pub_pem.encode(), default_backend())

    # Ephemeral sender key
    ephem_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephem_pub  = ephem_priv.public_key()

    shared_secret = ephem_priv.exchange(ec.ECDH(), recipient_pub)
    aes_key = hashlib.sha256(shared_secret).digest()[:AES_KEY_LEN]

    ciphertext = aes_encrypt(plaintext, aes_key)
    ephem_pub_bytes = ephem_pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    # Prefix: 4-byte length of ephemeral pub key PEM + PEM + ciphertext
    return struct.pack(">I", len(ephem_pub_bytes)) + ephem_pub_bytes + ciphertext


def ibe_decrypt(token: bytes, identity: str) -> Optional[bytes]:
    """Decrypt an IBE token using the registered private key for identity."""
    priv_pem = ibe_get_private_key(identity)
    if not priv_pem:
        return None
    priv_key = serialization.load_pem_private_key(priv_pem.encode(), None, default_backend())

    ephem_pub_len = struct.unpack(">I", token[:4])[0]
    ephem_pub_bytes = token[4: 4 + ephem_pub_len]
    ciphertext = token[4 + ephem_pub_len:]

    ephem_pub = serialization.load_pem_public_key(ephem_pub_bytes, default_backend())
    shared_secret = priv_key.exchange(ec.ECDH(), ephem_pub)
    aes_key = hashlib.sha256(shared_secret).digest()[:AES_KEY_LEN]
    return aes_decrypt(ciphertext, aes_key)


# ===========================================================================
# 4.4  CP-ABE simulation – policy checker
# ===========================================================================

def abe_check_policy(policy: str, attributes: List[str]) -> bool:
    """
    Very simple CP-ABE policy evaluator.
    Supports AND / OR of attribute tokens.
    Example policy: "TrafficOfficer AND Zone3"
    """
    attr_set = set(a.strip() for a in attributes)
    # Replace AND/OR with Python operators, then eval in a restricted namespace
    expr = policy.replace("AND", "and").replace("OR", "or")
    # Build a namespace where each token is True/False based on attr_set
    tokens = [t.strip() for t in policy.replace("AND", " ").replace("OR", " ").split()]
    namespace = {t: (t in attr_set) for t in tokens}
    try:
        return bool(eval(expr, {"__builtins__": {}}, namespace))
    except Exception:
        return False


DEFAULT_POLICY = "TrafficOfficer AND Zone3"


# ===========================================================================
# 4.5  PRE – Proxy Re-Encryption key transformation
# ===========================================================================

def pre_generate_rekey(owner_identity: str, neighbour_identity: str) -> Dict[str, str]:
    """
    Generate a re-encryption key so the edge node can transform ciphertext
    encrypted under owner_identity → decryptable by neighbour_identity.
    (Simplified: shares a freshly derived AES key wrapped for the neighbour.)
    """
    session_key = os.urandom(AES_KEY_LEN)
    nb_pub_pem  = ibe_get_public_key(neighbour_identity)
    if not nb_pub_pem:
        raise ValueError(f"Identity not registered: {neighbour_identity}")
    nb_pub = serialization.load_pem_public_key(nb_pub_pem.encode(), default_backend())
    ephem_priv = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared     = ephem_priv.exchange(ec.ECDH(), nb_pub)
    wrap_key   = hashlib.sha256(shared).digest()[:AES_KEY_LEN]
    wrapped    = aes_encrypt(session_key, wrap_key)
    ephem_pub_bytes = ephem_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "owner": owner_identity,
        "neighbour": neighbour_identity,
        "session_key_b64": base64.b64encode(session_key).decode(),
        "wrapped_key_b64": base64.b64encode(
            struct.pack(">I", len(ephem_pub_bytes)) + ephem_pub_bytes + wrapped
        ).decode(),
    }


def pre_transform_ciphertext(ciphertext_b64: str, rekey: Dict[str, str]) -> str:
    """
    Re-encrypt ciphertext using the session key so the neighbour can decrypt.
    Edge never sees plaintext – it only re-wraps the key layer.
    """
    session_key = base64.b64decode(rekey["session_key_b64"])
    ct = base64.b64decode(ciphertext_b64)
    # We treat ct as raw bytes for re-encryption
    re_encrypted = aes_encrypt(ct, session_key)
    return base64.b64encode(re_encrypted).decode()


# ===========================================================================
# 4.7  Honey Encryption – wrong password → plausible decoy
# ===========================================================================

DECOY_PLATES = [
    "KA01AB1234", "MH12CD5678", "DL3EF9012",
    "TN07GH3456", "AP09IJ7890", "GJ01KL2345",
    "RJ14MN6789", "UP32OP0123", "WB20QR4567",
    "HR26ST8901",
]

def he_encrypt(plaintext_json: str, password: str) -> bytes:
    """
    Honey Encrypt a JSON string under *password*.
    Any wrong password → decoys instead of garbage.
    """
    key, salt = derive_aes_key(password)
    ciphertext = aes_encrypt(plaintext_json.encode(), key)
    return salt + ciphertext   # prepend salt so we can re-derive


def he_decrypt(token: bytes, password: str) -> str:
    """
    Honey Decrypt: if password is wrong, returns a plausible fake plate list.
    """
    salt, ciphertext = token[:16], token[16:]
    key, _ = derive_aes_key(password, salt)
    try:
        plaintext = aes_decrypt(ciphertext, key)
        return plaintext.decode()
    except Exception:
        # Wrong password → serve decoy
        import random
        sample = random.sample(DECOY_PLATES, k=5)
        return json.dumps({"plates": sample, "note": "decoy"})


# ===========================================================================
# 4.8  SSE – Searchable Symmetric Encryption
# ===========================================================================

def sse_keygen(master_key: bytes) -> bytes:
    """Derive a deterministic SSE sub-key."""
    return hashlib.sha256(master_key + b"sse-subkey").digest()[:AES_KEY_LEN]


def sse_trapdoor(keyword: str, sse_key: bytes) -> str:
    """Generate a trapdoor for *keyword* (HMAC of keyword under sse_key)."""
    mac = hmac.new(sse_key, keyword.encode(), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode()


def sse_build_index(records: List[Dict], keywords: List[str], sse_key: bytes) -> Dict[str, List[str]]:
    """
    Build an encrypted keyword index.
    Returns {trapdoor_b64: [encrypted_record_ids]}.
    """
    index: Dict[str, List[str]] = {}
    for kw in keywords:
        td = sse_trapdoor(kw, sse_key)
        matching = []
        for rec in records:
            text = " ".join(str(v) for v in rec.values()).lower()
            if kw.lower() in text:
                enc_id = base64.b64encode(
                    aes_encrypt(str(rec.get("id", "")).encode(), sse_key)
                ).decode()
                matching.append(enc_id)
        if matching:
            index[td] = matching
    return index


def sse_search(trapdoor: str, index: Dict[str, List[str]]) -> List[str]:
    """Return encrypted record IDs matching the trapdoor."""
    return index.get(trapdoor, [])


# ===========================================================================
# 4.9  Paillier Homomorphic Encryption helpers
# ===========================================================================

def paillier_keygen(key_size: int = 1024):
    """Generate a Paillier key pair."""
    pub, priv = paillier.generate_paillier_keypair(n_length=key_size)
    return pub, priv


def paillier_encrypt(value: int, public_key) -> str:
    """Encrypt an integer with Paillier public key; returns JSON string."""
    enc = public_key.encrypt(value)
    return json.dumps({"ciphertext": str(enc.ciphertext()), "exponent": enc.exponent})


def paillier_add_encrypted(enc_jsons: List[str], public_key) -> str:
    """
    Homomorphically add a list of Paillier ciphertexts (server-side, no decryption).
    Returns the encrypted sum as JSON string.
    """
    total = public_key.encrypt(0)
    for ej in enc_jsons:
        d = json.loads(ej)
        enc_num = paillier.EncryptedNumber(public_key, int(d["ciphertext"]), int(d["exponent"]))
        total = total + enc_num
    return json.dumps({"ciphertext": str(total.ciphertext()), "exponent": total.exponent})


def paillier_decrypt(enc_json: str, private_key) -> int:
    """Decrypt a Paillier ciphertext JSON string."""
    d = json.loads(enc_json)
    pub = private_key.public_key
    enc_num = paillier.EncryptedNumber(pub, int(d["ciphertext"]), int(d["exponent"]))
    return private_key.decrypt(enc_num)


# ===========================================================================
# 4.11  Privacy helpers
# ===========================================================================

def hash_plate(plate: str) -> str:
    """One-way hash of a plate string (k-anonymity / pseudonymisation)."""
    return hashlib.sha256(plate.encode()).hexdigest()[:16]


def add_laplace_noise(value: float, sensitivity: float = 1.0, epsilon: float = 1.0) -> float:
    """Add Laplace differential-privacy noise to a numeric value."""
    import numpy as np  # type: ignore
    scale = sensitivity / epsilon
    return value + float(np.random.laplace(0, scale))


def rotate_camera_id(camera_id: str, seed: Optional[str] = None) -> str:
    """Generate a temporary pseudonymous camera ID."""
    ts  = seed or str(int(time.time() // 600))   # rotates every 10 min
    raw = hashlib.sha256(f"{camera_id}:{ts}".encode()).digest()
    return "CAM-" + base64.b32encode(raw[:8]).decode().rstrip("=")


def dummy_location() -> Dict[str, float]:
    """Inject a random dummy GPS location (privacy noise)."""
    import random
    return {
        "lat": round(12.97 + random.uniform(-0.5, 0.5), 6),
        "lon": round(77.59 + random.uniform(-0.5, 0.5), 6),
    }
