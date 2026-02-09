"""Xiaomi Mi Standard Auth (MJAC) - Registration and Login protocol.

Implements ECDH P-256 key exchange for registration and HMAC-SHA256 for login.
Based on miauth (github.com/dnandha/miauth) and HCI snoop log analysis.
"""

import json
import os
import secrets

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Fixed constants from the protocol
AES_CCM_NONCE = bytes([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                       0x18, 0x19, 0x1A, 0x1B])
AES_CCM_AAD = b"devID"
HKDF_REGISTER_INFO = b"mible-setup-info"
HKDF_LOGIN_INFO = b"mible-login-info"

TOKEN_FILE = os.path.join(os.path.dirname(__file__), "device_token.json")


def gen_keypair():
    """Generate an ECDH P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return private_key


def pub_key_bytes(private_key):
    """Get the 64-byte raw public key (X||Y, no 0x04 prefix)."""
    pub = private_key.public_key()
    raw = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    return raw[1:]  # strip the 0x04 uncompressed point marker


def derive_registration_keys(private_key, device_pub_bytes):
    """Perform ECDH and derive registration keys via HKDF.

    Returns (token, bind_key, a_key):
        token: 12 bytes - save for future logins
        bind_key: 16 bytes - beacon encryption key
        a_key: 16 bytes - used to encrypt device ID
    """
    device_pub = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), b"\x04" + device_pub_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), device_pub)

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=None,
        info=HKDF_REGISTER_INFO,
        backend=default_backend(),
    ).derive(shared_secret)

    token = derived[0:12]
    bind_key = derived[12:28]
    a_key = derived[28:44]
    return token, bind_key, a_key


def encrypt_did(a_key, did_bytes):
    """Encrypt the device ID using AES-CCM with fixed nonce and AAD."""
    aes = AESCCM(a_key, tag_length=4)
    return aes.encrypt(AES_CCM_NONCE, did_bytes, AES_CCM_AAD)


def derive_login_keys(token, app_rand, dev_rand):
    """Derive session keys for login from the saved token and random values.

    Returns dict with dev_key, app_key, dev_iv, app_iv.
    """
    salt = app_rand + dev_rand

    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=HKDF_LOGIN_INFO,
        backend=default_backend(),
    ).derive(token)

    return {
        "dev_key": derived[0:16],
        "app_key": derived[16:32],
        "dev_iv": derived[32:36],
        "app_iv": derived[36:40],
    }


def compute_login_info(keys, app_rand, dev_rand):
    """Compute HMAC values for login mutual authentication.

    Returns (app_info, expected_dev_info) - both 32 bytes.
    """
    salt = app_rand + dev_rand
    salt_inv = dev_rand + app_rand

    h1 = HMAC(keys["app_key"], hashes.SHA256())
    h1.update(salt)
    app_info = h1.finalize()

    h2 = HMAC(keys["dev_key"], hashes.SHA256())
    h2.update(salt_inv)
    expected_dev_info = h2.finalize()

    return app_info, expected_dev_info


def make_frames(data, chunk_size=18):
    """Split data into numbered frames for BLE writes."""
    frames = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        frame_num = i // chunk_size + 1
        frames.append(bytes([frame_num, 0x00]) + chunk)
    return frames


def parse_frames(frame_data):
    """Extract payload from a framed notification (strip 2-byte header)."""
    if len(frame_data) > 2:
        return frame_data[2:]
    return frame_data


def save_token(token, bind_key, device_id):
    """Save token and bind key to disk for future logins."""
    data = {
        "token": token.hex(),
        "bind_key": bind_key.hex(),
        "device_id": device_id,
    }
    with open(TOKEN_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"  Token saved to {TOKEN_FILE}")


def load_token():
    """Load saved token and bind key from disk."""
    if not os.path.exists(TOKEN_FILE):
        return None
    with open(TOKEN_FILE) as f:
        data = json.load(f)
    return {
        "token": bytes.fromhex(data["token"]),
        "bind_key": bytes.fromhex(data["bind_key"]),
        "device_id": data["device_id"],
    }
