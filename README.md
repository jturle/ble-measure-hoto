# ble-measure-hoto

BLE client for the HOTO QWCJY001 laser distance meter. Connects via Bluetooth Low Energy, authenticates using the Xiaomi Mi Standard Auth (MJAC) protocol, and receives live distance measurements.

## Device Info

- **Model**: HOTO QWCJY001
- **Platform**: xiaojiang.cc (Xiaomi IoT ecosystem)
- **BLE Services**: 0xFE95 (Xiaomi Mi Service), 0xFEB7 (measurement data)
- **Advertises as**: `xiaojiang.cc_XXX` or `stand demo`

## What This Does

1. **Scans** for the HOTO laser meter via BLE
2. **Registers** as a controller using ECDH P-256 key exchange (first time only)
3. **Logs in** via HMAC-SHA256 challenge-response (subsequent connections)
4. **Decrypts** measurement data using AES-CCM session encryption
5. **Displays** distances in meters and feet in real-time

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# First time: register with the device (wake it first!)
python connect.py --register

# Subsequent runs: auto-login and listen for measurements
python connect.py
```

See [SETUP.md](SETUP.md) for detailed instructions.

## Protocol

The device uses Xiaomi's MJAC (Mi Standard Auth) protocol:

- **Registration**: ECDH P-256 key exchange → HKDF-SHA256 key derivation → AES-CCM encrypted device ID confirmation
- **Login**: HMAC-SHA256 mutual authentication with saved token
- **Session encryption**: AES-CCM with session-derived keys (dev_key, dev_iv + counter nonce, tag_length=4)
- **Measurement format**: Property ID `0x0580`, distance as big-endian uint16 in millimeters

## Files

| File | Purpose |
|------|---------|
| `connect.py` | Main script - registration, login, and live measurement display |
| `mi_auth.py` | Cryptographic primitives (ECDH, HKDF, AES-CCM, HMAC) |
| `scan.py` | BLE device scanner |
| `explore.py` | BLE service/characteristic explorer |

## License

MIT
