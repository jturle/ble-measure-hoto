#!/usr/bin/env python3
"""Connect to the xiaojiang/HOTO laser meter using Xiaomi Mi Standard Auth.

Supports both registration (first time) and login (subsequent).
After authentication, listens for measurement data on char 0xFEA8.

Usage:
    python connect.py                # Auto: login if token exists, else register
    python connect.py --register     # Force new registration
    python connect.py --duration 120 # Listen longer
"""

import argparse
import asyncio
import secrets
import struct
from datetime import datetime

from bleak import BleakClient, BleakScanner
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from mi_auth import (
    compute_login_info,
    derive_login_keys,
    derive_registration_keys,
    encrypt_did,
    gen_keypair,
    load_token,
    make_frames,
    parse_frames,
    pub_key_bytes,
    save_token,
)

DEVICE_NAME_HINTS = ["xiaojiang", "stand demo"]
KNOWN_ADDRESS = "E704A490-AEFB-1EC2-A65E-BA016A0CFB32"

# Characteristic UUIDs
CHAR_FIRMWARE = "00000004-0000-1000-8000-00805f9b34fb"
CHAR_UPNP = "00000010-0000-1000-8000-00805f9b34fb"   # Auth control
CHAR_AVDTP = "00000019-0000-1000-8000-00805f9b34fb"   # Auth data
CHAR_MEASURE = "0000fea8-0000-1000-8000-00805f9b34fb"  # Measurement notify
CHAR_COMMAND = "0000fea7-0000-1000-8000-00805f9b34fb"  # Command write

# Protocol commands
CMD_AUTH_INIT = bytes.fromhex("a4")
CMD_GET_INFO = bytes.fromhex("a2000000")
CMD_SET_KEY = bytes.fromhex("15000000")
CMD_LOGIN = bytes.fromhex("24000000")
CMD_AUTH_LOCK = bytes.fromhex("13000000")

# Queues for async notification handling
avdtp_queue = asyncio.Queue()
upnp_queue = asyncio.Queue()
measure_log = []

# Session state for measurement decryption
session_keys = None
recv_counter = 0


async def find_device(timeout=15):
    print(f"Scanning ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for addr, (device, adv) in devices.items():
        name = device.name or adv.local_name or ""
        if any(h in name.lower() for h in DEVICE_NAME_HINTS):
            print(f"Found: {name} ({addr})")
            return device
    for addr, (device, adv) in devices.items():
        if addr == KNOWN_ADDRESS:
            print(f"Found by address: ({addr})")
            return device
    return None


def on_avdtp(sender, data):
    avdtp_queue.put_nowait(data)


def on_upnp(sender, data):
    upnp_queue.put_nowait(data)


def decrypt_measurement(data):
    """Decrypt measurement notification using miauth session keys.

    Scheme: AES-CCM with dev_key, nonce=dev_iv+0000+counter_le32, tag=4, no AAD.
    Returns (plaintext, counter_used) or (None, None).
    """
    global recv_counter
    if not session_keys:
        return None, None

    payload = data[2:] if len(data) > 2 else data
    key = session_keys["dev_key"]
    iv = session_keys["dev_iv"]

    # Try counters near the expected value
    for ctr in range(max(recv_counter - 1, 0), recv_counter + 10):
        nonce = iv + b"\x00\x00\x00\x00" + ctr.to_bytes(4, "little")
        try:
            pt = AESCCM(key, tag_length=4).decrypt(nonce, payload, b"")
            recv_counter = ctr + 1
            return pt, ctr
        except Exception:
            pass

    return None, None


def parse_measurement(decrypted):
    """Parse decrypted measurement payload.

    Known formats:
      Type 0x0580 (8 bytes): distance measurement
        Bytes 4: data type (04=distance)
        Bytes 5: reserved (00)
        Bytes 6-7: distance in mm, big-endian uint16
      Type 0x0780 (10 bytes): device status/config
    """
    if len(decrypted) < 4:
        return None

    prop_id = struct.unpack(">H", decrypted[2:4])[0]

    if prop_id == 0x0580 and len(decrypted) >= 8:
        distance_mm = struct.unpack(">H", decrypted[6:8])[0]
        meters = distance_mm / 1000.0
        feet = meters * 3.28084
        return {"type": "distance", "mm": distance_mm, "m": meters, "ft": feet}

    if prop_id == 0x0780:
        return {"type": "status", "data": decrypted.hex()}

    return {"type": "unknown", "prop_id": hex(prop_id), "data": decrypted.hex()}


def on_measure(sender, data):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    seq = struct.unpack("<H", data[:2])[0] if len(data) >= 2 else 0

    decrypted, ctr = decrypt_measurement(data)

    if decrypted:
        result = parse_measurement(decrypted)
        if result and result["type"] == "distance":
            print(f"\n  >>> #{seq}: {result['m']:.3f} m / {result['ft']:.3f} ft  ({result['mm']} mm)")
            measure_log.append({"ts": ts, "seq": seq, "m": result["m"], "ft": result["ft"], "mm": result["mm"]})
        elif result and result["type"] == "status":
            print(f"  [device status: {result['data']}]")
            measure_log.append({"ts": ts, "seq": seq, "type": "status"})
        else:
            print(f"\n  >>> #{seq}: [unknown format] {decrypted.hex()}")
            measure_log.append({"ts": ts, "seq": seq, "raw": decrypted.hex()})
    else:
        print(f"\n  >>> #{seq}: [decrypt failed] {data.hex()}")
        measure_log.append({"ts": ts, "seq": seq, "raw": data.hex()})


async def recv_avdtp(timeout=5.0):
    try:
        return await asyncio.wait_for(avdtp_queue.get(), timeout=timeout)
    except asyncio.TimeoutError:
        return None


async def recv_upnp(timeout=10.0):
    try:
        return await asyncio.wait_for(upnp_queue.get(), timeout=timeout)
    except asyncio.TimeoutError:
        return None


async def capability_exchange(client):
    """Phase 0: Optional capability/greeting exchange."""
    print("\n--- Capability exchange ---")

    await client.write_gatt_char(CHAR_UPNP, CMD_AUTH_INIT, response=False)
    print("  Sent auth init (0xA4)")

    resp = await recv_avdtp()
    if resp:
        print(f"  Device capability: {resp.hex()}")

    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("0000050006f2"), response=False
    )
    print("  Sent capability reply")

    resp = await recv_avdtp()
    if resp:
        print(f"  Padded capability: {resp.hex()[:30]}... ({len(resp)} bytes)")

    padded = bytes.fromhex("00000501") + bytes([0xF2] * 240)
    await client.write_gatt_char(CHAR_AVDTP, padded, response=False)
    print("  Sent padded reply")
    await asyncio.sleep(0.3)


async def register(client):
    """Register as a new controller via ECDH P-256 key exchange."""
    print("\n=== REGISTRATION ===")

    # Step 1: Get device info
    print("\n  Step 1: Get device info")
    await client.write_gatt_char(CHAR_UPNP, CMD_GET_INFO, response=False)

    resp = await recv_avdtp()
    if not resp:
        print("  ERROR: No device info response")
        return False

    print(f"  Raw response ({len(resp)} bytes): {resp.hex()}")

    # Response format from HCI capture (28 bytes):
    # [4-byte header: 00000200] [2-byte frame: 0100] [2-byte sub: 0000]
    # [20-byte remote_info: 00 + "blt.2.1g4uhpeg8ok00"]
    # The remote_info is exactly 20 bytes starting at offset 8
    if len(resp) >= 28:
        device_id_bytes = resp[8:28]
    elif len(resp) >= 24:
        device_id_bytes = resp[4:24]
    else:
        device_id_bytes = resp[-20:]

    device_id = device_id_bytes.decode("ascii", errors="replace").rstrip("\x00")
    print(f"  Device ID: {device_id}")
    print(f"  Device ID raw (20 bytes): {device_id_bytes.hex()}")

    # Ack
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("00000300"), response=False
    )

    # Step 2: Set key mode
    print("\n  Step 2: Set key mode")
    await client.write_gatt_char(CHAR_UPNP, CMD_SET_KEY, response=False)

    # Step 3: Send register command
    print("\n  Step 3: Send register command")
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("000000030100"), response=False
    )

    resp = await recv_avdtp()
    if resp:
        print(f"  Response: {resp.hex()}")

    # Step 4: Generate ECDH keypair and send public key
    print("\n  Step 4: ECDH key exchange")
    private_key = gen_keypair()
    our_pub = pub_key_bytes(private_key)
    print(f"  Our public key ({len(our_pub)} bytes): {our_pub.hex()[:40]}...")

    # Send as single frame: 0x01 0x00 + 64-byte key (MTU=247, fits in one write)
    # This matches the HCI capture: one write of 66 bytes
    key_frame = bytes([0x01, 0x00]) + our_pub
    await client.write_gatt_char(CHAR_AVDTP, key_frame, response=False)
    print(f"  Sent public key (1 frame, {len(key_frame)} bytes)")

    # Wait for RCV_OK
    resp = await recv_avdtp()
    if resp:
        print(f"  Key accepted: {resp.hex()}")

    # Receive device public key
    # HCI capture shows: 00000203 + 64-byte key in one notification
    resp = await recv_avdtp(timeout=10)
    if not resp:
        print("  ERROR: No device public key received")
        return False

    print(f"  Device key response ({len(resp)} bytes): {resp.hex()[:40]}...")

    # Strip the 4-byte frame header (00000203)
    device_pub = resp[4:] if len(resp) > 64 else resp

    if len(device_pub) != 64:
        print(f"  WARNING: Expected 64 bytes, got {len(device_pub)}")
        # Try to collect more frames if data was split
        while len(device_pub) < 64:
            extra = await recv_avdtp(timeout=3)
            if extra:
                device_pub += parse_frames(extra)
                print(f"  Got extra frame, now {len(device_pub)} bytes")
            else:
                break
        device_pub = device_pub[:64]

    print(f"  Device public key ({len(device_pub)} bytes): {device_pub.hex()[:40]}...")

    # Ack
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("00000300"), response=False
    )

    # Step 5: Derive keys from ECDH shared secret
    print("\n  Step 5: Derive keys")
    token, bind_key, a_key = derive_registration_keys(private_key, device_pub)
    print(f"  Token (12 bytes): {token.hex()}")
    print(f"  Bind key (16 bytes): {bind_key.hex()}")

    # Step 6: Encrypt device ID and send confirmation
    print("\n  Step 6: Send encrypted device ID")
    encrypted_did = encrypt_did(a_key, device_id_bytes)
    print(f"  Encrypted DID ({len(encrypted_did)} bytes): {encrypted_did.hex()}")

    # Send DID command
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("000000000100"), response=False
    )

    resp = await recv_avdtp()
    if resp:
        print(f"  Response: {resp.hex()}")

    # Send encrypted DID as single frame (24 bytes fits in one write)
    did_frame = bytes([0x01, 0x00]) + encrypted_did
    await client.write_gatt_char(CHAR_AVDTP, did_frame, response=False)
    print(f"  Sent encrypted DID ({len(did_frame)} bytes)")

    resp = await recv_avdtp()
    if resp:
        print(f"  DID accepted: {resp.hex()}")

    # Step 7: Finalize registration
    print("\n  Step 7: Finalize registration")
    await client.write_gatt_char(CHAR_UPNP, CMD_AUTH_LOCK, response=False)

    resp = await recv_upnp()
    if resp:
        result = resp.hex()
        print(f"  Result: {result}")
        if resp == bytes.fromhex("11000000"):
            print("  REGISTRATION SUCCESS!")
            save_token(token, bind_key, device_id)
            return True
        elif resp == bytes.fromhex("12000000"):
            print("  REGISTRATION FAILED (device rejected)")
            return False

    print("  No confirmation received")
    return False


async def login(client, token):
    """Login using a saved token via HMAC-SHA256 challenge-response."""
    print("\n=== LOGIN ===")

    # Step 1: Send login command + our random key
    print("\n  Step 1: Send login command + random key")
    await client.write_gatt_char(CHAR_UPNP, CMD_LOGIN, response=False)

    app_rand = secrets.token_bytes(16)
    print(f"  App random: {app_rand.hex()}")

    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("0000000b0100"), response=False
    )

    resp = await recv_avdtp()
    if resp:
        print(f"  Response: {resp.hex()}")

    # Send our random key as single frame
    frame = bytes([0x01, 0x00]) + app_rand
    await client.write_gatt_char(CHAR_AVDTP, frame, response=False)
    print("  Sent random key")

    resp = await recv_avdtp()
    if resp:
        print(f"  Key accepted: {resp.hex()}")

    # Step 2: Receive device random key
    # Device sends header + 16-byte random in ONE notification: 0000020d + random
    print("\n  Step 2: Receive device random key")
    resp = await recv_avdtp()
    if not resp:
        print("  ERROR: No device random key")
        return False

    print(f"  Device random response ({len(resp)} bytes): {resp.hex()}")
    dev_rand = resp[4:20]
    print(f"  Device random: {dev_rand.hex()}")

    # Ack (matches HCI capture: 00000300)
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("00000300"), response=False
    )

    # Step 3: Derive login keys and compute HMACs
    print("\n  Step 3: Derive session keys")
    keys = derive_login_keys(token, app_rand, dev_rand)
    app_info, expected_dev_info = compute_login_info(keys, app_rand, dev_rand)
    print(f"  App HMAC: {app_info.hex()[:30]}...")
    print(f"  Expected device HMAC: {expected_dev_info.hex()[:30]}...")

    # Step 4: Receive and verify device HMAC
    # Device sends header + 32-byte HMAC (may be one or two notifications)
    print("\n  Step 4: Receive device HMAC")
    resp = await recv_avdtp()
    if not resp:
        print("  ERROR: No device HMAC")
        return False

    print(f"  Device HMAC response ({len(resp)} bytes): {resp.hex()}")

    # Extract HMAC: skip 4-byte header if present
    if len(resp) > 32:
        dev_info = resp[4:36]
    else:
        dev_info = resp[:32]

    # Collect more frames if HMAC was split
    while len(dev_info) < 32:
        extra = await recv_avdtp(timeout=3)
        if extra:
            dev_info += parse_frames(extra)
        else:
            break
    dev_info = dev_info[:32]

    print(f"  Device HMAC: {dev_info.hex()}")

    if dev_info == expected_dev_info:
        print("  Device HMAC VERIFIED!")
    else:
        print("  WARNING: Device HMAC mismatch!")

    # Ack (matches HCI capture: 00000300)
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("00000300"), response=False
    )

    # Step 5: Send our HMAC
    print("\n  Step 5: Send app HMAC")
    await client.write_gatt_char(
        CHAR_AVDTP, bytes.fromhex("0000000a0100"), response=False
    )

    resp = await recv_avdtp()
    if resp:
        print(f"  Response: {resp.hex()}")

    # Send HMAC as single frame
    hmac_frame = bytes([0x01, 0x00]) + app_info
    await client.write_gatt_char(CHAR_AVDTP, hmac_frame, response=False)
    print(f"  Sent HMAC (1 frame, {len(hmac_frame)} bytes)")

    resp = await recv_avdtp()
    if resp:
        print(f"  HMAC accepted: {resp.hex()}")

    # Step 6: Wait for login confirmation on UPNP channel
    print("\n  Step 6: Wait for confirmation")
    resp = await recv_upnp()
    if resp:
        result = resp.hex()
        print(f"  Result: {result}")
        if resp == bytes.fromhex("21000000"):
            print("  LOGIN SUCCESS!")
            return keys
        elif resp == bytes.fromhex("23000000"):
            print("  LOGIN FAILED!")
            return None

    print("  No confirmation received")
    return None


async def main(force_register=False, duration=60):
    device = await find_device()
    if not device:
        print("Device not found! Make sure it's awake.")
        return

    print("Connecting...")
    async with BleakClient(device) as client:
        print(f"Connected: {client.is_connected}")

        # Subscribe to notification channels
        await client.start_notify(CHAR_AVDTP, on_avdtp)
        await client.start_notify(CHAR_UPNP, on_upnp)

        # Read firmware
        fw = await client.read_gatt_char(CHAR_FIRMWARE)
        print(f"Firmware: {fw.decode('ascii', errors='replace').rstrip(chr(0))}")

        # Capability exchange
        await capability_exchange(client)

        # Enable notifications on UPNP
        # (already done via start_notify)

        # Check for saved token
        saved = load_token()

        if saved and not force_register:
            print(f"\nFound saved token for device: {saved['device_id']}")
            keys = await login(client, saved["token"])
            if keys:
                global session_keys, recv_counter
                session_keys = keys
                recv_counter = 0
                print(f"\n  Session keys:")
                print(f"    dev_key: {keys['dev_key'].hex()}")
                print(f"    app_key: {keys['app_key'].hex()}")
                print(f"    dev_iv:  {keys['dev_iv'].hex()}")
                print(f"    app_iv:  {keys['app_iv'].hex()}")
        else:
            if force_register:
                print("\nForcing new registration...")
            else:
                print("\nNo saved token - registering as new controller...")
            success = await register(client)
            if not success:
                print("Registration failed!")
                return
            # After registration, need to reconnect and login
            print("\nRegistration complete! Reconnecting to login...")
            # Disconnect and reconnect
            await asyncio.sleep(1)
            return  # User should run again to login

        if not keys:
            print("Authentication failed!")
            return

        # Subscribe to measurement notifications
        print("\nSubscribing to measurement channel (char 0xFEA8)...")
        await client.start_notify(CHAR_MEASURE, on_measure)

        # Read firmware again (as seen in capture)
        fw = await client.read_gatt_char(CHAR_FIRMWARE)

        print("\n" + "=" * 50)
        print("AUTHENTICATED - Take measurements on the device!")
        print(f"Listening for {duration} seconds (Ctrl+C to stop)...")
        print("=" * 50 + "\n")

        try:
            for i in range(duration):
                if not client.is_connected:
                    print("Disconnected!")
                    break
                await asyncio.sleep(1)
                if i > 0 and i % 15 == 0:
                    print(f"  ... {duration - i}s remaining, {len(measure_log)} measurements")
        except asyncio.CancelledError:
            pass

        distances = [m for m in measure_log if "m" in m]
        print(f"\n=== SUMMARY ===")
        print(f"Measurements: {len(distances)}")
        for m in distances:
            print(f"  #{m['seq']}  {m['m']:.3f} m  /  {m['ft']:.3f} ft  ({m['mm']} mm)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect to HOTO laser meter")
    parser.add_argument(
        "--register", action="store_true", help="Force new registration"
    )
    parser.add_argument(
        "--duration", type=int, default=120, help="Listen duration in seconds"
    )
    args = parser.parse_args()
    try:
        asyncio.run(main(force_register=args.register, duration=args.duration))
    except KeyboardInterrupt:
        print("\n\nStopped.")

