#!/usr/bin/env python3
"""Connect to the xiaojiang laser meter and explore its BLE services."""

import asyncio
from bleak import BleakClient, BleakScanner


DEVICE_NAME_HINTS = ["xiaojiang", "stand demo"]
# Known address from previous scans - update if needed
KNOWN_ADDRESS = "E704A490-AEFB-1EC2-A65E-BA016A0CFB32"


async def find_device(timeout=10):
    print(f"Scanning for laser meter ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    for addr, (device, adv) in devices.items():
        name = device.name or adv.local_name or ""
        if any(h in name.lower() for h in DEVICE_NAME_HINTS):
            print(f"Found by name: {name} ({addr})")
            return device
    # Fall back to known address
    for addr, (device, adv) in devices.items():
        if addr == KNOWN_ADDRESS:
            name = device.name or adv.local_name or "(unknown)"
            print(f"Found by address: {name} ({addr})")
            return device
    return None


async def explore():
    device = await find_device()
    if not device:
        print("Device not found! Make sure it's awake and BLE is active.")
        return

    print("Connecting...")
    async with BleakClient(device) as client:
        print(f"Connected: {client.is_connected}\n")
        print("=" * 60)
        print("SERVICES & CHARACTERISTICS")
        print("=" * 60)

        for service in client.services:
            print(f"\nService: {service.uuid}")
            print(f"  Description: {service.description}")

            for char in service.characteristics:
                props = ", ".join(char.properties)
                print(f"\n  Characteristic: {char.uuid}")
                print(f"    Properties: [{props}]")
                print(f"    Handle: {char.handle}")
                print(f"    Description: {char.description}")

                for desc in char.descriptors:
                    try:
                        val = await client.read_gatt_descriptor(desc.handle)
                        print(f"    Descriptor: {desc.uuid} = {val.hex()}")
                    except Exception as e:
                        print(f"    Descriptor: {desc.uuid} (read error: {e})")

                if "read" in char.properties:
                    try:
                        val = await client.read_gatt_char(char)
                        print(f"    Value (hex): {val.hex()}")
                        print(f"    Value (raw): {val}")
                        try:
                            print(f"    Value (ascii): {val.decode('ascii', errors='replace')}")
                        except Exception:
                            pass
                    except Exception as e:
                        print(f"    Read error: {e}")

        print("\n" + "=" * 60)


if __name__ == "__main__":
    asyncio.run(explore())
