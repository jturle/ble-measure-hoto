#!/usr/bin/env python3
"""Scan for the xiaojiang laser meter and other nearby BLE devices."""

import asyncio
from bleak import BleakScanner


DEVICE_NAME_HINTS = ["xiaojiang", "stand demo", "laser", "measure"]


async def scan(timeout=10):
    print(f"Scanning for BLE devices ({timeout}s)...")
    devices = await BleakScanner.discover(timeout=timeout, return_adv=True)
    print(f"\nFound {len(devices)} devices:\n")

    matches = []
    others = []

    for addr, (device, adv) in sorted(
        devices.items(), key=lambda x: x[1][1].rssi or -999, reverse=True
    ):
        name = device.name or adv.local_name or "(unknown)"
        rssi = adv.rssi
        services = adv.service_uuids or []
        is_match = any(h in name.lower() for h in DEVICE_NAME_HINTS)

        entry = {
            "name": name,
            "address": addr,
            "rssi": rssi,
            "services": services,
        }

        if is_match:
            matches.append(entry)
        elif rssi and rssi > -75:
            others.append(entry)

    if matches:
        print("=== LIKELY LASER METER ===")
        for d in matches:
            print(f"  * {d['name']:30s}  {d['address']}  RSSI: {d['rssi']} dBm")
            for s in d["services"]:
                print(f"      Service: {s}")
        print()

    print("=== OTHER STRONG DEVICES ===")
    for d in others:
        print(f"    {d['name']:30s}  {d['address']}  RSSI: {d['rssi']} dBm")
        for s in d["services"]:
            print(f"      Service: {s}")


if __name__ == "__main__":
    asyncio.run(scan())
