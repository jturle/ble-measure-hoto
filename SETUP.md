# Setup Guide

## Prerequisites

- Python 3.10+
- macOS, Linux, or Windows with BLE support
- HOTO QWCJY001 laser distance meter

## Installation

```bash
git clone https://github.com/jturle/ble-measure-hoto.git
cd ble-measure-hoto

python -m venv .venv
source .venv/bin/activate    # macOS/Linux
# .venv\Scripts\activate     # Windows

pip install -r requirements.txt
```

## Finding the Device

The device goes to sleep quickly. **Press the power button** to wake it before running any commands.

```bash
python scan.py
```

Look for a device named `xiaojiang.cc_XXX` or `stand demo`. If found, note the address - you can update `KNOWN_ADDRESS` in `connect.py` if yours differs.

To explore the device's BLE services and characteristics:

```bash
python explore.py
```

## Registration (First Time)

Before your computer can receive measurements, it must register as a controller with the device. The device only allows one registered controller at a time.

**Important**: If the device is paired to the HOTO/Mi Home app, unpair it first (delete it from the app).

1. Wake the device (press the button)
2. Run:

```bash
python connect.py --register
```

3. On success, a `device_token.json` file is created containing your authentication token. Keep this file safe - you'll need it for future connections.

## Taking Measurements

After registration, connect and listen for measurements:

```bash
python connect.py
```

- Wake the device first, then run the command
- Take measurements on the device by pressing the measure button
- Distances appear in real-time in meters and feet
- Press **Ctrl+C** to stop
- Default listen duration is 120 seconds (override with `--duration`)

```bash
python connect.py --duration 300   # Listen for 5 minutes
```

## Troubleshooting

### "Device not found"
- Press the device's power button to wake it - it sleeps after a few seconds of inactivity
- Make sure Bluetooth is enabled on your computer
- The device may advertise as either `xiaojiang.cc_XXX` or `stand demo`

### "Authentication failed" / LOGIN FAILED
- Your token may be invalidated. Re-register: `python connect.py --register`
- Make sure the device isn't connected to the Mi Home / HOTO app on another phone

### "Registration failed"
- Delete the device from Mi Home / HOTO app first
- Only one controller can be registered at a time
- Try power-cycling the device (hold power button)

### Decryption failures
- If measurements show `[decrypt failed]`, the session encryption counter may be out of sync
- Disconnect and reconnect: stop with Ctrl+C and run `python connect.py` again
