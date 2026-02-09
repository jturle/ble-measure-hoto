# BLE Measure HOTO (TypeScript)

Connect to the xiaojiang/HOTO laser distance meter via Bluetooth Low Energy using the Xiaomi Mi Standard Auth protocol.

## Requirements

- Node.js 18+
- macOS (with Bluetooth permissions) or Linux

## Install

```bash
npm install
```

## Usage

### Scan for devices

```bash
npm run scan
```

### Connect and authenticate

```bash
npm run dev                    # Auto: login if token exists, else register
npm run dev -- --register      # Force new registration
npm run dev -- --duration 120  # Listen for 120 seconds
```

On first run, the device will register as a new controller. Press the button on the device when prompted. After registration, the token is saved to `device_token.json`.

On subsequent runs, login uses the saved token.

### Build (TypeScript → JavaScript)

```bash
npm run build
npm start
```

## How It Works

1. **Scan** - Find the HOTO device by name (`xiaojiang` / `stand demo`) or known address
2. **Connect** - Establish BLE connection
3. **Capability Exchange** - Initial handshake with the device
4. **Register or Login**:
   - **Register**: ECDH P-256 key exchange, derive token/bind_key, encrypt device ID
   - **Login**: HMAC-SHA256 challenge-response with saved token
5. **Receive Measurements** - Subscribe to notification characteristic `0xFEA8`, decrypt with AES-CCM

## Protocol Notes

The Xiaomi Mi Standard Auth (MJAC) protocol uses:

- **Registration**: ECDH P-256 → HKDF-SHA256 → AES-CCM for device ID
- **Login**: Random challenge → HKDF-SHA256 → HMAC-SHA256 mutual auth
- **Measurements**: AES-128-CCM with session keys, 4-byte tag, rolling counter

## Files

- `src/connect.ts` - Main connection logic
- `src/mi-auth.ts` - Cryptographic primitives
- `src/scan.ts` - BLE scanner utility

## License

MIT
