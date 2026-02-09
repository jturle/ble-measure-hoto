#!/usr/bin/env tsx
/**
 * Connect to the xiaojiang/HOTO laser meter using Xiaomi Mi Standard Auth.
 *
 * Supports both registration (first time) and login (subsequent).
 * After authentication, listens for measurement data on char 0xFEA8.
 *
 * Usage:
 *   npx tsx src/connect.ts                # Auto: login if token exists, else register
 *   npx tsx src/connect.ts --register     # Force new registration
 *   npx tsx src/connect.ts --duration 120 # Listen longer
 */

import noble, { Characteristic, Peripheral } from '@abandonware/noble';
import {
  computeLoginInfo,
  decryptMeasurement,
  deriveLoginKeys,
  deriveRegistrationKeys,
  encryptDid,
  genKeypair,
  loadToken,
  parseFrames,
  pubKeyBytes,
  saveToken,
  secureRandomBytes,
  SessionKeys,
} from './mi-auth.js';

// Parse CLI args
const args = process.argv.slice(2);
const forceRegister = args.includes('--register');
const durationIdx = args.indexOf('--duration');
const duration = durationIdx >= 0 ? parseInt(args[durationIdx + 1], 10) : 120;

const DEVICE_NAME_HINTS = ['xiaojiang', 'stand demo'];
const KNOWN_ADDRESS = 'e704a490-aefb-1ec2-a65e-ba016a0cfb32';

// Characteristic UUIDs - noble uses short form for standard BT UUIDs
const CHAR_FIRMWARE = '0004';
const CHAR_UPNP = '0010';     // Auth control
const CHAR_AVDTP = '0019';    // Auth data
const CHAR_MEASURE = '0000fea800001000800000805f9b34fb'; // Measurement notify
const CHAR_COMMAND = '0000fea700001000800000805f9b34fb'; // Command write

// Protocol commands
const CMD_AUTH_INIT = Buffer.from('a4', 'hex');
const CMD_GET_INFO = Buffer.from('a2000000', 'hex');
const CMD_SET_KEY = Buffer.from('15000000', 'hex');
const CMD_LOGIN = Buffer.from('24000000', 'hex');
const CMD_AUTH_LOCK = Buffer.from('13000000', 'hex');

// Queues for async notification handling
let avdtpQueue: Buffer[] = [];
let upnpQueue: Buffer[] = [];
const measureLog: Array<Record<string, unknown>> = [];

// Session state for measurement decryption
let sessionKeys: SessionKeys | null = null;
let recvCounter = 0;

// Characteristics cache
let charFirmware: Characteristic | null = null;
let charUpnp: Characteristic | null = null;
let charAvdtp: Characteristic | null = null;
let charMeasure: Characteristic | null = null;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForQueue(queue: Buffer[], timeoutMs = 5000): Promise<Buffer | null> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (queue.length > 0) {
      return queue.shift()!;
    }
    await sleep(50);
  }
  return null;
}

async function recvAvdtp(timeout = 5000): Promise<Buffer | null> {
  return waitForQueue(avdtpQueue, timeout);
}

async function recvUpnp(timeout = 10000): Promise<Buffer | null> {
  return waitForQueue(upnpQueue, timeout);
}

function parseMeasurement(decrypted: Buffer): Record<string, unknown> | null {
  if (decrypted.length < 4) return null;

  const propId = decrypted.readUInt16BE(2);

  if (propId === 0x0580 && decrypted.length >= 8) {
    const distanceMm = decrypted.readUInt16BE(6);
    const meters = distanceMm / 1000.0;
    const feet = meters * 3.28084;
    return { type: 'distance', mm: distanceMm, m: meters, ft: feet };
  }

  if (propId === 0x0780) {
    return { type: 'status', data: decrypted.toString('hex') };
  }

  return { type: 'unknown', propId: `0x${propId.toString(16)}`, data: decrypted.toString('hex') };
}

function onMeasure(data: Buffer) {
  const ts = new Date().toISOString().slice(11, 23);
  const seq = data.length >= 2 ? data.readUInt16LE(0) : 0;

  if (!sessionKeys) {
    console.log(`\n  >>> #${seq}: [no session keys] ${data.toString('hex')}`);
    measureLog.push({ ts, seq, raw: data.toString('hex') });
    return;
  }

  const result = decryptMeasurement(data, sessionKeys, recvCounter);

  if (result) {
    recvCounter = result.counter;
    const parsed = parseMeasurement(result.plaintext);

    if (parsed?.type === 'distance') {
      const m = parsed.m as number;
      const ft = parsed.ft as number;
      const mm = parsed.mm as number;
      console.log(`\n  >>> #${seq}: ${m.toFixed(3)} m / ${ft.toFixed(3)} ft  (${mm} mm)`);
      measureLog.push({ ts, seq, m, ft, mm });
    } else if (parsed?.type === 'status') {
      console.log(`  [device status: ${parsed.data}]`);
      measureLog.push({ ts, seq, type: 'status' });
    } else {
      console.log(`\n  >>> #${seq}: [unknown format] ${result.plaintext.toString('hex')}`);
      measureLog.push({ ts, seq, raw: result.plaintext.toString('hex') });
    }
  } else {
    console.log(`\n  >>> #${seq}: [decrypt failed] ${data.toString('hex')}`);
    measureLog.push({ ts, seq, raw: data.toString('hex') });
  }
}

async function findDevice(timeout = 15000): Promise<Peripheral | null> {
  console.log(`Scanning (${timeout / 1000}s)...`);

  return new Promise((resolve) => {
    let found: Peripheral | null = null;
    const timeoutId = setTimeout(() => {
      noble.stopScanning();
      resolve(found);
    }, timeout);

    noble.on('discover', (peripheral) => {
      const name = peripheral.advertisement.localName || '';
      const addr = peripheral.address?.toLowerCase() || peripheral.id?.toLowerCase() || '';

      if (DEVICE_NAME_HINTS.some((h) => name.toLowerCase().includes(h))) {
        console.log(`Found: ${name} (${addr})`);
        clearTimeout(timeoutId);
        noble.stopScanning();
        found = peripheral;
        resolve(found);
        return;
      }

      if (addr === KNOWN_ADDRESS || peripheral.id?.toLowerCase() === KNOWN_ADDRESS) {
        console.log(`Found by address: (${addr})`);
        clearTimeout(timeoutId);
        noble.stopScanning();
        found = peripheral;
        resolve(found);
      }
    });

    noble.startScanning([], false);
  });
}

async function discoverCharacteristics(peripheral: Peripheral): Promise<boolean> {
  return new Promise((resolve) => {
    peripheral.discoverAllServicesAndCharacteristics((err, services, characteristics) => {
      if (err) {
        console.error('Error discovering characteristics:', err);
        resolve(false);
        return;
      }

      for (const char of characteristics || []) {
        const uuid = char.uuid.toLowerCase();
        if (uuid === CHAR_FIRMWARE) {
          charFirmware = char;
        } else if (uuid === CHAR_UPNP) {
          charUpnp = char;
        } else if (uuid === CHAR_AVDTP) {
          charAvdtp = char;
        } else if (uuid === CHAR_MEASURE) {
          charMeasure = char;
        }
      }
      resolve(!!(charFirmware && charUpnp && charAvdtp && charMeasure));
    });
  });
}

async function writeChar(char: Characteristic, data: Buffer, withResponse = false): Promise<void> {
  return new Promise((resolve, reject) => {
    char.write(data, !withResponse, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function readChar(char: Characteristic): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    char.read((err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

async function subscribeChar(char: Characteristic, handler: (data: Buffer) => void): Promise<void> {
  return new Promise((resolve, reject) => {
    char.on('data', handler);
    char.subscribe((err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

async function capabilityExchange(): Promise<void> {
  console.log('\n--- Capability exchange ---');

  await writeChar(charUpnp!, CMD_AUTH_INIT);
  console.log('  Sent auth init (0xA4)');

  const resp = await recvAvdtp();
  if (resp) {
    console.log(`  Device capability: ${resp.toString('hex')}`);
  }

  await writeChar(charAvdtp!, Buffer.from('0000050006f2', 'hex'));
  console.log('  Sent capability reply');

  const resp2 = await recvAvdtp();
  if (resp2) {
    console.log(`  Padded capability: ${resp2.toString('hex').slice(0, 30)}... (${resp2.length} bytes)`);
  }

  const padded = Buffer.concat([Buffer.from('00000501', 'hex'), Buffer.alloc(240, 0xf2)]);
  await writeChar(charAvdtp!, padded);
  console.log('  Sent padded reply');
  await sleep(300);
}

async function register(): Promise<boolean> {
  console.log('\n=== REGISTRATION ===');

  // Step 1: Get device info
  console.log('\n  Step 1: Get device info');
  await writeChar(charUpnp!, CMD_GET_INFO);

  const resp = await recvAvdtp();
  if (!resp) {
    console.log('  ERROR: No device info response');
    return false;
  }

  console.log(`  Raw response (${resp.length} bytes): ${resp.toString('hex')}`);

  let deviceIdBytes: Buffer;
  if (resp.length >= 28) {
    deviceIdBytes = resp.subarray(8, 28);
  } else if (resp.length >= 24) {
    deviceIdBytes = resp.subarray(4, 24);
  } else {
    deviceIdBytes = resp.subarray(-20);
  }

  const deviceId = deviceIdBytes.toString('ascii').replace(/\0/g, '');
  console.log(`  Device ID: ${deviceId}`);
  console.log(`  Device ID raw (20 bytes): ${deviceIdBytes.toString('hex')}`);

  // Ack
  await writeChar(charAvdtp!, Buffer.from('00000300', 'hex'));

  // Step 2: Set key mode
  console.log('\n  Step 2: Set key mode');
  await writeChar(charUpnp!, CMD_SET_KEY);

  // Step 3: Send register command
  console.log('\n  Step 3: Send register command');
  await writeChar(charAvdtp!, Buffer.from('000000030100', 'hex'));

  const resp2 = await recvAvdtp();
  if (resp2) {
    console.log(`  Response: ${resp2.toString('hex')}`);
  }

  // Step 4: Generate ECDH keypair and send public key
  console.log('\n  Step 4: ECDH key exchange');
  const ecdh = genKeypair();
  const ourPub = pubKeyBytes(ecdh);
  console.log(`  Our public key (${ourPub.length} bytes): ${ourPub.toString('hex').slice(0, 40)}...`);

  const keyFrame = Buffer.concat([Buffer.from([0x01, 0x00]), ourPub]);
  await writeChar(charAvdtp!, keyFrame);
  console.log(`  Sent public key (1 frame, ${keyFrame.length} bytes)`);

  // Wait for RCV_OK
  const resp3 = await recvAvdtp();
  if (resp3) {
    console.log(`  Key accepted: ${resp3.toString('hex')}`);
  }

  // Receive device public key
  let resp4 = await recvAvdtp(10000);
  if (!resp4) {
    console.log('  ERROR: No device public key received');
    return false;
  }

  console.log(`  Device key response (${resp4.length} bytes): ${resp4.toString('hex').slice(0, 40)}...`);

  let devicePub = resp4.length > 64 ? resp4.subarray(4) : resp4;

  if (devicePub.length < 64) {
    console.log(`  WARNING: Expected 64 bytes, got ${devicePub.length}`);
    while (devicePub.length < 64) {
      const extra = await recvAvdtp(3000);
      if (extra) {
        devicePub = Buffer.concat([devicePub, parseFrames(extra)]);
        console.log(`  Got extra frame, now ${devicePub.length} bytes`);
      } else {
        break;
      }
    }
  }
  devicePub = devicePub.subarray(0, 64);
  console.log(`  Device public key (${devicePub.length} bytes): ${devicePub.toString('hex').slice(0, 40)}...`);

  // Ack
  await writeChar(charAvdtp!, Buffer.from('00000300', 'hex'));

  // Step 5: Derive keys from ECDH shared secret
  console.log('\n  Step 5: Derive keys');
  const { token, bindKey, aKey } = deriveRegistrationKeys(ecdh, devicePub);
  console.log(`  Token (12 bytes): ${token.toString('hex')}`);
  console.log(`  Bind key (16 bytes): ${bindKey.toString('hex')}`);

  // Step 6: Encrypt device ID and send confirmation
  console.log('\n  Step 6: Send encrypted device ID');
  const encryptedDid = encryptDid(aKey, deviceIdBytes);
  console.log(`  Encrypted DID (${encryptedDid.length} bytes): ${encryptedDid.toString('hex')}`);

  await writeChar(charAvdtp!, Buffer.from('000000000100', 'hex'));

  const resp5 = await recvAvdtp();
  if (resp5) {
    console.log(`  Response: ${resp5.toString('hex')}`);
  }

  const didFrame = Buffer.concat([Buffer.from([0x01, 0x00]), encryptedDid]);
  await writeChar(charAvdtp!, didFrame);
  console.log(`  Sent encrypted DID (${didFrame.length} bytes)`);

  const resp6 = await recvAvdtp();
  if (resp6) {
    console.log(`  DID accepted: ${resp6.toString('hex')}`);
  }

  // Step 7: Finalize registration
  console.log('\n  Step 7: Finalize registration');
  await writeChar(charUpnp!, CMD_AUTH_LOCK);

  const resp7 = await recvUpnp();
  if (resp7) {
    console.log(`  Result: ${resp7.toString('hex')}`);
    if (resp7.equals(Buffer.from('11000000', 'hex'))) {
      console.log('  REGISTRATION SUCCESS!');
      saveToken(token, bindKey, deviceId);
      return true;
    } else if (resp7.equals(Buffer.from('12000000', 'hex'))) {
      console.log('  REGISTRATION FAILED (device rejected)');
      return false;
    }
  }

  console.log('  No confirmation received');
  return false;
}

async function login(token: Buffer): Promise<SessionKeys | null> {
  console.log('\n=== LOGIN ===');

  // Step 1: Send login command + our random key
  console.log('\n  Step 1: Send login command + random key');
  await writeChar(charUpnp!, CMD_LOGIN);

  const appRand = secureRandomBytes(16);
  console.log(`  App random: ${appRand.toString('hex')}`);

  await writeChar(charAvdtp!, Buffer.from('0000000b0100', 'hex'));

  const resp = await recvAvdtp();
  if (resp) {
    console.log(`  Response: ${resp.toString('hex')}`);
  }

  const frame = Buffer.concat([Buffer.from([0x01, 0x00]), appRand]);
  await writeChar(charAvdtp!, frame);
  console.log('  Sent random key');

  const resp2 = await recvAvdtp();
  if (resp2) {
    console.log(`  Key accepted: ${resp2.toString('hex')}`);
  }

  // Step 2: Receive device random key
  console.log('\n  Step 2: Receive device random key');
  const resp3 = await recvAvdtp();
  if (!resp3) {
    console.log('  ERROR: No device random key');
    return null;
  }

  console.log(`  Device random response (${resp3.length} bytes): ${resp3.toString('hex')}`);
  const devRand = resp3.subarray(4, 20);
  console.log(`  Device random: ${devRand.toString('hex')}`);

  // Ack
  await writeChar(charAvdtp!, Buffer.from('00000300', 'hex'));

  // Step 3: Derive login keys and compute HMACs
  console.log('\n  Step 3: Derive session keys');
  const keys = deriveLoginKeys(token, appRand, devRand);
  const { appInfo, expectedDevInfo } = computeLoginInfo(keys, appRand, devRand);
  console.log(`  App HMAC: ${appInfo.toString('hex').slice(0, 30)}...`);
  console.log(`  Expected device HMAC: ${expectedDevInfo.toString('hex').slice(0, 30)}...`);

  // Step 4: Receive and verify device HMAC
  console.log('\n  Step 4: Receive device HMAC');
  const resp4 = await recvAvdtp();
  if (!resp4) {
    console.log('  ERROR: No device HMAC');
    return null;
  }

  console.log(`  Device HMAC response (${resp4.length} bytes): ${resp4.toString('hex')}`);

  let devInfo: Buffer;
  if (resp4.length > 32) {
    devInfo = resp4.subarray(4, 36);
  } else {
    devInfo = resp4.subarray(0, 32);
  }

  while (devInfo.length < 32) {
    const extra = await recvAvdtp(3000);
    if (extra) {
      devInfo = Buffer.concat([devInfo, parseFrames(extra)]);
    } else {
      break;
    }
  }
  devInfo = devInfo.subarray(0, 32);
  console.log(`  Device HMAC: ${devInfo.toString('hex')}`);

  if (devInfo.equals(expectedDevInfo)) {
    console.log('  Device HMAC VERIFIED!');
  } else {
    console.log('  WARNING: Device HMAC mismatch!');
  }

  // Ack
  await writeChar(charAvdtp!, Buffer.from('00000300', 'hex'));

  // Step 5: Send our HMAC
  console.log('\n  Step 5: Send app HMAC');
  await writeChar(charAvdtp!, Buffer.from('0000000a0100', 'hex'));

  const resp5 = await recvAvdtp();
  if (resp5) {
    console.log(`  Response: ${resp5.toString('hex')}`);
  }

  const hmacFrame = Buffer.concat([Buffer.from([0x01, 0x00]), appInfo]);
  await writeChar(charAvdtp!, hmacFrame);
  console.log(`  Sent HMAC (1 frame, ${hmacFrame.length} bytes)`);

  const resp6 = await recvAvdtp();
  if (resp6) {
    console.log(`  HMAC accepted: ${resp6.toString('hex')}`);
  }

  // Step 6: Wait for login confirmation on UPNP channel
  console.log('\n  Step 6: Wait for confirmation');
  const resp7 = await recvUpnp();
  if (resp7) {
    console.log(`  Result: ${resp7.toString('hex')}`);
    if (resp7.equals(Buffer.from('21000000', 'hex'))) {
      console.log('  LOGIN SUCCESS!');
      return keys;
    } else if (resp7.equals(Buffer.from('23000000', 'hex'))) {
      console.log('  LOGIN FAILED!');
      return null;
    }
  }

  console.log('  No confirmation received');
  return null;
}

async function main() {
  console.log('Waiting for Bluetooth...');

  await new Promise<void>((resolve) => {
    if ((noble as unknown as { state: string }).state === 'poweredOn') {
      resolve();
    } else {
      noble.on('stateChange', (state) => {
        if (state === 'poweredOn') {
          resolve();
        }
      });
    }
  });

  const device = await findDevice();
  if (!device) {
    console.log('Device not found! Make sure it is awake.');
    process.exit(1);
  }

  console.log('Connecting...');

  await new Promise<void>((resolve, reject) => {
    device.connect((err) => {
      if (err) reject(err);
      else resolve();
    });
  });

  console.log(`Connected: ${device.state === 'connected'}`);

  const found = await discoverCharacteristics(device);
  if (!found) {
    console.log('Required characteristics not found!');
    device.disconnect();
    process.exit(1);
  }

  // Subscribe to notification channels
  await subscribeChar(charAvdtp!, (data) => avdtpQueue.push(data));
  await subscribeChar(charUpnp!, (data) => upnpQueue.push(data));

  // Read firmware
  const fw = await readChar(charFirmware!);
  console.log(`Firmware: ${fw.toString('ascii').replace(/\0/g, '')}`);

  // Capability exchange
  await capabilityExchange();

  // Check for saved token
  const saved = loadToken();
  let keys: SessionKeys | null = null;

  if (saved && !forceRegister) {
    console.log(`\nFound saved token for device: ${saved.deviceId}`);
    keys = await login(saved.token);
    if (keys) {
      sessionKeys = keys;
      recvCounter = 0;
      console.log('\n  Session keys:');
      console.log(`    dev_key: ${keys.devKey.toString('hex')}`);
      console.log(`    app_key: ${keys.appKey.toString('hex')}`);
      console.log(`    dev_iv:  ${keys.devIv.toString('hex')}`);
      console.log(`    app_iv:  ${keys.appIv.toString('hex')}`);
    }
  } else {
    if (forceRegister) {
      console.log('\nForcing new registration...');
    } else {
      console.log('\nNo saved token - registering as new controller...');
    }
    const success = await register();
    if (!success) {
      console.log('Registration failed!');
      device.disconnect();
      process.exit(1);
    }
    console.log('\nRegistration complete! Reconnecting to login...');
    device.disconnect();
    process.exit(0);
  }

  if (!keys) {
    console.log('Authentication failed!');
    device.disconnect();
    process.exit(1);
  }

  // Subscribe to measurement notifications
  console.log('\nSubscribing to measurement channel (char 0xFEA8)...');
  await subscribeChar(charMeasure!, onMeasure);

  // Read firmware again (as seen in capture)
  await readChar(charFirmware!);

  console.log('\n' + '='.repeat(50));
  console.log('AUTHENTICATED - Take measurements on the device!');
  console.log(`Listening for ${duration} seconds (Ctrl+C to stop)...`);
  console.log('='.repeat(50) + '\n');

  for (let i = 0; i < duration; i++) {
    if (device.state !== 'connected') {
      console.log('Disconnected!');
      break;
    }
    await sleep(1000);
    if (i > 0 && i % 15 === 0) {
      console.log(`  ... ${duration - i}s remaining, ${measureLog.length} measurements`);
    }
  }

  const distances = measureLog.filter((m) => 'm' in m);
  console.log('\n=== SUMMARY ===');
  console.log(`Measurements: ${distances.length}`);
  for (const m of distances) {
    console.log(`  #${m.seq}  ${(m.m as number).toFixed(3)} m  /  ${(m.ft as number).toFixed(3)} ft  (${m.mm} mm)`);
  }

  device.disconnect();
  process.exit(0);
}

main().catch((err) => {
  console.error('Error:', err);
  process.exit(1);
});
