/**
 * Xiaomi Mi Standard Auth (MJAC) - Registration and Login protocol.
 *
 * Implements ECDH P-256 key exchange for registration and HMAC-SHA256 for login.
 * Based on miauth (github.com/dnandha/miauth) and HCI snoop log analysis.
 */

import { createECDH, createHmac, createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

// Fixed constants from the protocol
const AES_CCM_NONCE = Buffer.from([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b]);
const AES_CCM_AAD = Buffer.from('devID');
const HKDF_REGISTER_INFO = Buffer.from('mible-setup-info');
const HKDF_LOGIN_INFO = Buffer.from('mible-login-info');

const TOKEN_FILE = join(__dirname, '..', 'device_token.json');

export interface SessionKeys {
  devKey: Buffer;
  appKey: Buffer;
  devIv: Buffer;
  appIv: Buffer;
}

export interface SavedToken {
  token: Buffer;
  bindKey: Buffer;
  deviceId: string;
}

/**
 * Generate an ECDH P-256 key pair.
 * Returns the ECDH object which can be used to get public key and compute shared secret.
 */
export function genKeypair() {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

/**
 * Get the 64-byte raw public key (X||Y, no 0x04 prefix).
 */
export function pubKeyBytes(ecdh: ReturnType<typeof createECDH>): Buffer {
  const raw = ecdh.getPublicKey();
  // Raw format is 0x04 + X (32 bytes) + Y (32 bytes)
  return raw.subarray(1);
}

/**
 * Perform ECDH and derive registration keys via HKDF.
 *
 * Returns { token, bindKey, aKey }:
 *   token: 12 bytes - save for future logins
 *   bindKey: 16 bytes - beacon encryption key
 *   aKey: 16 bytes - used to encrypt device ID
 */
export function deriveRegistrationKeys(ecdh: ReturnType<typeof createECDH>, devicePubBytes: Buffer) {
  // Prepend 0x04 for uncompressed point format
  const devicePub = Buffer.concat([Buffer.from([0x04]), devicePubBytes]);
  const sharedSecret = ecdh.computeSecret(devicePub);

  const derivedBuf = Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), HKDF_REGISTER_INFO, 64));

  return {
    token: derivedBuf.subarray(0, 12),
    bindKey: derivedBuf.subarray(12, 28),
    aKey: derivedBuf.subarray(28, 44),
  };
}

/**
 * Encrypt the device ID using AES-CCM with fixed nonce and AAD.
 */
export function encryptDid(aKey: Buffer, didBytes: Buffer): Buffer {
  // AES-128-CCM with 4-byte tag
  const cipher = createCipheriv('aes-128-ccm', aKey, AES_CCM_NONCE, {
    authTagLength: 4,
  });
  cipher.setAAD(AES_CCM_AAD, { plaintextLength: didBytes.length });
  const encrypted = cipher.update(didBytes);
  cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([encrypted, tag]);
}

/**
 * Derive session keys for login from the saved token and random values.
 */
export function deriveLoginKeys(token: Buffer, appRand: Buffer, devRand: Buffer): SessionKeys {
  const salt = Buffer.concat([appRand, devRand]);

  const derivedBuf = Buffer.from(hkdfSync('sha256', token, salt, HKDF_LOGIN_INFO, 64));

  return {
    devKey: derivedBuf.subarray(0, 16),
    appKey: derivedBuf.subarray(16, 32),
    devIv: derivedBuf.subarray(32, 36),
    appIv: derivedBuf.subarray(36, 40),
  };
}

/**
 * Compute HMAC values for login mutual authentication.
 * Returns { appInfo, expectedDevInfo } - both 32 bytes.
 */
export function computeLoginInfo(keys: SessionKeys, appRand: Buffer, devRand: Buffer) {
  const salt = Buffer.concat([appRand, devRand]);
  const saltInv = Buffer.concat([devRand, appRand]);

  const appInfo = createHmac('sha256', keys.appKey).update(salt).digest();
  const expectedDevInfo = createHmac('sha256', keys.devKey).update(saltInv).digest();

  return { appInfo, expectedDevInfo };
}

/**
 * Split data into numbered frames for BLE writes.
 */
export function makeFrames(data: Buffer, chunkSize = 18): Buffer[] {
  const frames: Buffer[] = [];
  for (let i = 0; i < data.length; i += chunkSize) {
    const chunk = data.subarray(i, i + chunkSize);
    const frameNum = Math.floor(i / chunkSize) + 1;
    frames.push(Buffer.concat([Buffer.from([frameNum, 0x00]), chunk]));
  }
  return frames;
}

/**
 * Extract payload from a framed notification (strip 2-byte header).
 */
export function parseFrames(frameData: Buffer): Buffer {
  if (frameData.length > 2) {
    return frameData.subarray(2);
  }
  return frameData;
}

/**
 * Save token and bind key to disk for future logins.
 */
export function saveToken(token: Buffer, bindKey: Buffer, deviceId: string): void {
  const data = {
    token: token.toString('hex'),
    bind_key: bindKey.toString('hex'),
    device_id: deviceId,
  };
  writeFileSync(TOKEN_FILE, JSON.stringify(data, null, 2));
  console.log(`  Token saved to ${TOKEN_FILE}`);
}

/**
 * Load saved token and bind key from disk.
 */
export function loadToken(): SavedToken | null {
  if (!existsSync(TOKEN_FILE)) {
    return null;
  }
  const data = JSON.parse(readFileSync(TOKEN_FILE, 'utf8'));
  return {
    token: Buffer.from(data.token, 'hex'),
    bindKey: Buffer.from(data.bind_key, 'hex'),
    deviceId: data.device_id,
  };
}

/**
 * Decrypt measurement notification using session keys.
 * Scheme: AES-CCM with dev_key, nonce=dev_iv+0000+counter_le32, tag=4, no AAD.
 */
export function decryptMeasurement(
  data: Buffer,
  sessionKeys: SessionKeys,
  recvCounter: number
): { plaintext: Buffer; counter: number } | null {
  const payload = data.length > 2 ? data.subarray(2) : data;

  // Try counters near the expected value
  for (let ctr = Math.max(recvCounter - 1, 0); ctr < recvCounter + 10; ctr++) {
    const counterBuf = Buffer.alloc(4);
    counterBuf.writeUInt32LE(ctr);
    const nonce = Buffer.concat([sessionKeys.devIv, Buffer.alloc(4), counterBuf]);

    try {
      const decipher = createDecipheriv('aes-128-ccm', sessionKeys.devKey, nonce, {
        authTagLength: 4,
      });
      // Last 4 bytes are the tag
      const ciphertext = payload.subarray(0, -4);
      const tag = payload.subarray(-4);
      decipher.setAuthTag(tag);
      decipher.setAAD(Buffer.alloc(0), { plaintextLength: ciphertext.length });

      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return { plaintext, counter: ctr + 1 };
    } catch {
      // Try next counter
    }
  }

  return null;
}

/**
 * Generate random bytes.
 */
export function secureRandomBytes(length: number): Buffer {
  return randomBytes(length);
}
