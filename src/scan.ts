#!/usr/bin/env tsx
/**
 * Scan for nearby BLE devices.
 *
 * Usage:
 *   npx tsx src/scan.ts           # Scan for 10 seconds
 *   npx tsx src/scan.ts 30        # Scan for 30 seconds
 */

import noble from '@abandonware/noble';

const duration = parseInt(process.argv[2] || '10', 10);

console.log('Waiting for Bluetooth...');

noble.on('stateChange', (state) => {
  if (state === 'poweredOn') {
    console.log(`Scanning for ${duration}s...\n`);
    noble.startScanning([], true);

    setTimeout(() => {
      noble.stopScanning();
      console.log('\nDone.');
      process.exit(0);
    }, duration * 1000);
  }
});

const seen = new Set<string>();

noble.on('discover', (peripheral) => {
  const id = peripheral.id || peripheral.address || 'unknown';
  if (seen.has(id)) return;
  seen.add(id);

  const name = peripheral.advertisement.localName || '(no name)';
  const rssi = peripheral.rssi;
  const addr = peripheral.address || peripheral.id || '';

  console.log(`[${rssi.toString().padStart(4)}] ${name.padEnd(30)} ${addr}`);
});
