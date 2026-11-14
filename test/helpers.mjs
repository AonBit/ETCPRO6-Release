import { crc32 } from '../tools/archive.mjs';
export function zipFixture(entries) {
  const locals = [], centrals = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name), data = Buffer.from(entry.data ?? ''), mode = entry.mode ?? (entry.name.endsWith('/') ? 0o040755 : 0o100644), crc = crc32(data);
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x800, 6); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50); central.writeUInt16LE(0x314, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x800, 8); central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt32LE((mode << 16) >>> 0, 38); central.writeUInt32LE(offset, 42);
    locals.push(local, name, data); centrals.push(central, name); offset += local.length + name.length + data.length;
  }
  const central = Buffer.concat(centrals), end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(central.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, central, end]);
}
export function zip64Fixture(entries, { entryZip64 = true, streaming = true } = {}) {
  const locals = [], centrals = []; let offset = 0;
  for (const entry of entries) {
    const name = Buffer.from(entry.name), data = Buffer.from(entry.data ?? ''), crc = crc32(data), flags = 0x800 | (streaming ? 8 : 0), mode = entry.mode ?? 0o100644;
    const localExtra = entryZip64 ? Buffer.alloc(20) : Buffer.alloc(0);
    if (entryZip64) { localExtra.writeUInt16LE(1); localExtra.writeUInt16LE(16, 2); localExtra.writeBigUInt64LE(BigInt(streaming ? 0 : data.length), 4); localExtra.writeBigUInt64LE(BigInt(streaming ? 0 : data.length), 12); }
    const local = Buffer.alloc(30); local.writeUInt32LE(0x04034b50); local.writeUInt16LE(45, 4); local.writeUInt16LE(flags, 6); local.writeUInt32LE(streaming ? 0 : crc, 14); local.writeUInt32LE(entryZip64 ? 0xffffffff : streaming ? 0 : data.length, 18); local.writeUInt32LE(entryZip64 ? 0xffffffff : streaming ? 0 : data.length, 22); local.writeUInt16LE(name.length, 26); local.writeUInt16LE(localExtra.length, 28);
    const descriptor = streaming ? Buffer.alloc(entryZip64 ? 24 : 16) : Buffer.alloc(0);
    if (streaming) { descriptor.writeUInt32LE(0x08074b50); descriptor.writeUInt32LE(crc, 4); if (entryZip64) { descriptor.writeBigUInt64LE(BigInt(data.length), 8); descriptor.writeBigUInt64LE(BigInt(data.length), 16); } else { descriptor.writeUInt32LE(data.length, 8); descriptor.writeUInt32LE(data.length, 12); } }
    const centralExtra = entryZip64 ? Buffer.alloc(28) : Buffer.alloc(0);
    if (entryZip64) { centralExtra.writeUInt16LE(1); centralExtra.writeUInt16LE(24, 2); centralExtra.writeBigUInt64LE(BigInt(data.length), 4); centralExtra.writeBigUInt64LE(BigInt(data.length), 12); centralExtra.writeBigUInt64LE(BigInt(offset), 20); }
    const central = Buffer.alloc(46); central.writeUInt32LE(0x02014b50); central.writeUInt16LE(0x32d, 4); central.writeUInt16LE(45, 6); central.writeUInt16LE(flags, 8); central.writeUInt32LE(crc, 16); central.writeUInt32LE(entryZip64 ? 0xffffffff : data.length, 20); central.writeUInt32LE(entryZip64 ? 0xffffffff : data.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt16LE(centralExtra.length, 30); central.writeUInt32LE((mode << 16) >>> 0, 38); central.writeUInt32LE(entryZip64 ? 0xffffffff : offset, 42);
    locals.push(local, name, localExtra, data, descriptor); centrals.push(central, name, centralExtra); offset += local.length + name.length + localExtra.length + data.length + descriptor.length;
  }
  const central = Buffer.concat(centrals), end64 = Buffer.alloc(56), locator = Buffer.alloc(20), end = Buffer.alloc(22);
  end64.writeUInt32LE(0x06064b50); end64.writeBigUInt64LE(44n, 4); end64.writeUInt16LE(45, 12); end64.writeUInt16LE(45, 14); end64.writeBigUInt64LE(BigInt(entries.length), 24); end64.writeBigUInt64LE(BigInt(entries.length), 32); end64.writeBigUInt64LE(BigInt(central.length), 40); end64.writeBigUInt64LE(BigInt(offset), 48);
  locator.writeUInt32LE(0x07064b50); locator.writeBigUInt64LE(BigInt(offset + central.length), 8); locator.writeUInt32LE(1, 16);
  end.writeUInt32LE(0x06054b50); end.writeUInt16LE(0xffff, 8); end.writeUInt16LE(0xffff, 10); end.writeUInt32LE(0xffffffff, 12); end.writeUInt32LE(0xffffffff, 16);
  return Buffer.concat([...locals, central, end64, locator, end]);
}
export const root = 'ETCPRO6.xcarchive';
export const app = `${root}/Products/Applications/ETCPRO6.app`;
export const archiveEntries = () => [
  { name: `${root}/`, mode: 0o040755 }, { name: `${root}/Info.plist`, data: '<plist/>' },
  { name: `${root}/Products/`, mode: 0o040755 }, { name: `${root}/Products/Applications/`, mode: 0o040755 },
  { name: `${app}/`, mode: 0o040755 }, { name: `${app}/Contents/`, mode: 0o040755 },
  { name: `${app}/Contents/Info.plist`, data: '<plist/>' },
];
