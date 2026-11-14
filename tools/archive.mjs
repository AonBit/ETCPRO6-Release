import { inflateRawSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, readFile, readdir, realpath, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

const fail = () => { throw new Error('Unsafe or unsupported archive'); };
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0); }
  return (crc ^ 0xffffffff) >>> 0;
}
function uint64(bytes, offset) { if (offset + 8 > bytes.length) fail(); const number = bytes.readBigUInt64LE(offset); if (number > BigInt(Number.MAX_SAFE_INTEGER)) fail(); return Number(number); }
function zip64Extra(bytes) {
  let result = null;
  for (let offset = 0; offset < bytes.length;) {
    if (offset + 4 > bytes.length) fail(); const id = bytes.readUInt16LE(offset), size = bytes.readUInt16LE(offset + 2); offset += 4;
    if (offset + size > bytes.length) fail(); if (id === 1) { if (result) fail(); result = bytes.subarray(offset, offset + size); } offset += size;
  }
  return result;
}
export function zipEntries(bytes, { maximumBytes = 2 * 1024 ** 3, maximumEntries = 20_000 } = {}) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 22 || bytes.length > maximumBytes) fail();
  let end = -1;
  for (let offset = bytes.length - 22; offset >= Math.max(0, bytes.length - 65_557); offset--) {
    if (bytes.readUInt32LE(offset) === 0x06054b50 && offset + 22 + bytes.readUInt16LE(offset + 20) === bytes.length) { end = offset; break; }
  }
  if (end < 0 || bytes.readUInt16LE(end + 4) || bytes.readUInt16LE(end + 6)) fail();
  let count = bytes.readUInt16LE(end + 10), size = bytes.readUInt32LE(end + 12), start = bytes.readUInt32LE(end + 16), centralEnd = end;
  if (count !== bytes.readUInt16LE(end + 8)) fail();
  const has64 = end >= 20 && bytes.readUInt32LE(end - 20) === 0x07064b50;
  if (has64) {
    const locator = end - 20, recordOffset = uint64(bytes, locator + 8);
    if (bytes.readUInt32LE(locator + 4) || bytes.readUInt32LE(locator + 16) !== 1 || recordOffset + 56 > locator || bytes.readUInt32LE(recordOffset) !== 0x06064b50) fail();
    const recordLength = uint64(bytes, recordOffset + 4);
    if (recordLength < 44 || recordLength > 1024 || recordOffset + 12 + recordLength !== locator || bytes.readUInt32LE(recordOffset + 16) || bytes.readUInt32LE(recordOffset + 20)) fail();
    const count64 = uint64(bytes, recordOffset + 32), diskCount64 = uint64(bytes, recordOffset + 24), size64 = uint64(bytes, recordOffset + 40), start64 = uint64(bytes, recordOffset + 48);
    if (count64 !== diskCount64 || (count !== 0xffff && count !== count64) || (size !== 0xffffffff && size !== size64) || (start !== 0xffffffff && start !== start64)) fail();
    count = count64; size = size64; start = start64; centralEnd = recordOffset;
  } else if (count === 0xffff || size === 0xffffffff || start === 0xffffffff) fail();
  if (count < 1 || count > maximumEntries || start + size !== centralEnd || start < 0 || centralEnd > end) fail();
  const names = new Set(), spans = [], entries = []; let offset = start, expanded = 0;
  for (let i = 0; i < count; i++) {
    if (offset + 46 > centralEnd || bytes.readUInt32LE(offset) !== 0x02014b50) fail();
    const flags = bytes.readUInt16LE(offset + 8), method = bytes.readUInt16LE(offset + 10);
    const crc = bytes.readUInt32LE(offset + 16); let compressed = bytes.readUInt32LE(offset + 20), length = bytes.readUInt32LE(offset + 24);
    const nameLength = bytes.readUInt16LE(offset + 28), extra = bytes.readUInt16LE(offset + 30), comment = bytes.readUInt16LE(offset + 32);
    const external = bytes.readUInt32LE(offset + 38); let local = bytes.readUInt32LE(offset + 42), disk = bytes.readUInt16LE(offset + 34);
    if (offset + 46 + nameLength + extra + comment > centralEnd || flags & ~0x0808 || ![0, 8].includes(method)) fail();
    const central64 = zip64Extra(bytes.subarray(offset + 46 + nameLength, offset + 46 + nameLength + extra)); let index64 = 0;
    const next64 = () => { if (!central64) fail(); const value = uint64(central64, index64); index64 += 8; return value; };
    if (length === 0xffffffff) length = next64(); if (compressed === 0xffffffff) compressed = next64(); if (local === 0xffffffff) local = next64();
    if (disk === 0xffff) { if (!central64 || index64 + 4 > central64.length) fail(); disk = central64.readUInt32LE(index64); index64 += 4; }
    if ((central64 && index64 !== central64.length) || local >= start || disk || compressed > maximumBytes || length > maximumBytes) fail();
    const nameBytes = bytes.subarray(offset + 46, offset + 46 + nameLength), name = nameBytes.toString('utf8');
    if (!name || !Buffer.from(name).equals(nameBytes) || /[\\:\x00-\x1f\x7f]/.test(name) || name.startsWith('/') || name.length > 1024) fail();
    const parts = name.replace(/\/$/, '').split('/');
    const folded = name.replace(/\/$/, '').toLowerCase();
    if (parts.some(part => !part || part === '.' || part === '..') || names.has(folded)) fail();
    names.add(folded);
    const mode = external >>> 16, type = mode & 0o170000;
    const kind = name.endsWith('/') ? 'directory' : type === 0o120000 ? 'symlink' : 'file';
    if ((kind === 'directory' && type && type !== 0o040000) || (kind === 'file' && type && type !== 0o100000) || (kind === 'symlink' && length > 1024)) fail();
    if (local + 30 > start || bytes.readUInt32LE(local) !== 0x04034b50 || bytes.readUInt16LE(local + 6) !== flags || bytes.readUInt16LE(local + 8) !== method) fail();
    const localNameLength = bytes.readUInt16LE(local + 26), localExtra = bytes.readUInt16LE(local + 28);
    if (local + 30 + localNameLength + localExtra > start) fail();
    if (!bytes.subarray(local + 30, local + 30 + localNameLength).equals(nameBytes)) fail();
    const dataStart = local + 30 + localNameLength + localExtra, dataEnd = dataStart + compressed;
    let localCompressed = bytes.readUInt32LE(local + 18), localLength = bytes.readUInt32LE(local + 22), localCRC = bytes.readUInt32LE(local + 14), localIndex = 0;
    const local64 = zip64Extra(bytes.subarray(local + 30 + localNameLength, dataStart));
    if (localLength === 0xffffffff) { if (!local64) fail(); localLength = uint64(local64, localIndex); localIndex += 8; }
    if (localCompressed === 0xffffffff) { if (!local64) fail(); localCompressed = uint64(local64, localIndex); localIndex += 8; }
    if (local64 && local64.length !== localIndex) fail();
    let entryEnd = dataEnd;
    if (flags & 8) {
      // Streaming ZIPs carry their checksum/sizes after the payload. Accept the exact 32/64-bit descriptor only.
      let descriptor = dataEnd; if (descriptor + 4 <= start && bytes.readUInt32LE(descriptor) === 0x08074b50) descriptor += 4;
      if (descriptor + 12 > start || bytes.readUInt32LE(descriptor) !== crc) fail();
      const wide = !!local64;
      const descriptorCompressed = wide ? uint64(bytes, descriptor + 4) : bytes.readUInt32LE(descriptor + 4), descriptorLength = wide ? uint64(bytes, descriptor + 12) : bytes.readUInt32LE(descriptor + 8);
      entryEnd = descriptor + (wide ? 20 : 12);
      if (descriptorCompressed !== compressed || descriptorLength !== length || (localCRC !== 0 && localCRC !== crc) || (localCompressed !== 0 && localCompressed !== compressed) || (localLength !== 0 && localLength !== length)) fail();
    } else if (localCRC !== crc || localCompressed !== compressed || localLength !== length) fail();
    if (entryEnd > start || spans.some(([a, b]) => local < b && entryEnd > a)) fail();
    spans.push([local, entryEnd]); expanded += length;
    if (expanded > maximumBytes || length > 1024 ** 3 || (kind === 'directory' && length !== 0)) fail();
    const stored = bytes.subarray(dataStart, dataEnd);
    let data; try { data = method === 0 ? stored : inflateRawSync(stored, { maxOutputLength: Math.max(length, 1) }); } catch { fail(); }
    if (data.length !== length || crc32(data) !== crc) fail();
    entries.push({ name, kind, mode: mode & 0o777, data }); offset += 46 + nameLength + extra + comment;
  }
  if (offset !== centralEnd) fail();
  return entries;
}

export function validateArchiveEntries(entries, prefix = 'ETCPRO6.xcarchive') {
  const paths = new Map(entries.map(entry => [entry.name.replace(/\/$/, ''), entry]));
  for (const entry of entries) {
    const name = entry.name.replace(/\/$/, '');
    if (name !== prefix && !name.startsWith(`${prefix}/`)) fail();
    if (![prefix, `${prefix}/Info.plist`, `${prefix}/Products`, `${prefix}/Products/Applications`, `${prefix}/Products/Applications/ETCPRO6.app`].includes(name) && !name.startsWith(`${prefix}/Products/Applications/ETCPRO6.app/`)) fail();
    if (/(?:^|\/)(?:__MACOSX|\.DS_Store|\.\._[^/]*|\.git)(?:\/|$)/.test(name)) fail();
    let parent = path.posix.dirname(name);
    while (parent !== '.') {
      if (paths.has(parent) && paths.get(parent).kind !== 'directory') fail();
      parent = path.posix.dirname(parent);
    }
    if (entry.kind === 'symlink') {
      const target = entry.data.toString('utf8');
      if (!Buffer.from(target).equals(entry.data) || !target || /[\\:\x00-\x1f\x7f]/.test(target) || target.startsWith('/') || target.split('/').some(part => part === '..' || part === '.')) fail();
      const bundle = name.match(new RegExp(`^${prefix.replaceAll('.', '\\.')}\/Products\/Applications\/ETCPRO6\\.app(?:\/|$)`))?.[0].replace(/\/$/, '');
      if (!bundle) fail();
      let resolved = path.posix.normalize(path.posix.join(path.posix.dirname(name), target));
      if (!resolved.startsWith(`${bundle}/`)) fail();
      const visited = new Set([name]);
      for (let depth = 0; depth < 40; depth++) {
        const parts = resolved.split('/'); let link = null;
        for (let i = 1; i <= parts.length; i++) { const candidate = parts.slice(0, i).join('/'); if (paths.get(candidate)?.kind === 'symlink') { link = { candidate, suffix: parts.slice(i).join('/') }; break; } }
        if (!link) break;
        if (visited.has(link.candidate)) fail(); visited.add(link.candidate);
        const next = paths.get(link.candidate).data.toString('utf8');
        resolved = path.posix.normalize(path.posix.join(path.posix.dirname(link.candidate), next, link.suffix));
        if (!resolved.startsWith(`${bundle}/`) || depth === 39) fail();
      }
      if (!paths.has(resolved) && !entries.some(item => item.name.startsWith(`${resolved}/`))) fail();
    }
  }
  if (!paths.has(`${prefix}/Info.plist`) || !paths.has(`${prefix}/Products/Applications/ETCPRO6.app/Contents/Info.plist`)) fail();
  return entries;
}

export async function extractArchive(zip, destination) {
  const info = await lstat(zip); if (!info.isFile() || info.isSymbolicLink()) fail();
  const entries = validateArchiveEntries(zipEntries(await readFile(zip)));
  await mkdir(destination, { recursive: false, mode: 0o700 });
  const root = await realpath(destination);
  for (const entry of entries.filter(item => item.kind !== 'symlink')) {
    const target = path.join(root, entry.name);
    if (entry.kind === 'directory') await mkdir(target, { recursive: true, mode: 0o755 });
    else { await mkdir(path.dirname(target), { recursive: true, mode: 0o755 }); await writeFile(target, entry.data, { flag: 'wx', mode: entry.mode & 0o111 ? 0o755 : 0o644 }); }
  }
  for (const entry of entries.filter(item => item.kind === 'symlink')) { const target = path.join(root, entry.name); await mkdir(path.dirname(target), { recursive: true, mode: 0o700 }); await symlink(entry.data.toString('utf8'), target); }
  async function verify(directory) {
    for (const name of await readdir(directory)) {
      const target = path.join(directory, name), item = await lstat(target), actual = await realpath(target);
      if (!actual.startsWith(`${root}${path.sep}`)) fail();
      if (item.isDirectory()) { await chmod(target, 0o755); await verify(target); }
      else if (!item.isFile() && !item.isSymbolicLink()) fail();
    }
  }
  await verify(root);
  return path.join(root, 'ETCPRO6.xcarchive');
}
