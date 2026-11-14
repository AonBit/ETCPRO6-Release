import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, lstat, readFile, readlink, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { extractArchive, validateArchiveEntries, zipEntries } from '../tools/archive.mjs';
import { app, root, archiveEntries, zipFixture, zip64Fixture } from './helpers.mjs';

test('safe archive extracts files and real Sparkle-style internal version symlinks', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'etcpro6-public-zip-test-'));
  try {
    const framework = `${app}/Contents/Frameworks/Sparkle.framework`;
    const entries = [...archiveEntries(), { name: `${framework}/Versions/B/Resources/`, mode: 0o040755 }, { name: `${framework}/Versions/B/Sparkle`, data: 'Mach-O fixture', mode: 0o100755 }, { name: `${framework}/Versions/Current`, data: 'B', mode: 0o120755 }, { name: `${framework}/Sparkle`, data: 'Versions/Current/Sparkle', mode: 0o120755 }, { name: `${framework}/Resources`, data: 'Versions/Current/Resources', mode: 0o120755 }];
    const file = path.join(directory, 'fixture.zip'); await writeFile(file, zipFixture(entries));
    const archive = await extractArchive(file, path.join(directory, 'expanded'));
    assert.equal(await readFile(path.join(archive, 'Products/Applications/ETCPRO6.app/Contents/Frameworks/Sparkle.framework/Sparkle'), 'utf8'), 'Mach-O fixture');
    assert.equal(await readlink(path.join(archive, 'Products/Applications/ETCPRO6.app/Contents/Frameworks/Sparkle.framework/Versions/Current')), 'B');
    assert.equal((await lstat(path.join(directory, 'expanded'))).mode & 0o777, 0o700);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('zip parser rejects traversal, absolute names, duplicate paths, devices, corrupt CRC and unknown archive entries', () => {
  for (const item of [
    { name: `${root}/../escape`, data: 'x' }, { name: '/tmp/escape', data: 'x' }, { name: `${root}\\escape`, data: 'x' },
    { name: `${root}/Info.plist`, data: 'duplicate' }, { name: `${root}/INFO.PLIST`, data: 'case duplicate' },
    { name: `${app}/Contents/device`, mode: 0o020600 }, { name: `${root}/build-script.sh`, data: 'echo evil' },
    { name: `${app}/Contents/.git/config`, data: 'private' },
  ]) assert.throws(() => validateArchiveEntries(zipEntries(zipFixture([...archiveEntries(), item]))), /archive/);
  const damaged = zipFixture(archiveEntries()); damaged[damaged.indexOf(Buffer.from('<plist/>'))] ^= 1;
  assert.throws(() => zipEntries(damaged), /archive/);
});

test('symlinks cannot escape, form cycles, or become an ancestor of stored entries', () => {
  for (const entries of [
    [{ name: `${app}/Contents/Escape`, mode: 0o120755, data: '/private/tmp' }],
    [{ name: `${app}/Contents/Escape`, mode: 0o120755, data: '../../../outside' }],
    [{ name: `${app}/Contents/A`, mode: 0o120755, data: 'B' }, { name: `${app}/Contents/B`, mode: 0o120755, data: 'A' }],
    [{ name: `${app}/Contents/A`, mode: 0o120755, data: 'Info.plist' }, { name: `${app}/Contents/A/escape`, data: 'evil' }],
    [{ name: `${root}/Products/A`, mode: 0o120755, data: 'Applications' }],
  ]) assert.throws(() => validateArchiveEntries(zipEntries(zipFixture([...archiveEntries(), ...entries]))), /archive/);
});
test('bounded ZIP64 accepts streaming GitHub artifact styles and rejects inconsistent wide sizes', () => {
  const entries = [{ name: 'unsigned-manifest.json', data: '{"fixture":true}' }, { name: 'ETCPRO6-unsigned.xcarchive.zip', data: 'inner fixture' }];
  for (const options of [{ entryZip64: false, streaming: true }, { entryZip64: true, streaming: true }, { entryZip64: true, streaming: false }]) {
    const parsed = zipEntries(zip64Fixture(entries, options)); assert.equal(parsed.length, 2); assert.equal(parsed[0].data.toString(), '{"fixture":true}');
  }
  const tooLarge = zip64Fixture(entries); tooLarge.writeBigUInt64LE(2n ** 63n, tooLarge.length - 22 - 20 + 8); assert.throws(() => zipEntries(tooLarge), /archive/);
  const wrongLocalSize = zip64Fixture(entries, { streaming: false }); wrongLocalSize.writeBigUInt64LE(99n, 30 + Buffer.byteLength(entries[0].name) + 4); assert.throws(() => zipEntries(wrongLocalSize), /archive/);
  const wrongDescriptor = zip64Fixture(entries); const descriptor = wrongDescriptor.indexOf(Buffer.from([0x50, 0x4b, 0x07, 0x08])); wrongDescriptor.writeBigUInt64LE(99n, descriptor + 8); assert.throws(() => zipEntries(wrongDescriptor), /archive/);
});
