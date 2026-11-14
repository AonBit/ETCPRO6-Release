import test from 'node:test';
import assert from 'node:assert/strict';
import { downloadSource } from './download-source.mjs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../tools/archive.mjs';
import { zipFixture, zip64Fixture } from '../test/helpers.mjs';
const request = { repository: 'AonBit/ETCPRO6-MAC', artifact: { id: 456, size: 4, digest: 'a'.repeat(64) } };
const token = 'fixture-token-never-forwarded';
test('rejects redirects to an unapproved host before sending credentials elsewhere', async () => {
  let calls = 0;
  await assert.rejects(downloadSource(request, '/unused', token, async (url, options) => {
    calls++; assert.equal(options.redirect, 'manual'); assert.equal(options.headers.Authorization, `Bearer ${token}`);
    return new Response(null, { status: 302, headers: { location: 'https://attacker.test/payload' } });
  }));
  assert.equal(calls, 1);
});
test('fails closed on a mismatched outer ZIP digest and never forwards the GitHub token', async () => {
  let calls = 0;
  await assert.rejects(downloadSource(request, '/unused', token, async (url, options) => {
    calls++;
    if (calls === 1) return new Response(null, { status: 302, headers: { location: 'https://fixture.blob.core.windows.net/archive?signed=fixture' } });
    assert.equal(options.headers, undefined); assert.equal(options.redirect, 'error');
    return new Response('data');
  }));
  assert.equal(calls, 2);
});
test('downloads only the two manifest-bound files after exact classic or ZIP64 outer digest verification', async () => {
  for (const zip of [zipFixture, zip64Fixture]) {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'etcpro6-download-test-'));
    try {
      const bytes = zip([{ name: 'ETCPRO6-unsigned.xcarchive.zip', data: 'fixture inner archive' }, { name: 'unsigned-manifest.json', data: '{"fixture":true}' }]);
      const verified = { ...request, artifact: { ...request.artifact, size: bytes.length, digest: sha256(bytes) } };
      let calls = 0;
      const output = path.join(directory, 'input');
      await downloadSource(verified, output, token, async () => ++calls === 1 ? new Response(null, { status: 302, headers: { location: 'https://fixture.blob.core.windows.net/archive' } }) : new Response(bytes));
      assert.equal(await readFile(path.join(output, 'ETCPRO6-unsigned.xcarchive.zip'), 'utf8'), 'fixture inner archive');
      assert.equal(await readFile(path.join(output, 'unsigned-manifest.json'), 'utf8'), '{"fixture":true}');
    } finally { await rm(directory, { recursive: true, force: true }); }
  }
});
