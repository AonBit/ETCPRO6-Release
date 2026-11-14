import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../tools/archive.mjs';
import { childEnvironment, cleanupSigning, decryptRecovery, encryptRecovery, inspectInput, notarize, prepareSigning, promote, publishCandidate, restoreCandidate, snapshotCandidate, SOURCE_REPOSITORY, SOURCE_WORKFLOW, SPARKLE_REVISION, validateSparkleKey, validateUnsignedManifest } from '../tools/release.mjs';
import { archiveEntries, zipFixture } from './helpers.mjs';

const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const publicKey = Buffer.from('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', 'hex');
const key = Buffer.alloc(32, 7).toString('base64');
const env = { UPDATE_ADMIN_BASE_URL: 'https://admin.aonbit.test', UPDATE_PUBLIC_BASE_URL: 'https://updates.aonbit.test', STAGING_UPDATE_ADMIN_BASE_URL: 'https://admin-staging.aonbit.test', STAGING_UPDATE_PUBLIC_BASE_URL: 'https://updates-staging.aonbit.test', ETCPRO6_UPDATE_PUBLIC_KEY: publicKey.toString('base64'), CF_CANDIDATE_ACCESS_CLIENT_ID: 'candidate', CF_CANDIDATE_ACCESS_CLIENT_SECRET: 'candidate-secret-never-log', STAGING_CF_CANDIDATE_ACCESS_CLIENT_ID: 'staging', STAGING_CF_CANDIDATE_ACCESS_CLIENT_SECRET: 'staging-secret-never-log' };
function manifest(zip) { return { schemaVersion: 1, repository: SOURCE_REPOSITORY, commit: 'a'.repeat(40), workflowRunId: '123', workflowPath: SOURCE_WORKFLOW, version: '0.1.0', build: 1, releaseId: '0.1.0+1', archive: { file: 'ETCPRO6-unsigned.xcarchive.zip', size: zip.length, sha256: sha256(zip) }, sparkle: { version: '2.10.1', revision: SPARKLE_REVISION }, updates: { feedURL: `${env.UPDATE_PUBLIC_BASE_URL}/stable/appcast.xml`, publicKeySHA256: sha256(publicKey) } }; }
const verified = { schemaVersion: 1, repository: SOURCE_REPOSITORY, commit: 'a'.repeat(40), releaseTag: 'v0.1.0', workflow: { path: SOURCE_WORKFLOW, runId: '123', runAttempt: 1 }, artifact: { id: 456, name: 'unsigned-release', size: 1000, digest: 'b'.repeat(64) } };
async function temporary(body, prefix = 'etcpro6-public-test-') { const directory = await mkdtemp(path.join(process.env.RUNNER_TEMP || os.tmpdir(), prefix)); try { return await body(await import('node:fs/promises').then(fs => fs.realpath(directory))); } finally { await rm(directory, { recursive: true, force: true }); } }

test('input provenance and exact inner ZIP hash are checked without executing input code', async () => temporary(async directory => {
  const input = path.join(directory, 'input'); await mkdir(input); const zip = zipFixture(archiveEntries()), m = manifest(zip), verifiedFile = path.join(directory, 'verified.json');
  await writeFile(path.join(input, m.archive.file), zip); await writeFile(path.join(input, 'unsigned-manifest.json'), JSON.stringify(m)); await writeFile(verifiedFile, JSON.stringify(verified));
  assert.equal((await inspectInput(input, verifiedFile, env)).manifest.commit, m.commit);
  for (const mutation of [value => { value.repository = 'other/private'; }, value => { value.commit = 'c'.repeat(40); }, value => { value.workflowRunId = '999'; }, value => { value.archive.file = '../evil'; }, value => { value.updates.publicKeySHA256 = 'c'.repeat(64); }, value => { value.sparkle.version = '2.10.0'; }, value => { value.build = 0; }]) { const changed = structuredClone(m); mutation(changed); assert.throws(() => validateUnsignedManifest(changed, verified, env)); }
  await writeFile(path.join(input, m.archive.file), Buffer.concat([zip, Buffer.from('evil')])); await assert.rejects(inspectInput(input, verifiedFile, env), /hash or size/);
  await writeFile(path.join(input, 'source.swift'), 'private source'); await assert.rejects(inspectInput(input, verifiedFile, env), /Unexpected/);
}));

test('Sparkle accepts only reviewed 32/96-byte formats and verifies configured public key', () => {
  assert.equal(validateSparkleKey(seed.toString('base64'), publicKey.toString('base64')).length, 32);
  const expanded = createHash('sha512').update(seed).digest(); expanded[0] &= 248; expanded[31] &= 63; expanded[31] |= 64;
  assert.equal(validateSparkleKey(Buffer.concat([expanded, publicKey]).toString('base64'), publicKey.toString('base64')).length, 96);
  assert.throws(() => validateSparkleKey(Buffer.alloc(64).toString('base64'), publicKey.toString('base64')));
  assert.throws(() => validateSparkleKey(seed.toString('base64'), Buffer.alloc(32).toString('base64')), /mismatch/);
  assert.throws(() => validateSparkleKey(`${seed.toString('base64')}\n`, publicKey.toString('base64')));
});

test('child environments never inherit signing/upload secrets or injected loader configuration', () => {
  const child = childEnvironment({ HOME: '/fixture', PATH: '/usr/bin', APPLE_SIGNING_P12: 'secret', SPARKLE_PRIVATE_KEY: 'secret', CF_CANDIDATE_ACCESS_CLIENT_SECRET: 'secret', GITHUB_TOKEN: 'secret', DYLD_INSERT_LIBRARIES: '/evil', NODE_OPTIONS: '--require evil', GIT_CONFIG_COUNT: '1', GIT_TRACE: '/leak' });
  assert.deepEqual(child, { HOME: '/fixture', PATH: '/usr/bin' });
});

test('Keychain passwords use interpreter stdin and cleanup scrubs secrets before retryable recovery', async () => temporary(async directory => {
  const signing = { APPLE_SIGNING_P12: 'AQID', APPLE_SIGNING_P12_PASSWORD: 'fixture-p12-secret', APPLE_SIGNING_IDENTITY: 'Developer ID Application: Fixture (ABCDEFGHIJ)', APPLE_NOTARY_KEY: 'fixture-p8-secret', SPARKLE_PRIVATE_KEY: seed.toString('base64') };
  const calls = [];
  const execute = (tool, args, options = {}) => { calls.push({ tool, args, input: options.input }); return { status: 0, stderr: '', stdout: args[0] === 'list-keychains' ? '"/fixture/login.keychain-db"' : args[0] === 'find-identity' ? `1) AAAAA "${signing.APPLE_SIGNING_IDENTITY}"` : '' }; };
  await prepareSigning(directory, signing, execute);
  assert.equal(calls.some(call => call.args.some(arg => arg.includes(signing.APPLE_SIGNING_P12_PASSWORD))), false);
  assert.equal(calls.some(call => call.input?.includes(signing.APPLE_SIGNING_P12_PASSWORD)), true);
  let failed = false;
  await assert.rejects(cleanupSigning(directory, (tool, args, options) => { if (!failed && options?.input?.includes('delete-keychain')) { failed = true; throw new Error('fixed interruption'); } return execute(tool, args, options); }), /retry/);
  for (const name of ['signing.p12', 'AuthKey.p8', 'sparkle.key']) await assert.rejects(lstat(path.join(directory, name)), { code: 'ENOENT' });
  const state = JSON.parse(await readFile(path.join(directory, 'state.json'), 'utf8')); assert.equal(state.keychainCreated, true); assert.equal(JSON.stringify(state).includes('fixture-p12-secret'), false);
  await cleanupSigning(directory, execute); assert.equal(JSON.parse(await readFile(path.join(directory, 'state.json'), 'utf8')).keychainCreated, false);
}, 'etcpro6-public-release-'));

test('encrypted recovery authenticates exact DMG bytes and metadata, rejects wrong key/tampering', async () => temporary(async directory => {
  const dmg = path.join(directory, 'ETCPRO6-0.1.0+1.dmg'), bytes = Buffer.from('private-not-yet-published-dmg'); await writeFile(dmg, bytes);
  const receipts = path.join(directory, 'receipts'); await mkdir(receipts); const metadata = { submissionId: '11111111-1111-4111-8111-111111111111', submittedSHA256: sha256(bytes), artifactName: path.basename(dmg) };
  await encryptRecovery(dmg, receipts, metadata, key);
  assert.equal((await readFile(path.join(receipts, 'recovery.bin'))).includes(bytes), false);
  assert.deepEqual(await decryptRecovery(receipts, path.join(directory, 'restored.dmg'), key), metadata);
  assert.deepEqual(await readFile(path.join(directory, 'restored.dmg')), bytes);
  await assert.rejects(decryptRecovery(receipts, path.join(directory, 'wrong.dmg'), Buffer.alloc(32, 8).toString('base64')), /authentication/);
  const e = JSON.parse(await readFile(path.join(receipts, 'recovery.json'), 'utf8')); e.metadata.artifactName = 'ETCPRO6-0.1.0+2.dmg'; await writeFile(path.join(receipts, 'recovery.json'), JSON.stringify(e));
  await assert.rejects(decryptRecovery(receipts, path.join(directory, 'tampered.dmg'), key), /authentication/);
}));

test('notary timeout resumes the exact submission and refuses a second submit', async () => temporary(async directory => {
  const dmg = path.join(directory, 'ETCPRO6-0.1.0+1.dmg'); await writeFile(dmg, 'fixture-dmg'); const receipts = path.join(directory, 'receipts'); await mkdir(receipts);
  const m = manifest(zipFixture(archiveEntries())), calls = [], id = '11111111-1111-4111-8111-111111111111'; let status = 'In Progress';
  const execute = (_tool, args) => { calls.push(args); return { status: args[1] === 'wait' && status !== 'Accepted' ? 1 : 0, stdout: JSON.stringify({ id, status }), stderr: '' }; };
  const notaryEnv = { APPLE_NOTARY_KEY_ID: 'ABCDEFGHIJ', APPLE_NOTARY_ISSUER_ID: id, APPLE_TEAM_ID: 'KLMNOPQRST', RECOVERY_ENCRYPTION_KEY: key };
  await assert.rejects(notarize(dmg, m, directory, receipts, notaryEnv, execute), /not accepted/);
  const receipt = JSON.parse(await readFile(path.join(receipts, 'notary.json'), 'utf8')); assert.equal(receipt.submissionId, id);
  assert.equal((await lstat(path.join(receipts, 'notary-recovery.bin'))).isFile(), true);
  await assert.rejects(notarize(dmg, m, directory, receipts, notaryEnv, execute), /exists/);
  status = 'Accepted'; assert.equal((await notarize(dmg, m, directory, receipts, notaryEnv, execute, receipt)).status, 'Accepted');
  assert.equal(calls.filter(args => args[1] === 'submit').length, 1); assert.equal(calls.filter(args => ['wait', 'info'].includes(args[1])).every(args => args[2] === id), true);
}));

test('lost notary submit response retains authenticated bytes before any ID is available', async () => temporary(async directory => {
  const dmg = path.join(directory, 'ETCPRO6-0.1.0+1.dmg'); await writeFile(dmg, 'accepted-by-Apple-response-lost'); const receipts = path.join(directory, 'receipts'); await mkdir(receipts);
  const m = manifest(zipFixture(archiveEntries())), calls = [];
  const execute = (_tool, args) => { calls.push(args); return { status: 1, stdout: '', stderr: 'private service response' }; };
  const notaryEnv = { APPLE_NOTARY_KEY_ID: 'ABCDEFGHIJ', APPLE_NOTARY_ISSUER_ID: '11111111-1111-4111-8111-111111111111', APPLE_TEAM_ID: 'KLMNOPQRST', RECOVERY_ENCRYPTION_KEY: key };
  await assert.rejects(notarize(dmg, m, directory, receipts, notaryEnv, execute), /submission ID/);
  const restored = path.join(directory, 'restored.dmg'), metadata = await decryptRecovery(receipts, restored, key, 'submission-recovery');
  assert.equal(metadata.stage, 'submission-unknown'); assert.equal(metadata.submittedSHA256, sha256(await readFile(dmg))); assert.deepEqual(await readFile(restored), await readFile(dmg));
  await assert.rejects(notarize(dmg, m, directory, receipts, notaryEnv, execute)); assert.equal(calls.filter(args => args[1] === 'submit').length, 1);
}));

function releaseFixture() {
  const artifact = Buffer.from('signed-dmg-fixture'), appcast = Buffer.from('signed-feed-fixture');
  const m = { schemaVersion: 1, releaseId: '0.1.0+1', version: '0.1.0', build: 1, minimumSystemVersion: '14.0', artifact: { key: 'releases/0.1.0+1/ETCPRO6-0.1.0+1.dmg', size: artifact.length, sha256: sha256(artifact), sparkleEdSignature: 'A'.repeat(86) + '==' }, appcast: { key: 'releases/0.1.0+1/appcast.xml', size: appcast.length, sha256: sha256(appcast) }, source: { commit: 'a'.repeat(40), tag: 'v0.1.0', workflowRunId: '123' }, notarization: { submissionId: '11111111-1111-4111-8111-111111111111', status: 'Accepted' }, createdAt: '2026-11-14T00:00:00.000Z' };
  return { m, artifact, appcast };
}
test('candidate publication cannot promote, stable uses its own token/CAS and preserves receipt after probe failure', async () => temporary(async directory => {
  const { m, artifact, appcast } = releaseFixture(), calls = []; let finalized = false, stable = false, failStable = false;
  const fetcher = async (url, options) => {
    const u = new URL(url); calls.push({ path: u.pathname, id: options.headers?.['CF-Access-Client-Id'] });
    if (u.pathname === '/api/releases/init') { finalized = true; return Response.json({ finalized: true }); }
    if (u.pathname === '/api/releases') return Response.json({ releases: finalized ? [m] : [], stable: null });
    if (u.pathname === '/api/channels/stable/promote') { assert.equal(options.headers['CF-Access-Client-Id'], 'channel'); assert.deepEqual(JSON.parse(options.body), { releaseId: m.releaseId, sha256: m.artifact.sha256, expectedETag: null, expectedBuild: null }); stable = true; return Response.json({ releaseId: m.releaseId, sha256: m.artifact.sha256, build: 1, etag: '"revision"', auditKey: 'audit/fixture.json' }); }
    const isFeed = u.pathname.endsWith('appcast.xml');
    if (u.pathname === '/stable/appcast.xml' && failStable) return new Response('unavailable', { status: 503 });
    return new Response(isFeed ? appcast : artifact, { headers: { ETag: '"fixture"', 'Cache-Control': u.pathname === '/stable/appcast.xml' ? 'public, max-age=60' : 'public, immutable' } });
  };
  await publishCandidate(m, directory, directory, env, fetcher); assert.equal(stable, false); assert.equal(calls.some(call => call.path.includes('/promote')), false);
  const stableEnv = { UPDATE_ADMIN_BASE_URL: env.UPDATE_ADMIN_BASE_URL, UPDATE_PUBLIC_BASE_URL: env.UPDATE_PUBLIC_BASE_URL, CF_CHANNEL_ACCESS_CLIENT_ID: 'channel', CF_CHANNEL_ACCESS_CLIENT_SECRET: 'channel-secret' };
  await assert.rejects(promote(path.join(directory, 'candidate.json'), directory, { ...stableEnv, APPLE_SIGNING_P12: 'secret' }, fetcher), /must not enter/);
  failStable = true; await assert.rejects(promote(path.join(directory, 'candidate.json'), directory, stableEnv, fetcher), /503/);
  assert.equal(JSON.parse(await readFile(path.join(directory, 'stable.json'), 'utf8')).etag, '"revision"');
  const receipt = await readFile(path.join(directory, 'candidate.json'), 'utf8'); for (const secret of ['candidate-secret-never-log', 'staging-secret-never-log', 'channel-secret']) assert.equal(receipt.includes(secret), false);
}));

test('post-staple recovery reuses exact manifest/DMG/feed after production finalizes and staging fails', async () => temporary(async directory => {
  const { m, artifact, appcast } = releaseFixture(), unsigned = manifest(zipFixture(archiveEntries()));
  const signingEnv = { ...env, APPLE_TEAM_ID: 'ABCDEFGHIJ', RECOVERY_ENCRYPTION_KEY: key }, work = path.join(directory, 'work'), receipts = path.join(directory, 'receipts'); await mkdir(work); await mkdir(receipts);
  await writeFile(path.join(work, path.basename(m.artifact.key)), artifact); await writeFile(path.join(work, 'appcast.xml'), appcast);
  await snapshotCandidate(path.join(work, path.basename(m.artifact.key)), unsigned, m, { submissionId: m.notarization.submissionId, manifestCreatedAt: m.createdAt, status: 'Accepted' }, work, receipts, signingEnv);
  let failStaging = true, productionManifest = null, stagingManifest = null; const calls = [];
  const fetcher = async (url, options) => {
    const u = new URL(url); calls.push(u.pathname);
    if (u.pathname === '/api/releases/init') {
      const value = JSON.parse(options.body);
      if (u.origin === env.UPDATE_ADMIN_BASE_URL) { if (productionManifest && JSON.stringify(productionManifest) !== JSON.stringify(value)) return new Response('conflict', { status: 409 }); productionManifest = value; return Response.json({ finalized: true }); }
      if (failStaging) return new Response('temporary staging failure', { status: 503 }); stagingManifest = value; return Response.json({ finalized: true });
    }
    if (u.pathname === '/api/releases') return Response.json({ releases: [productionManifest], stable: null });
    return new Response(u.pathname.endsWith('appcast.xml') ? appcast : artifact, { headers: { ETag: '"fixture"', 'Cache-Control': 'public, immutable' } });
  };
  await assert.rejects(publishCandidate(m, work, receipts, signingEnv, fetcher), /503/); assert.deepEqual(productionManifest, m);
  const restoredWork = path.join(directory, 'restored'); await mkdir(restoredWork); const restored = await restoreCandidate(receipts, restoredWork, signingEnv);
  assert.deepEqual(restored.manifest, m); assert.deepEqual(await readFile(path.join(restoredWork, path.basename(m.artifact.key))), artifact); assert.deepEqual(await readFile(path.join(restoredWork, 'appcast.xml')), appcast);
  failStaging = false; await publishCandidate(restored.manifest, restoredWork, receipts, signingEnv, fetcher);
  assert.deepEqual(stagingManifest, productionManifest); assert.equal(stagingManifest.createdAt, m.createdAt); assert.equal(calls.some(item => item.includes('notary')), false);
}));
