import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { sha256 } from '../tools/archive.mjs';
import { encryptRecovery } from '../tools/release.mjs';
import { downloadCandidate, downloadRecovery, recoveryFiles, retainRecovery, verifyRecoveryRequest } from './verify-recovery.mjs';
import { zipFixture, zip64Fixture } from '../test/helpers.mjs';

const repository = 'AonBit/ETCPRO6-Release', commit = 'a'.repeat(40), token = 'fixture-public-actions-token-do-not-print';
const request = { RECOVERY_REPOSITORY: repository, RECOVERY_RUN_ID: '123', RECOVERY_ARTIFACT_ID: '456', GH_RECOVERY_TOKEN: token };
const valid = {
  run: { id: 123, repository: { full_name: repository }, head_repository: { full_name: repository }, head_sha: commit, head_branch: 'main', event: 'workflow_dispatch', status: 'completed', conclusion: 'failure', path: '.github/workflows/release.yml', run_attempt: 2 },
  artifact: { id: 456, name: 'encrypted-notary-recovery-123-2', expired: false, size_in_bytes: 4096, digest: `sha256:${'b'.repeat(64)}`, workflow_run: { id: 123, head_sha: commit } },
  comparison: { status: 'ahead', base_commit: { sha: commit }, merge_base_commit: { sha: commit } },
};
function github(values = valid) { return async (url, options) => {
  assert.equal(options.headers.Authorization, `Bearer ${token}`); assert.equal(options.redirect, 'error');
  if (url.endsWith('/actions/artifacts/456')) return Response.json(values.artifact);
  if (url.endsWith('/actions/runs/123/attempts/2')) return Response.json(values.run);
  if (url.endsWith(`/compare/${commit}...main`)) return Response.json(values.comparison);
  throw new Error('Unexpected test API');
}; }
async function temporary(body) { const directory = await mkdtemp(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'etcpro6-recovery-test-')); try { return await body(directory); } finally { await rm(directory, { recursive: true, force: true }); } }
const unsigned = { schemaVersion: 1, repository: 'AonBit/ETCPRO6-MAC', commit, workflowRunId: '321', workflowPath: '.github/workflows/release-build.yml', version: '0.1.0', build: 1, releaseId: '0.1.0+1', archive: { file: 'ETCPRO6-unsigned.xcarchive.zip', size: 100, sha256: 'c'.repeat(64) }, sparkle: { version: '2.10.1', revision: 'ab7d71291238df6e0492143b120c9b696a35f603' }, updates: { feedURL: 'https://updates.aonbit.test/stable/appcast.xml', publicKeySHA256: 'd'.repeat(64) } };
const notary = { submissionId: '11111111-1111-4111-8111-111111111111', status: 'Accepted', submittedSHA256: sha256('fixture ciphertext plaintext'), artifactName: 'ETCPRO6-0.1.0+1.dmg', manifestCreatedAt: '2026-11-14T00:00:00.000Z' };
const manifest = { schemaVersion: 1, releaseId: '0.1.0+1', version: '0.1.0', build: 1, minimumSystemVersion: '14.0', artifact: { key: 'releases/0.1.0+1/ETCPRO6-0.1.0+1.dmg', size: 1, sha256: 'e'.repeat(64), sparkleEdSignature: 'A'.repeat(86) + '==' }, appcast: { key: 'releases/0.1.0+1/appcast.xml', size: 1, sha256: 'f'.repeat(64) }, source: { commit, tag: 'v0.1.0', workflowRunId: '321' }, notarization: { submissionId: notary.submissionId, status: 'Accepted' }, createdAt: notary.manifestCreatedAt };
async function snapshot(directory, name) {
  await mkdir(directory, { recursive: true }); const plain = path.join(directory, 'fixture.dmg'); await writeFile(plain, 'fixture ciphertext plaintext');
  const common = { unsignedManifest: unsigned, signingTeamID: 'ABCDEFGHIJ', artifactName: notary.artifactName };
  const metadata = name === 'candidate-recovery' ? { stage: 'candidate', payloadSHA256: notary.submittedSHA256, ...common, manifest, notaryReceipt: notary } : name === 'notary-recovery' ? { stage: 'notary', ...notary, ...common } : { stage: 'submission-unknown', submittedSHA256: notary.submittedSHA256, manifestCreatedAt: notary.manifestCreatedAt, ...common };
  await encryptRecovery(plain, directory, metadata, Buffer.alloc(32, 7).toString('base64'), name); await rm(plain);
  return Promise.all((await readdir(directory)).map(async filename => ({ name: filename, kind: 'file', data: await readFile(path.join(directory, filename)) })));
}
function blobFetcher(bytes, artifact) { let calls = 0; return async (url, options) => {
  if (url === `https://api.github.com/repos/${repository}/actions/artifacts/${artifact.id}/zip`) { assert.equal(options.headers.Authorization, `Bearer ${token}`); calls++; return new Response(null, { status: 302, headers: { Location: 'https://fixture.blob.core.windows.net/recovery?signed=fixture' } }); }
  assert.equal(url, 'https://fixture.blob.core.windows.net/recovery?signed=fixture'); assert.equal(options.headers, undefined); assert.equal(options.redirect, 'error'); calls++; return new Response(bytes);
}; }

test('recovery binds an exact failed trusted public main attempt and artifact', async () => {
  const verified = await verifyRecoveryRequest(request, github());
  assert.equal(verified.commit, commit); assert.equal(verified.workflow.runAttempt, 2); assert.equal(verified.artifact.name, valid.artifact.name); assert.equal(verified.artifact.digest, 'b'.repeat(64));
  assert.equal(JSON.stringify(verified).includes(token), false);
  for (const path of ['.github/workflows/release.yml', '.github/workflows/recover.yml']) for (const conclusion of ['failure', 'timed_out', 'cancelled']) {
    const values = structuredClone(valid); values.run.path = path; values.run.conclusion = conclusion; assert.equal((await verifyRecoveryRequest(request, github(values))).workflow.conclusion, conclusion);
  }
});
test('recovery rejects wrong repository, workflow, branch, conclusion, attempt, artifact and main ancestry', async () => {
  for (const mutate of [
    v => { v.run.repository.full_name = 'attacker/repo'; }, v => { v.run.head_repository.full_name = 'attacker/repo'; },
    v => { v.run.path = '.github/workflows/ci.yml'; }, v => { v.run.head_branch = 'feature'; }, v => { v.run.event = 'pull_request'; },
    v => { v.run.status = 'in_progress'; }, v => { v.run.conclusion = 'success'; }, v => { v.run.run_attempt = 3; },
    v => { v.artifact.expired = true; }, v => { v.artifact.name = 'encrypted-notary-recovery-999-2'; }, v => { v.artifact.workflow_run.id = 999; },
    v => { v.artifact.workflow_run.head_sha = 'c'.repeat(40); }, v => { v.artifact.digest = 'sha256:bad'; }, v => { v.artifact.size_in_bytes = 0; },
    v => { v.comparison.status = 'diverged'; }, v => { v.comparison.merge_base_commit.sha = 'c'.repeat(40); },
  ]) { const values = structuredClone(valid); mutate(values); await assert.rejects(verifyRecoveryRequest(request, github(values))); }
  for (const patch of [{ RECOVERY_REPOSITORY: 'attacker/repo' }, { RECOVERY_RUN_ID: 'latest' }, { RECOVERY_ARTIFACT_ID: '0' }, { NOTARY_SUBMISSION_ID: notary.submissionId }]) {
    let called = false; await assert.rejects(verifyRecoveryRequest({ ...request, ...patch }, async () => { called = true; throw new Error(); })); assert.equal(called, false);
  }
});

test('recovery download hard-fails outer digest mismatch and permits only complete AES snapshot pairs', async () => temporary(async directory => {
  const entries = await snapshot(path.join(directory, 'source'), 'notary-recovery');
  for (const zip of [zipFixture, zip64Fixture]) {
    const bytes = zip(entries), verified = { schemaVersion: 1, repository, workflow: { path: '.github/workflows/release.yml' }, artifact: { repository, id: 456, size: bytes.length, digest: sha256(bytes) } }, destination = path.join(directory, zip === zipFixture ? 'classic' : 'zip64');
    await downloadRecovery(verified, destination, token, blobFetcher(bytes, verified.artifact)); assert.equal((await readdir(destination)).length, 2);
    await assert.rejects(downloadRecovery({ ...verified, artifact: { ...verified.artifact, digest: '0'.repeat(64) } }, `${destination}-tampered`, token, blobFetcher(bytes, verified.artifact)));
  }
  for (const files of [[entries[0]], [...entries, { name: '../escape', kind: 'file', data: Buffer.from('evil') }], [...entries, { name: 'private.swift', kind: 'file', data: Buffer.from('private') }], entries.map((entry, i) => i === 0 ? { ...entry, kind: 'symlink' } : entry)]) assert.throws(() => recoveryFiles(files));
  const corrupt = entries.map(entry => entry.name.endsWith('.bin') ? { ...entry, data: Buffer.from('changed ciphertext') } : entry); assert.throws(() => recoveryFiles(corrupt));
}));

test('another recovery timeout preserves original snapshots and independently adds a complete advanced stage', async () => temporary(async directory => {
  const source = path.join(directory, 'source'), generated = path.join(directory, 'generated'), retained = path.join(directory, 'retained');
  await snapshot(source, 'notary-recovery'); const originalCipher = await readFile(path.join(source, 'notary-recovery.bin'));
  await mkdir(generated); await writeFile(path.join(generated, 'notary.json'), '{"sanitized":"receipt"}');
  await retainRecovery(source, generated, retained); assert.deepEqual(await readFile(path.join(retained, 'notary-recovery.bin')), originalCipher);
  await snapshot(generated, 'candidate-recovery'); await retainRecovery(source, generated, `${retained}-advanced`);
  assert.deepEqual((await readdir(`${retained}-advanced`)).sort(), ['candidate-recovery.bin', 'candidate-recovery.json', 'notary-recovery.bin', 'notary-recovery.json']);
  assert.deepEqual(await readFile(path.join(source, 'notary-recovery.bin')), originalCipher); assert.equal((await readdir(source)).length, 2);
  await writeFile(path.join(generated, 'submission-recovery.bin'), 'incomplete'); await assert.rejects(retainRecovery(source, generated, `${retained}-partial`));
  assert.deepEqual(await readFile(path.join(source, 'notary-recovery.bin')), originalCipher);
}));

test('stable downloads only the exact current recovery candidate artifact and hard-verifies digest', async () => temporary(async directory => {
  const receipt = { schemaVersion: 1, manifest, expectedETag: null, expectedBuild: null, stagingVerified: true }, bytes = zipFixture([{ name: 'candidate.json', data: JSON.stringify(receipt) }]), artifact = { id: 789, name: 'approved-candidate-123-2', expired: false, size_in_bytes: bytes.length, digest: `sha256:${sha256(bytes)}`, workflow_run: { id: 123, head_sha: commit } };
  const env = { GH_RECOVERY_TOKEN: token, CURRENT_RUN_ID: '123', CURRENT_RUN_ATTEMPT: '2', CURRENT_COMMIT: commit, CANDIDATE_ARTIFACT_ID: '789' };
  const fetcher = async (url, options) => url.endsWith('/actions/artifacts/789') ? Response.json(artifact) : blobFetcher(bytes, artifact)(url, options);
  const output = path.join(directory, 'candidate'); await downloadCandidate(env, output, fetcher); assert.deepEqual(JSON.parse(await readFile(path.join(output, 'candidate.json'), 'utf8')), receipt);
  artifact.digest = `sha256:${'0'.repeat(64)}`; await assert.rejects(downloadCandidate(env, `${output}-changed`, fetcher));
  artifact.digest = `sha256:${sha256(bytes)}`; artifact.workflow_run.id = 999; await assert.rejects(downloadCandidate(env, `${output}-wrong-run`, fetcher));
}));
