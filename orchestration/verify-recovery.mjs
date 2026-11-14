import { lstat, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, zipEntries } from '../tools/archive.mjs';
import { strictBase64, validateReleaseManifest } from '../tools/release.mjs';
import { downloadReleaseArtifact } from './download-release-artifact.mjs';

const repository = 'AonBit/ETCPRO6-Release';
const workflows = ['.github/workflows/release.yml', '.github/workflows/recover.yml'];
const stages = ['submission-recovery', 'notary-recovery', 'candidate-recovery'];
const names = stages.flatMap(stage => [`${stage}.bin`, `${stage}.json`]);
const hash = /^[a-f0-9]{64}$/, commit = /^[a-f0-9]{40}$/, integer = /^[1-9]\d*$/;
const fail = () => { throw new Error('Recovery verification rejected'); };
const exact = (value, keys) => { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail(); };
const positive = value => typeof value === 'string' && integer.test(value) && Number.isSafeInteger(Number(value));
async function api(route, token, fetcher) {
  let response; try { response = await fetcher(`https://api.github.com/repos/${repository}${route}`, { redirect: 'error', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, signal: AbortSignal.timeout(15_000) }); } catch { fail(); }
  if (!response.ok) fail(); try { return await response.json(); } catch { fail(); }
}
function tokenValue(env) { const value = env.GH_RECOVERY_TOKEN; if (typeof value !== 'string' || value.length < 20 || value.length > 4096 || /[\r\n\0]/.test(value)) fail(); return value; }
function artifactValue(artifact, id, runId, sha, expectedName) {
  const digest = typeof artifact.digest === 'string' ? artifact.digest.match(/^sha256:([a-f0-9]{64})$/) : null;
  if (artifact.id !== Number(id) || artifact.name !== expectedName || artifact.expired !== false || !Number.isSafeInteger(artifact.size_in_bytes) || artifact.size_in_bytes < 1 || artifact.size_in_bytes > 1024 ** 3 + 4 * 1024 ** 2 || artifact.workflow_run?.id !== Number(runId) || artifact.workflow_run?.head_sha !== sha || !digest) fail();
  return { repository, id: artifact.id, name: artifact.name, size: artifact.size_in_bytes, digest: digest[1] };
}

export async function verifyRecoveryRequest(env, fetcher = fetch) {
  if (env.RECOVERY_REPOSITORY !== repository || !positive(env.RECOVERY_RUN_ID) || !positive(env.RECOVERY_ARTIFACT_ID)) fail();
  const token = tokenValue(env), runId = env.RECOVERY_RUN_ID, artifactId = env.RECOVERY_ARTIFACT_ID;
  const operatorId = env.NOTARY_SUBMISSION_ID || '', operatorHash = env.CONFIRM_SUBMISSION_SHA256 || '';
  if ((operatorId || operatorHash) && (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(operatorId) || !hash.test(operatorHash))) fail();
  const artifact = await api(`/actions/artifacts/${artifactId}`, token, fetcher), matched = artifact.name?.match(new RegExp(`^encrypted-notary-recovery-${runId}-([1-9][0-9]*)$`));
  if (!matched || !positive(matched[1])) fail();
  const attempt = matched[1], run = await api(`/actions/runs/${runId}/attempts/${attempt}`, token, fetcher);
  if (run.id !== Number(runId) || run.repository?.full_name !== repository || run.head_repository?.full_name !== repository || run.head_branch !== 'main' || !commit.test(run.head_sha ?? '') || run.event !== 'workflow_dispatch' || run.status !== 'completed' || !['failure', 'timed_out', 'cancelled'].includes(run.conclusion) || !workflows.includes(run.path) || run.run_attempt !== Number(attempt)) fail();
  const comparison = await api(`/compare/${run.head_sha}...main`, token, fetcher);
  if (!['ahead', 'identical'].includes(comparison.status) || comparison.base_commit?.sha !== run.head_sha || comparison.merge_base_commit?.sha !== run.head_sha) fail();
  return { schemaVersion: 1, repository, commit: run.head_sha, workflow: { path: run.path, runId: Number(runId), runAttempt: Number(attempt), conclusion: run.conclusion }, artifact: artifactValue(artifact, artifactId, runId, run.head_sha, artifact.name), ...(operatorId ? { operatorBinding: { submissionId: operatorId, submittedSHA256: operatorHash } } : {}) };
}
function unsigned(value) {
  exact(value, ['schemaVersion', 'repository', 'commit', 'workflowRunId', 'workflowPath', 'version', 'build', 'releaseId', 'archive', 'sparkle', 'updates']);
  exact(value.archive, ['file', 'size', 'sha256']); exact(value.sparkle, ['version', 'revision']); exact(value.updates, ['feedURL', 'publicKeySHA256']);
  if (value.schemaVersion !== 1 || value.repository !== 'AonBit/ETCPRO6-MAC' || !commit.test(value.commit ?? '') || !integer.test(String(value.workflowRunId)) || value.workflowPath !== '.github/workflows/release-build.yml' || !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value.version ?? '') || !Number.isSafeInteger(value.build) || value.build < 1 || value.releaseId !== `${value.version}+${value.build}` || value.archive.file !== 'ETCPRO6-unsigned.xcarchive.zip' || !hash.test(value.archive.sha256 ?? '') || !Number.isSafeInteger(value.archive.size) || value.archive.size < 1 || value.archive.size > 1024 ** 3 || value.sparkle.version !== '2.10.1' || value.sparkle.revision !== 'ab7d71291238df6e0492143b120c9b696a35f603' || !hash.test(value.updates.publicKeySHA256 ?? '')) fail();
  let feed; try { feed = new URL(value.updates.feedURL); } catch { fail(); }
  if (feed.protocol !== 'https:' || feed.username || feed.password || feed.pathname !== '/stable/appcast.xml' || feed.search || feed.hash) fail();
}
function notary(value, allowExtra = false) {
  const keys = ['submissionId', 'status', 'submittedSHA256', 'artifactName', 'manifestCreatedAt'];
  if (allowExtra) { for (const key of Object.keys(value)) if (!keys.includes(key) && !['stage', 'unsignedManifest', 'signingTeamID'].includes(key)) fail(); }
  else exact(value, keys);
  if (!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value.submissionId ?? '') || !['Submitted', 'In Progress', 'Accepted', 'Invalid'].includes(value.status) || !hash.test(value.submittedSHA256 ?? '') || !Number.isFinite(Date.parse(value.manifestCreatedAt))) fail();
}
function validateEnvelope(envelope, stage, ciphertext) {
  exact(envelope, ['schemaVersion', 'algorithm', 'iv', 'tag', 'encryptedSHA256', 'metadata']);
  if (envelope.schemaVersion !== 1 || envelope.algorithm !== 'AES-256-GCM' || !hash.test(envelope.encryptedSHA256 ?? '') || envelope.encryptedSHA256 !== sha256(ciphertext)) fail();
  strictBase64(envelope.iv, [12]); strictBase64(envelope.tag, [16]);
  const m = envelope.metadata;
  if (stage === 'submission-recovery') exact(m, ['stage', 'submittedSHA256', 'artifactName', 'unsignedManifest', 'signingTeamID', 'manifestCreatedAt']);
  else if (stage === 'notary-recovery') exact(m, ['stage', 'submissionId', 'status', 'submittedSHA256', 'artifactName', 'manifestCreatedAt', 'unsignedManifest', 'signingTeamID']);
  else exact(m, ['stage', 'payloadSHA256', 'artifactName', 'unsignedManifest', 'signingTeamID', 'manifest', 'notaryReceipt']);
  unsigned(m.unsignedManifest);
  if (!/^[A-Z0-9]{10}$/.test(m.signingTeamID ?? '') || m.artifactName !== `ETCPRO6-${m.unsignedManifest.releaseId}.dmg`) fail();
  if (stage === 'candidate-recovery') {
    if (m.stage !== 'candidate' || !hash.test(m.payloadSHA256 ?? '')) fail(); validateReleaseManifest(m.manifest); notary(m.notaryReceipt, true);
    if (m.manifest.source.commit !== m.unsignedManifest.commit || m.manifest.releaseId !== m.unsignedManifest.releaseId || m.manifest.notarization.submissionId !== m.notaryReceipt.submissionId) fail();
  } else {
    if (m.stage !== (stage === 'submission-recovery' ? 'submission-unknown' : 'notary') || !hash.test(m.submittedSHA256 ?? '') || !Number.isFinite(Date.parse(m.manifestCreatedAt))) fail();
    if (stage === 'notary-recovery') notary(Object.fromEntries(['submissionId', 'status', 'submittedSHA256', 'artifactName', 'manifestCreatedAt'].map(key => [key, m[key]])));
  }
  return envelope;
}

export function recoveryFiles(entries) {
  if (!entries.length || entries.length > 6 || entries.some(entry => entry.kind !== 'file' || !names.includes(entry.name))) fail();
  const files = new Map(entries.map(entry => [entry.name, entry.data]));
  for (const stage of stages) {
    const cipher = files.get(`${stage}.bin`), encoded = files.get(`${stage}.json`);
    if (!!cipher !== !!encoded) fail();
    if (cipher) { if (!cipher.length || cipher.length > 1024 ** 3 + 2 * 1024 ** 2 || encoded.length > 128 * 1024) fail(); let envelope; try { envelope = JSON.parse(encoded); } catch { fail(); } validateEnvelope(envelope, stage, cipher); }
  }
  return files;
}
export async function downloadRecovery(verified, destination, token, fetcher = fetch) {
  if (verified?.schemaVersion !== 1 || verified.repository !== repository || verified.artifact?.repository !== repository || !workflows.includes(verified.workflow?.path)) fail();
  const bytes = await downloadReleaseArtifact(verified.artifact, token, fetcher), entries = zipEntries(bytes, { maximumBytes: 2 * 1024 ** 3, maximumEntries: 6 }), files = recoveryFiles(entries);
  await mkdir(destination, { mode: 0o700 }); for (const [name, data] of files) await writeFile(path.join(destination, name), data, { flag: 'wx', mode: 0o600 });
}
async function directoryEntries(directory, strict = true) {
  let listed; try { const info = await lstat(directory); if (!info.isDirectory() || info.isSymbolicLink()) fail(); listed = await readdir(directory); } catch (error) { if (!strict && error.code === 'ENOENT') return []; throw error; }
  const entries = [];
  for (const name of listed) {
    if (!names.includes(name)) { if (strict) fail(); continue; }
    const file = path.join(directory, name), info = await lstat(file); if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > 1024 ** 3 + 2 * 1024 ** 2) fail();
    entries.push({ name, kind: 'file', data: await readFile(file) });
  }
  return entries;
}
export async function retainRecovery(source, generated, destination) {
  const original = recoveryFiles(await directoryEntries(source)), freshEntries = await directoryEntries(generated, false), fresh = freshEntries.length ? recoveryFiles(freshEntries) : new Map(), merged = new Map(original);
  for (const [name, data] of fresh) merged.set(name, data);
  recoveryFiles([...merged].map(([name, data]) => ({ name, kind: 'file', data })));
  await mkdir(destination, { mode: 0o700 });
  for (const [name, data] of merged) await writeFile(path.join(destination, name), data, { flag: 'wx', mode: 0o600 });
}

export async function downloadCandidate(env, destination, fetcher = fetch) {
  if (!positive(env.CURRENT_RUN_ID) || !positive(env.CURRENT_RUN_ATTEMPT) || !positive(env.CANDIDATE_ARTIFACT_ID) || !commit.test(env.CURRENT_COMMIT ?? '')) fail();
  const token = tokenValue(env), artifact = await api(`/actions/artifacts/${env.CANDIDATE_ARTIFACT_ID}`, token, fetcher), expectedName = `approved-candidate-${env.CURRENT_RUN_ID}-${env.CURRENT_RUN_ATTEMPT}`;
  const binding = artifactValue(artifact, env.CANDIDATE_ARTIFACT_ID, env.CURRENT_RUN_ID, env.CURRENT_COMMIT, expectedName), bytes = await downloadReleaseArtifact(binding, token, fetcher), entries = zipEntries(bytes, { maximumBytes: 128 * 1024, maximumEntries: 1 });
  if (entries.length !== 1 || entries[0].name !== 'candidate.json' || entries[0].kind !== 'file' || entries[0].data.length > 64 * 1024) fail();
  let receipt; try { receipt = JSON.parse(entries[0].data); } catch { fail(); }
  exact(receipt, ['schemaVersion', 'manifest', 'expectedETag', 'expectedBuild', 'stagingVerified']); validateReleaseManifest(receipt.manifest);
  if (receipt.schemaVersion !== 1 || receipt.stagingVerified !== true) fail();
  await mkdir(destination, { mode: 0o700 }); await writeFile(path.join(destination, 'candidate.json'), entries[0].data, { mode: 0o600, flag: 'wx' });
}
async function main(args, env = process.env) {
  if (args[0] === 'verify' && args.length === 2) { const verified = await verifyRecoveryRequest(env); await writeFile(args[1], `${JSON.stringify(verified, null, 2)}\n`, { flag: 'wx', mode: 0o600 }); return; }
  if (args[0] === 'download' && args.length === 3) return downloadRecovery(JSON.parse(await readFile(args[1], 'utf8')), args[2], env.GH_RECOVERY_TOKEN);
  if (args[0] === 'retain' && args.length === 4) return retainRecovery(args[1], args[2], args[3]);
  if (args[0] === 'download-candidate' && args.length === 2) return downloadCandidate(env, args[1]);
  fail();
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2)).catch(() => { console.error('Recovery verification or preservation failed; original recovery artifact remains authoritative. Details suppressed.'); process.exitCode = 1; });
