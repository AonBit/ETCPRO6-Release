#!/usr/bin/env node
// Trusted public release executor. Inputs are data; no private source or input script is run.
import { createCipheriv, createDecipheriv, createHash, createPrivateKey, createPublicKey, randomBytes, timingSafeEqual } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { pipeline } from 'node:stream/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractArchive, sha256, zipEntries } from './archive.mjs';

export const SOURCE_REPOSITORY = 'AonBit/ETCPRO6-MAC';
export const SOURCE_WORKFLOW = '.github/workflows/release-build.yml';
export const SPARKLE_VERSION = '2.10.1';
export const SPARKLE_REVISION = 'ab7d71291238df6e0492143b120c9b696a35f603';
export const SPARKLE_URL = 'https://github.com/sparkle-project/Sparkle/releases/download/2.10.1/Sparkle-for-Swift-Package-Manager.zip';
export const SPARKLE_SHA256 = '4c2e48a3e50ebcc2c88a58a4c7264a1a99c3c31857ce754357afb9cdb323022a';
const BUNDLE_ID = 'jp.co.aonbit.ETCPRO6';
const hashPattern = /^[a-f0-9]{64}$/, commitPattern = /^[a-f0-9]{40}$/;
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const uuidPattern = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const signaturePattern = /^[A-Za-z0-9+/]{86}==$/;
const fail = message => { throw new Error(message); };
const required = (env, name) => { if (typeof env[name] !== 'string' || !env[name]) fail(`Missing required ${name}`); return env[name]; };
const json = async file => JSON.parse(await readFile(file, 'utf8'));
const equalJSON = (left, right) => JSON.stringify(canonical(left)) === JSON.stringify(canonical(right));
function canonical(value) { return Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value; }
function record(value, keys) { if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join(',') !== [...keys].sort().join(',')) fail('Invalid release input schema'); return value; }
async function regular(file, maximum = 1024 ** 3) { const info = await lstat(file); if (!info.isFile() || info.isSymbolicLink() || info.size < 1 || info.size > maximum) fail('Expected a bounded regular release file'); return info; }
async function saveJSON(file, value) { await mkdir(path.dirname(file), { recursive: true, mode: 0o700 }); await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 }); await chmod(file, 0o600); }
export function baseURL(value) { let url; try { url = new URL(value); } catch { fail('Invalid release origin'); } if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/' || /(?:example|replace|localhost)/i.test(url.hostname)) fail('Invalid release origin'); return url.origin; }
export function strictBase64(value, lengths) { if (typeof value !== 'string') fail('Invalid key encoding'); const bytes = Buffer.from(value, 'base64'); if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || bytes.toString('base64') !== value || !lengths.includes(bytes.length)) fail('Invalid key encoding'); return bytes; }
export function validateSparkleKey(secretValue, publicValue) {
  const secret = strictBase64(secretValue, [32, 96]), expected = strictBase64(publicValue, [32]);
  const actual = secret.length === 32 ? createPublicKey(createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), secret]), format: 'der', type: 'pkcs8' })).export({ format: 'der', type: 'spki' }).subarray(-32) : secret.subarray(64);
  if (!timingSafeEqual(actual, expected)) fail('Sparkle key pair mismatch');
  return secret;
}
export function childEnvironment(env = process.env) {
  const child = {};
  for (const name of ['PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'LC_CTYPE', 'DEVELOPER_DIR', '__CF_USER_TEXT_ENCODING']) if (typeof env[name] === 'string') child[name] = env[name];
  return child;
}
export function run(tool, args, options = {}) {
  const result = spawnSync(tool, args, { encoding: 'utf8', env: childEnvironment(), timeout: 30 * 60_000, maxBuffer: 8 * 1024 ** 2, ...options });
  if (result.error || (result.status !== 0 && !options.allowFailure)) fail('Trusted release tool failed; private output suppressed');
  return { stdout: result.stdout ?? '', stderr: result.stderr ?? '', status: result.status };
}
export function validateUnsignedManifest(m, verified, env) {
  record(m, ['schemaVersion', 'repository', 'commit', 'workflowRunId', 'workflowPath', 'version', 'build', 'releaseId', 'archive', 'sparkle', 'updates']);
  record(m.archive, ['file', 'size', 'sha256']); record(m.sparkle, ['version', 'revision']); record(m.updates, ['feedURL', 'publicKeySHA256']);
  if (m.schemaVersion !== 1 || m.repository !== SOURCE_REPOSITORY || !commitPattern.test(m.commit) || !/^\d+$/.test(String(m.workflowRunId)) || m.workflowPath !== SOURCE_WORKFLOW || !versionPattern.test(m.version) || !Number.isSafeInteger(m.build) || m.build < 1 || m.releaseId !== `${m.version}+${m.build}` || m.archive.file !== 'ETCPRO6-unsigned.xcarchive.zip' || !Number.isSafeInteger(m.archive.size) || m.archive.size < 1 || m.archive.size > 1024 ** 3 || !hashPattern.test(m.archive.sha256) || m.sparkle.version !== SPARKLE_VERSION || m.sparkle.revision !== SPARKLE_REVISION || !hashPattern.test(m.updates.publicKeySHA256)) fail('Unsigned archive manifest rejected');
  if (verified?.schemaVersion !== 1 || verified.repository !== m.repository || verified.commit !== m.commit || String(verified.workflow?.runId) !== String(m.workflowRunId) || verified.workflow?.path !== m.workflowPath || verified.releaseTag !== `v${m.version}` || !Number.isSafeInteger(Number(verified.artifact?.id)) || !hashPattern.test(verified.artifact?.digest ?? '')) fail('Archive provenance differs from approved request');
  const origin = baseURL(required(env, 'UPDATE_PUBLIC_BASE_URL'));
  if (m.updates.feedURL !== `${origin}/stable/appcast.xml` || m.updates.publicKeySHA256 !== sha256(strictBase64(required(env, 'ETCPRO6_UPDATE_PUBLIC_KEY'), [32]))) fail('Archive update configuration differs from approved environment');
  return m;
}
export async function inspectInput(inputDirectory, verifiedPath, env) {
  if ((await lstat(inputDirectory)).isSymbolicLink()) fail('Unsafe input directory');
  const directory = await realpath(inputDirectory), names = (await readdir(directory)).sort();
  if (names.join(',') !== 'ETCPRO6-unsigned.xcarchive.zip,unsigned-manifest.json') fail('Unexpected private input contents');
  await regular(path.join(directory, 'unsigned-manifest.json'), 64 * 1024); await regular(verifiedPath, 64 * 1024);
  const m = validateUnsignedManifest(await json(path.join(directory, 'unsigned-manifest.json')), await json(verifiedPath), env);
  const archive = path.join(directory, m.archive.file), info = await regular(archive);
  if (info.size !== m.archive.size || sha256(await readFile(archive)) !== m.archive.sha256) fail('Unsigned archive hash or size mismatch');
  return { manifest: m, archive, unsignedManifestSHA256: sha256(await readFile(path.join(directory, 'unsigned-manifest.json'))) };
}
function assertSecrets(env, resume = false) {
  for (const name of ['APPLE_NOTARY_KEY', 'APPLE_NOTARY_KEY_ID', 'APPLE_NOTARY_ISSUER_ID', 'SPARKLE_PRIVATE_KEY', 'ETCPRO6_UPDATE_PUBLIC_KEY', 'RECOVERY_ENCRYPTION_KEY', 'CF_CANDIDATE_ACCESS_CLIENT_ID', 'CF_CANDIDATE_ACCESS_CLIENT_SECRET', 'STAGING_CF_CANDIDATE_ACCESS_CLIENT_ID', 'STAGING_CF_CANDIDATE_ACCESS_CLIENT_SECRET']) required(env, name);
  strictBase64(env.RECOVERY_ENCRYPTION_KEY, [32]); validateSparkleKey(env.SPARKLE_PRIVATE_KEY, env.ETCPRO6_UPDATE_PUBLIC_KEY);
  if (env.CF_CHANNEL_ACCESS_CLIENT_ID || env.CF_CHANNEL_ACCESS_CLIENT_SECRET) fail('Channel credentials must not enter the candidate executor');
  if (!/^[A-Z0-9]{10}$/.test(env.APPLE_NOTARY_KEY_ID) || !uuidPattern.test(env.APPLE_NOTARY_ISSUER_ID)) fail('Invalid notary identity');
  if (!/^[A-Z0-9]{10}$/.test(required(env, 'APPLE_TEAM_ID'))) fail('Invalid signing team');
  try { if (createPrivateKey(env.APPLE_NOTARY_KEY).asymmetricKeyDetails?.namedCurve !== 'prime256v1') fail('Invalid notary key'); } catch { fail('Invalid notary key'); }
  if (!resume) {
    for (const name of ['APPLE_SIGNING_P12', 'APPLE_SIGNING_P12_PASSWORD', 'APPLE_SIGNING_IDENTITY', 'APPLE_TEAM_ID']) required(env, name);
    const p12 = Buffer.from(env.APPLE_SIGNING_P12, 'base64');
    if (!p12.length || p12.toString('base64') !== env.APPLE_SIGNING_P12 || p12.length > 1024 ** 2 || !/^[A-Z0-9]{10}$/.test(env.APPLE_TEAM_ID) || !/^Developer ID Application: [^\r\n]+$/.test(env.APPLE_SIGNING_IDENTITY) || !env.APPLE_SIGNING_IDENTITY.endsWith(`(${env.APPLE_TEAM_ID})`) || /[\r\n\0]/.test(env.APPLE_SIGNING_P12_PASSWORD)) fail('Invalid signing identity');
  }
  const origins = ['UPDATE_ADMIN_BASE_URL', 'UPDATE_PUBLIC_BASE_URL', 'STAGING_UPDATE_ADMIN_BASE_URL', 'STAGING_UPDATE_PUBLIC_BASE_URL'].map(name => baseURL(required(env, name)));
  if (new Set(origins).size !== 4) fail('Release origins must be distinct');
}
const securityWord = value => { if (/[\r\n\0]/.test(value)) fail('Invalid Keychain input'); return `"${value.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}"`; };
function securityInput(args, execute = run) {
  const result = execute('/usr/bin/security', ['-i'], { input: `${args.map(securityWord).join(' ')}\n` });
  // security's interactive interpreter may return zero after an individual command error.
  if (/(?:Sec[A-Za-z]+:|error:|failed|not found|denied|does not exist)/i.test(result.stderr)) fail('Keychain command failed; private details suppressed');
  return result;
}
export async function prepareSigning(directory, env, execute = run) {
  directory = await realpath(directory);
  const state = { directory, keychain: path.join(directory, 'signing.keychain-db'), originalSearchList: [], keychainCreated: false };
  await saveJSON(path.join(directory, 'state.json'), state);
  try {
    state.originalSearchList = [...execute('/usr/bin/security', ['list-keychains', '-d', 'user']).stdout.matchAll(/"([^"\r\n]+)"/g)].map(match => match[1]);
    if (!state.originalSearchList.length) fail('Cannot preserve Keychain search list');
    await saveJSON(path.join(directory, 'state.json'), state);
    await writeFile(path.join(directory, 'signing.p12'), Buffer.from(env.APPLE_SIGNING_P12, 'base64'), { mode: 0o600 });
    await writeFile(path.join(directory, 'AuthKey.p8'), env.APPLE_NOTARY_KEY, { mode: 0o600 });
    await writeFile(path.join(directory, 'sparkle.key'), env.SPARKLE_PRIVATE_KEY, { mode: 0o600 });
    const password = randomBytes(32).toString('hex');
    securityInput(['create-keychain', '-p', password, state.keychain], execute); state.keychainCreated = true; await saveJSON(path.join(directory, 'state.json'), state);
    securityInput(['set-keychain-settings', '-lut', '21600', state.keychain], execute);
    securityInput(['unlock-keychain', '-p', password, state.keychain], execute);
    securityInput(['import', path.join(directory, 'signing.p12'), '-k', state.keychain, '-P', env.APPLE_SIGNING_P12_PASSWORD, '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'], execute);
    securityInput(['set-key-partition-list', '-S', 'apple-tool:,apple:,codesign:', '-s', '-k', password, state.keychain], execute);
    securityInput(['list-keychains', '-d', 'user', '-s', state.keychain, ...state.originalSearchList], execute);
    if (!execute('/usr/bin/security', ['find-identity', '-v', '-p', 'codesigning', state.keychain]).stdout.includes(`"${env.APPLE_SIGNING_IDENTITY}"`)) fail('Imported Developer ID identity unavailable');
    return state;
  } catch (error) { try { await cleanupSigning(directory, execute); } catch { /* cleanup CLI is retryable */ } throw error; }
}
export async function cleanupSigning(directory, execute = run) {
  const actual = await realpath(directory), state = await json(path.join(actual, 'state.json'));
  if ((await lstat(directory)).isSymbolicLink() || path.dirname(actual) !== await realpath(process.env.RUNNER_TEMP || os.tmpdir()) || state.directory !== actual || !/^etcpro6-public-release-[A-Za-z0-9]+$/.test(path.basename(actual)) || state.keychain !== path.join(actual, 'signing.keychain-db') || !Array.isArray(state.originalSearchList) || state.originalSearchList.some(item => typeof item !== 'string' || !path.isAbsolute(item) || /[\r\n]/.test(item))) fail('Unsafe signing cleanup state');
  let failed = false;
  for (const name of ['signing.p12', 'AuthKey.p8', 'sparkle.key']) { try { await rm(path.join(actual, name), { force: true }); } catch { failed = true; } }
  if (state.originalSearchList.length) { try { securityInput(['list-keychains', '-d', 'user', '-s', ...state.originalSearchList], execute); state.originalSearchList = []; } catch { failed = true; } }
  if (state.keychainCreated) { try { securityInput(['delete-keychain', state.keychain], execute); state.keychainCreated = false; } catch { failed = true; } }
  await saveJSON(path.join(actual, 'state.json'), state);
  if (failed) fail('Signing cleanup incomplete; retry cleanup before publication');
}

async function fetchSafe(url, options = {}, fetcher = fetch) { let response; try { response = await fetcher(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(120_000) }); } catch { fail('Release HTTP request failed; private details suppressed'); } if (!response.ok) { await response.body?.cancel(); fail(`Release HTTP request returned ${response.status}`); } return response; }
export async function acquireSparkle(directory, fetcher = fetch) {
  let url = SPARKLE_URL, response;
  for (let redirects = 0; redirects <= 3; redirects++) {
    try { response = await fetcher(url, { redirect: 'manual', signal: AbortSignal.timeout(120_000) }); } catch { fail('Pinned Sparkle download failed'); }
    if (response.ok) break;
    if (![301, 302, 303, 307, 308].includes(response.status) || redirects === 3) fail('Pinned Sparkle download failed');
    let next; try { next = new URL(response.headers.get('Location')); } catch { fail('Pinned Sparkle redirect rejected'); }
    if (next.protocol !== 'https:' || !['release-assets.githubusercontent.com', 'objects.githubusercontent.com'].includes(next.hostname) || next.username || next.password || next.hash) fail('Pinned Sparkle redirect rejected');
    await response.body?.cancel(); url = next.href;
  }
  const chunks = []; let size = 0;
  for await (const chunk of response.body) { size += chunk.length; if (size > 256 * 1024 ** 2) fail('Pinned Sparkle tool download too large'); chunks.push(chunk); }
  const bytes = Buffer.concat(chunks);
  if (sha256(bytes) !== SPARKLE_SHA256) fail('Pinned Sparkle tool download checksum mismatch');
  const entries = zipEntries(bytes, { maximumBytes: 512 * 1024 ** 2 });
  const tool = entries.filter(entry => entry.name === 'bin/sign_update' && entry.kind === 'file');
  if (tool.length !== 1) fail('Pinned Sparkle sign_update absent');
  const target = path.join(directory, 'sign_update'); await writeFile(target, tool[0].data, { mode: 0o700, flag: 'wx' }); return target;
}
async function sanitizeApp(app, execute = run) {
  async function visit(target) { const info = await lstat(target); if (info.isSymbolicLink()) return; const attributes = execute('/usr/bin/xattr', ['-s', target]).stdout.trim().split('\n'); for (const name of ['com.apple.FinderInfo', 'com.apple.ResourceFork']) if (attributes.includes(name)) execute('/usr/bin/xattr', ['-s', '-d', name, target]); if (info.isDirectory()) for (const name of await readdir(target)) await visit(path.join(target, name)); }
  await visit(app);
}
async function plist(file, execute = run) { try { return JSON.parse(execute('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file]).stdout); } catch { fail('Release bundle metadata invalid'); } }
export async function validateApp(app, m, env, signed, execute = run) {
  const info = await plist(path.join(app, 'Contents/Info.plist'), execute);
  if (info.CFBundleIdentifier !== BUNDLE_ID || info.CFBundleShortVersionString !== m.version || String(info.CFBundleVersion) !== String(m.build) || info.LSMinimumSystemVersion !== '14.0' || info.SUFeedURL !== m.updates.feedURL || sha256(strictBase64(info.SUPublicEDKey, [32])) !== m.updates.publicKeySHA256 || info.SURequireSignedFeed !== true || info.SUVerifyUpdateBeforeExtraction !== true || info.SUSignedFeedFailureExpirationInterval !== 0 || info.SUAllowsAutomaticUpdates !== false || info.SUEnableAutomaticChecks !== false || info.SUEnableSystemProfiling !== false) fail('Release bundle configuration mismatch');
  for (const architecture of ['arm64', 'x86_64']) execute('/usr/bin/lipo', [path.join(app, 'Contents/MacOS/ETCPRO6'), '-verify_arch', architecture]);
  if (signed) {
    execute('/usr/bin/codesign', ['--verify', '--deep', '--strict', app]);
    const signature = execute('/usr/bin/codesign', ['-dv', '--verbose=4', app]).stderr;
    if (!/^Authority=Developer ID Application: /m.test(signature) || (env.APPLE_SIGNING_IDENTITY && !signature.includes(`Authority=${env.APPLE_SIGNING_IDENTITY}\n`)) || !signature.includes(`TeamIdentifier=${env.APPLE_TEAM_ID}\n`) || !/flags=.*runtime/.test(signature) || !/^Timestamp=/m.test(signature)) fail('Developer ID signature verification failed');
    const entitlements = execute('/usr/bin/codesign', ['-d', '--entitlements', ':-', app]).stdout;
    if (/<key>com\.apple\.security\.get-task-allow<\/key>\s*<true\s*\/>/.test(entitlements)) fail('Debugger entitlement is forbidden');
  }
  async function scan(directory) { for (const name of await readdir(directory)) { const target = path.join(directory, name), stat = await lstat(target); if (stat.isSymbolicLink()) continue; if (/\.(?:swift|xcodeproj|xcworkspace|p12|p8|pem|key|sh|command|xctest|dSYM|csv)$/i.test(name)) fail('Forbidden private or executable-script content in bundle'); if (stat.isDirectory()) await scan(target); else if (stat.isFile() && stat.size < 64 * 1024 ** 2 && /\/Users\/|\/dev\/cu\.(?:usbserial|wchusbserial)/.test((await readFile(target)).toString('latin1'))) fail('Developer-specific path in distributable bundle'); } }
  await scan(app);
}
export async function exportArchive(archive, work, m, env, execute = run) {
  let properties; try { properties = JSON.parse(execute('/usr/bin/plutil', ['-extract', 'ApplicationProperties', 'json', '-o', '-', path.join(archive, 'Info.plist')]).stdout); } catch { fail('Archive application metadata invalid'); }
  if (properties.ApplicationPath !== 'Applications/ETCPRO6.app' || properties.CFBundleIdentifier !== BUNDLE_ID || properties.CFBundleShortVersionString !== m.version || String(properties.CFBundleVersion) !== String(m.build) || !Array.isArray(properties.Architectures) || [...properties.Architectures].sort().join(',') !== 'arm64,x86_64') fail('Archive application provenance mismatch');
  const options = path.join(work, 'ExportOptions.plist');
  await writeFile(options, `<?xml version="1.0"?><plist version="1.0"><dict><key>method</key><string>developer-id</string><key>destination</key><string>export</string><key>signingStyle</key><string>manual</string><key>signingCertificate</key><string>${xml(env.APPLE_SIGNING_IDENTITY)}</string><key>teamID</key><string>${env.APPLE_TEAM_ID}</string></dict></plist>`, { mode: 0o600 });
  // Export processes an already built archive. No build/project/workspace argument is permitted.
  execute('/usr/bin/xcodebuild', ['-exportArchive', '-archivePath', archive, '-exportPath', path.join(work, 'export'), '-exportOptionsPlist', options]);
  const app = path.join(work, 'export/ETCPRO6.app');
  await sanitizeApp(app, execute);
  await signBuiltApp(app, work, env, execute, path.join(archive, 'Products/Applications/ETCPRO6.app'));
  await validateApp(app, m, env, true, execute); return app;
}
export async function signBuiltApp(app, work, env, execute = run, originalApp = app) {
  const objects = [];
  async function visit(target) {
    const stat = await lstat(target);
    if (stat.isSymbolicLink()) return;
    if (stat.isDirectory()) {
      for (const name of (await readdir(target)).sort()) await visit(path.join(target, name));
      if (target === app || /\.(?:app|xpc|framework)$/.test(target)) objects.push(target);
    } else if (stat.isFile()) {
      const bytes = await readFile(target), magic = bytes.subarray(0, 4).toString('hex');
      if (['feedface','cefaedfe','feedfacf','cffaedfe','cafebabe','bebafeca','cafebabf','bfbafeca'].includes(magic)) objects.push(target);
    } else fail('Unsupported signing entity');
  }
  await visit(app);
  const entitlements = path.join(work, 'signing-entitlements'); await mkdir(entitlements, { mode: 0o700 });
  // Capture original embedded entitlements before any child signature can change a parent seal.
  const records = [];
  for (const [index, target] of objects.entries()) {
    const original = path.join(originalApp, path.relative(app, target));
    const result = execute('/usr/bin/codesign', ['-d', '--entitlements', ':-', original], { allowFailure: true });
    const args = ['--force', '--options', 'runtime', '--timestamp', '--sign', env.APPLE_SIGNING_IDENTITY];
    if (result.stdout.trim()) {
      let data; try { data = JSON.parse(execute('/usr/bin/plutil', ['-convert','json','-o','-','-'], { input: result.stdout }).stdout); } catch { fail('Invalid original signing entitlements'); }
      if (!data || typeof data !== 'object' || Array.isArray(data) || data['com.apple.security.get-task-allow'] === true) fail('Debugger entitlement is forbidden');
      const file = path.join(entitlements, `${index}.plist`); await writeFile(file, result.stdout, { mode: 0o600, flag: 'wx' }); args.push('--entitlements', file);
    }
    records.push({ target, args });
  }
  for (const { target, args } of records) execute('/usr/bin/codesign', [...args, target]);
}
async function makeDMG(app, work, m, env, execute = run) {
  const payload = path.join(work, 'payload'); await mkdir(payload, { mode: 0o700 });
  execute('/usr/bin/ditto', [app, path.join(payload, 'ETCPRO6.app')]);
  await import('node:fs/promises').then(fs => fs.symlink('/Applications', path.join(payload, 'Applications')));
  const dmg = path.join(work, `ETCPRO6-${m.releaseId}.dmg`);
  execute('/usr/bin/hdiutil', ['create', '-quiet', '-volname', 'ETC PRO6', '-srcfolder', payload, '-fs', 'HFS+', '-format', 'UDZO', dmg]);
  execute('/usr/bin/hdiutil', ['verify', dmg]); execute('/usr/bin/codesign', ['--sign', env.APPLE_SIGNING_IDENTITY, '--timestamp', '--identifier', `${BUNDLE_ID}.diskimage`, dmg]); execute('/usr/bin/codesign', ['--verify', '--strict', dmg]); return dmg;
}
async function verifyImage(dmg, work, m, env, execute = run) {
  const mount = path.join(work, 'mount'); await mkdir(mount, { mode: 0o700 });
  execute('/usr/bin/hdiutil', ['attach', '-quiet', '-readonly', '-nobrowse', '-mountpoint', mount, dmg]);
  try {
    if ((await readdir(mount)).sort().join(',') !== 'Applications,ETCPRO6.app') fail('Unexpected disk image payload');
    const fs = await import('node:fs/promises');
    if (!(await lstat(path.join(mount, 'Applications'))).isSymbolicLink() || await fs.readlink(path.join(mount, 'Applications')) !== '/Applications') fail('Invalid disk image Applications link');
    await validateApp(path.join(mount, 'ETCPRO6.app'), m, env, true, execute);
    execute('/usr/sbin/spctl', ['--assess', '--type', 'execute', path.join(mount, 'ETCPRO6.app')]);
  } finally { execute('/usr/bin/hdiutil', ['detach', '-quiet', mount]); }
}
const xml = value => String(value).replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
export function notaryReceipt(value) { if (!uuidPattern.test(value?.id)) fail('Notary response did not include a submission ID'); return { submissionId: value.id, status: ['Accepted', 'Invalid', 'In Progress'].includes(value.status) ? value.status : 'Submitted' }; }
const recoveryNames = ['recovery', 'submission-recovery', 'notary-recovery', 'candidate-recovery'];
export async function encryptRecovery(dmg, directory, metadata, keyValue, name = 'recovery') {
  if (!recoveryNames.includes(name)) fail('Invalid recovery snapshot name');
  const key = strictBase64(keyValue, [32]), iv = randomBytes(12), aad = Buffer.from(JSON.stringify(canonical(metadata)));
  const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(aad);
  const encrypted = path.join(directory, `${name}.bin`); await pipeline(createReadStream(dmg), cipher, createWriteStream(encrypted, { mode: 0o600, flags: 'wx' }));
  const envelope = { schemaVersion: 1, algorithm: 'AES-256-GCM', iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), encryptedSHA256: sha256(await readFile(encrypted)), metadata };
  await saveJSON(path.join(directory, `${name}.json`), envelope); return envelope;
}
export async function decryptRecovery(directory, destination, keyValue, name = 'recovery') {
  if (!recoveryNames.includes(name)) fail('Invalid recovery snapshot name');
  const e = await json(path.join(directory, `${name}.json`)); record(e, ['schemaVersion', 'algorithm', 'iv', 'tag', 'encryptedSHA256', 'metadata']);
  if (e.schemaVersion !== 1 || e.algorithm !== 'AES-256-GCM' || !hashPattern.test(e.encryptedSHA256)) fail('Invalid encrypted recovery envelope');
  const encrypted = path.join(directory, `${name}.bin`); await regular(encrypted, 1024 ** 3 + 2 * 1024 ** 2);
  if (sha256(await readFile(encrypted)) !== e.encryptedSHA256) fail('Recovery ciphertext hash mismatch');
  const decipher = createDecipheriv('aes-256-gcm', strictBase64(keyValue, [32]), strictBase64(e.iv, [12])); decipher.setAuthTag(strictBase64(e.tag, [16])); decipher.setAAD(Buffer.from(JSON.stringify(canonical(e.metadata))));
  try { await pipeline(createReadStream(encrypted), decipher, createWriteStream(destination, { mode: 0o600, flags: 'wx' })); } catch { await rm(destination, { force: true }); fail('Recovery authentication failed'); }
  if (sha256(await readFile(destination)) !== (e.metadata.payloadSHA256 || e.metadata.submittedSHA256)) { await rm(destination, { force: true }); fail('Recovery submitted hash mismatch'); } return e.metadata;
}
export async function notarize(dmg, m, work, receipts, env, execute = run, retained = null) {
  const auth = ['--key', path.join(work, 'AuthKey.p8'), '--key-id', env.APPLE_NOTARY_KEY_ID, '--issuer', env.APPLE_NOTARY_ISSUER_ID];
  let receipt = retained;
  const invoke = (args, allowFailure = false) => { const result = execute('/usr/bin/xcrun', ['notarytool', ...args, ...auth, '--output-format', 'json'], { allowFailure }); let data; try { data = JSON.parse(result.stdout); } catch { data = null; } return { ...result, data }; };
  if (!receipt) {
    try { await lstat(path.join(receipts, 'notary.json')); fail('Submission receipt exists; recover the same ID'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
    const draft = { stage: 'submission-unknown', submittedSHA256: sha256(await readFile(dmg)), artifactName: path.basename(dmg), unsignedManifest: m, signingTeamID: env.APPLE_TEAM_ID, manifestCreatedAt: new Date().toISOString() };
    // Preserve exact bytes before the network call: Apple may accept a submission even when its response is lost.
    await encryptRecovery(dmg, receipts, draft, env.RECOVERY_ENCRYPTION_KEY, 'submission-recovery');
    const result = invoke(['submit', dmg, '--no-wait'], true);
    receipt = { ...notaryReceipt(result.data), submittedSHA256: draft.submittedSHA256, artifactName: draft.artifactName, manifestCreatedAt: draft.manifestCreatedAt };
    await saveJSON(path.join(receipts, 'notary.json'), receipt);
    await encryptRecovery(dmg, receipts, { stage: 'notary', ...receipt, unsignedManifest: m, signingTeamID: env.APPLE_TEAM_ID }, env.RECOVERY_ENCRYPTION_KEY, 'notary-recovery');
    if (result.status !== 0) fail('Notary submission interrupted after ID; resume encrypted recovery');
  }
  if (!uuidPattern.test(receipt.submissionId) || sha256(await readFile(dmg)) !== receipt.submittedSHA256) fail('Recovery submission identity/hash mismatch');
  invoke(['wait', receipt.submissionId, '--timeout', '20m'], true);
  const info = invoke(['info', receipt.submissionId], true), updated = notaryReceipt(info.data);
  if (updated.submissionId !== receipt.submissionId) fail('Notary ID mismatch');
  receipt = { ...receipt, ...updated }; await saveJSON(path.join(receipts, 'notary.json'), receipt);
  if (info.status !== 0 || receipt.status !== 'Accepted') fail('Notarization not accepted; retain same submission recovery');
  return receipt;
}
export async function signFeed(dmg, m, notary, tool, work, env, execute = run) {
  const key = path.join(work, 'sparkle.key'); validateSparkleKey(await readFile(key, 'utf8'), env.ETCPRO6_UPDATE_PUBLIC_KEY);
  const signature = execute(tool, ['--ed-key-file', key, '-p', dmg]).stdout.trim(); if (!signaturePattern.test(signature)) fail('Sparkle archive signature invalid'); execute(tool, ['--ed-key-file', key, '--verify', dmg, signature]);
  const bytes = await readFile(dmg), feedPath = path.join(work, 'appcast.xml'), origin = baseURL(env.UPDATE_PUBLIC_BASE_URL);
  await writeFile(feedPath, `<?xml version="1.0" encoding="utf-8"?>\n<rss version="2.0" xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle"><channel><title>ETCPRO6</title><item><title>${xml(m.version)}</title><sparkle:version>${m.build}</sparkle:version><sparkle:shortVersionString>${xml(m.version)}</sparkle:shortVersionString><sparkle:minimumSystemVersion>14.0</sparkle:minimumSystemVersion><enclosure url="${xml(`${origin}/releases/${m.releaseId}/${path.basename(dmg)}`)}" sparkle:edSignature="${signature}" length="${bytes.length}" type="application/octet-stream"/></item></channel></rss>\n`, { mode: 0o600 });
  execute(tool, ['--ed-key-file', key, feedPath]); execute(tool, ['--ed-key-file', key, '--verify', feedPath]);
  const feed = await readFile(feedPath);
  if (!Number.isFinite(Date.parse(notary.manifestCreatedAt))) fail('Fixed release creation time missing');
  return { schemaVersion: 1, releaseId: m.releaseId, version: m.version, build: m.build, minimumSystemVersion: '14.0', artifact: { key: `releases/${m.releaseId}/${path.basename(dmg)}`, size: bytes.length, sha256: sha256(bytes), sparkleEdSignature: signature }, appcast: { key: `releases/${m.releaseId}/appcast.xml`, size: feed.length, sha256: sha256(feed) }, source: { commit: m.commit, tag: `v${m.version}`, workflowRunId: String(m.workflowRunId) }, notarization: { submissionId: notary.submissionId, status: 'Accepted' }, createdAt: notary.manifestCreatedAt };
}
function accessHeaders(env, staging = false, channel = false) { const prefix = channel ? 'CF_CHANNEL' : staging ? 'STAGING_CF_CANDIDATE' : 'CF_CANDIDATE'; return { 'CF-Access-Client-Id': required(env, `${prefix}_ACCESS_CLIENT_ID`), 'CF-Access-Client-Secret': required(env, `${prefix}_ACCESS_CLIENT_SECRET`), 'Content-Type': 'application/json' }; }
async function api(base, route, headers, body, fetcher) { const response = await fetchSafe(`${base}${route}`, { method: body ? 'POST' : 'GET', headers, ...(body ? { body: JSON.stringify(body) } : {}) }, fetcher); try { return await response.json(); } catch { fail('Release API returned invalid JSON'); } }
export async function probe(base, m, stable = false, fetcher = fetch) {
  for (const file of [m.artifact, m.appcast]) {
    const isStable = stable && file === m.appcast, response = await fetchSafe(`${base}/${isStable ? 'stable/appcast.xml' : file.key}`, { headers: { 'Cache-Control': 'no-cache' } }, fetcher);
    if (!response.headers.get('ETag') || !response.headers.get('Cache-Control')?.includes(isStable ? 'max-age=60' : 'immutable')) fail('Public cache probe failed');
    let size = 0; const hash = createHash('sha256'); for await (const chunk of response.body) { size += chunk.length; if (size > file.size) fail('Public artifact size mismatch'); hash.update(chunk); } if (size !== file.size || hash.digest('hex') !== file.sha256) fail('Public artifact digest mismatch');
  }
}
export async function uploadOne(env, staging, m, work, fetcher = fetch) {
  const admin = baseURL(env[staging ? 'STAGING_UPDATE_ADMIN_BASE_URL' : 'UPDATE_ADMIN_BASE_URL']), headers = accessHeaders(env, staging), session = await api(admin, '/api/releases/init', headers, m, fetcher);
  if (!session.finalized) {
    if (!uuidPattern.test(session.sessionId) || session.releaseId !== m.releaseId || !Array.isArray(session.uploads) || session.uploads.length !== 2) fail('Invalid upload session');
    for (const file of [m.artifact, m.appcast]) {
      const upload = session.uploads.find(item => item.key === file.key); let url; try { url = new URL(upload?.url); } catch { fail('Invalid presigned upload'); }
      if (!/^https:\/\/[a-f0-9]{32}\.r2\.cloudflarestorage\.com$/.test(url.origin) || url.username || url.password || !url.pathname.endsWith(`/uploads/${session.sessionId}/${path.basename(file.key)}`) || Object.keys(upload.headers ?? {}).sort().join(',') !== 'Content-Length,x-amz-checksum-sha256' || upload.headers['Content-Length'] !== String(file.size) || upload.headers['x-amz-checksum-sha256'] !== Buffer.from(file.sha256, 'hex').toString('base64')) fail('Presigned authorization differs from candidate');
      const local = path.join(work, path.basename(file.key)), info = await regular(local); if (info.size !== file.size || sha256(await readFile(local)) !== file.sha256) fail('Signed artifact changed');
      const response = await fetchSafe(url, { method: 'PUT', headers: upload.headers, body: createReadStream(local), duplex: 'half' }, fetcher); await response.body?.cancel();
    }
    const result = await api(admin, `/api/releases/${m.releaseId}/finalize`, headers, { sessionId: session.sessionId }, fetcher); if (!result.finalized || result.sha256 !== m.artifact.sha256) fail('Candidate finalization mismatch');
  }
}
export async function publishCandidate(m, work, receipts, env, fetcher = fetch) {
  await uploadOne(env, false, m, work, fetcher); await uploadOne(env, true, m, work, fetcher);
  await probe(baseURL(env.UPDATE_PUBLIC_BASE_URL), m, false, fetcher); await probe(baseURL(env.STAGING_UPDATE_PUBLIC_BASE_URL), m, false, fetcher);
  const list = await api(baseURL(env.UPDATE_ADMIN_BASE_URL), '/api/releases', accessHeaders(env), null, fetcher);
  if (!list.releases?.some(item => equalJSON(item, m)) || (list.stable && m.build <= list.stable.build)) fail('Finalized candidate/stable state mismatch');
  const receipt = { schemaVersion: 1, manifest: m, expectedETag: list.stable?.etag ?? null, expectedBuild: list.stable?.build ?? null, stagingVerified: true };
  await saveJSON(path.join(receipts, 'candidate.json'), receipt); return receipt;
}
export function validateReleaseManifest(m) {
  record(m, ['schemaVersion', 'releaseId', 'version', 'build', 'minimumSystemVersion', 'artifact', 'appcast', 'source', 'notarization', 'createdAt']);
  record(m.artifact, ['key', 'size', 'sha256', 'sparkleEdSignature']); record(m.appcast, ['key', 'size', 'sha256']); record(m.source, ['commit', 'tag', 'workflowRunId']); record(m.notarization, ['submissionId', 'status']);
  if (m.schemaVersion !== 1 || !versionPattern.test(m.version) || !Number.isSafeInteger(m.build) || m.build < 1 || m.releaseId !== `${m.version}+${m.build}` || m.minimumSystemVersion !== '14.0' || !commitPattern.test(m.source.commit) || m.source.tag !== `v${m.version}` || !/^\d+$/.test(m.source.workflowRunId) || m.notarization.status !== 'Accepted' || !uuidPattern.test(m.notarization.submissionId) || !Number.isFinite(Date.parse(m.createdAt))) fail('Invalid release manifest');
  for (const [file, name, maximum] of [[m.artifact, `ETCPRO6-${m.releaseId}.dmg`, 1024 ** 3], [m.appcast, 'appcast.xml', 1024 ** 2]]) if (file.key !== `releases/${m.releaseId}/${name}` || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > maximum || !hashPattern.test(file.sha256)) fail('Invalid release file');
  if (!signaturePattern.test(m.artifact.sparkleEdSignature)) fail('Invalid release signature'); return m;
}
export async function promote(receiptFile, receipts, env, fetcher = fetch) {
  for (const name of Object.keys(env)) if (/^(?:APPLE_|SPARKLE_|CF_CANDIDATE_|STAGING_CF_CANDIDATE_|RECOVERY_ENCRYPTION_KEY)/.test(name) && env[name]) fail('Candidate/signing credentials must not enter stable executor');
  await regular(receiptFile, 64 * 1024); const receipt = await json(receiptFile); record(receipt, ['schemaVersion', 'manifest', 'expectedETag', 'expectedBuild', 'stagingVerified']);
  const m = validateReleaseManifest(receipt.manifest);
  if (receipt.schemaVersion !== 1 || receipt.stagingVerified !== true || !(receipt.expectedETag === null || (typeof receipt.expectedETag === 'string' && receipt.expectedETag.length < 200)) || !(receipt.expectedBuild === null || Number.isSafeInteger(receipt.expectedBuild))) fail('Invalid approved candidate receipt');
  const admin = baseURL(required(env, 'UPDATE_ADMIN_BASE_URL')), publicBase = baseURL(required(env, 'UPDATE_PUBLIC_BASE_URL')), headers = accessHeaders(env, false, true), list = await api(admin, '/api/releases', headers, null, fetcher);
  if (!list.releases?.some(item => equalJSON(item, m))) fail('Approved manifest differs from server'); await probe(publicBase, m, false, fetcher);
  const result = await api(admin, '/api/channels/stable/promote', headers, { releaseId: m.releaseId, sha256: m.artifact.sha256, expectedETag: receipt.expectedETag, expectedBuild: receipt.expectedBuild }, fetcher);
  if (result.releaseId !== m.releaseId || result.build !== m.build || result.sha256 !== m.artifact.sha256 || typeof result.etag !== 'string' || typeof result.auditKey !== 'string') fail('Publication response ambiguous; inspect channel before retry');
  await saveJSON(path.join(receipts, 'stable.json'), { schemaVersion: 1, releaseId: m.releaseId, build: m.build, sha256: m.artifact.sha256, appcastSHA256: m.appcast.sha256, etag: result.etag, historyKey: result.historyKey ?? null, auditKey: result.auditKey });
  await probe(publicBase, m, true, fetcher); return result;
}
async function privateWork(env) { const base = await realpath(env.RUNNER_TEMP || os.tmpdir()); if (!path.isAbsolute(base)) fail('Invalid runner temporary root'); const work = await mkdtemp(path.join(base, 'etcpro6-public-release-')); await chmod(work, 0o700); return work; }
async function finishSigned(dmg, m, work, receipts, env, notary, tool) {
  run('/usr/bin/xcrun', ['stapler', 'staple', dmg]); run('/usr/bin/xcrun', ['stapler', 'validate', dmg]); run('/usr/bin/codesign', ['--verify', '--strict', dmg]); run('/usr/sbin/spctl', ['--assess', '--type', 'open', '--context', 'context:primary-signature', dmg]);
  await verifyImage(dmg, work, m, env);
  const manifest = await signFeed(dmg, m, notary, tool, work, env); await saveJSON(path.join(receipts, 'manifest.json'), manifest);
  await snapshotCandidate(dmg, m, manifest, notary, work, receipts, env);
  await cleanupSigning(work); // Signing material is removed before upload HTTP begins.
  await publishCandidate(manifest, work, receipts, env); return manifest;
}
export async function snapshotCandidate(dmg, unsignedManifest, manifest, notary, work, receipts, env) {
  validateReleaseManifest(manifest);
  const bytes = await readFile(dmg), appcast = await readFile(path.join(work, 'appcast.xml'));
  if (sha256(bytes) !== manifest.artifact.sha256 || bytes.length !== manifest.artifact.size || sha256(appcast) !== manifest.appcast.sha256 || appcast.length !== manifest.appcast.size) fail('Candidate snapshot differs from manifest');
  const payload = path.join(work, 'candidate-recovery.payload'); await writeFile(payload, Buffer.concat([bytes, appcast]), { mode: 0o600, flag: 'wx' });
  const metadata = { stage: 'candidate', payloadSHA256: sha256(await readFile(payload)), artifactName: path.basename(dmg), unsignedManifest, signingTeamID: env.APPLE_TEAM_ID, manifest, notaryReceipt: notary };
  await encryptRecovery(payload, receipts, metadata, env.RECOVERY_ENCRYPTION_KEY, 'candidate-recovery'); await rm(payload);
}
export async function restoreCandidate(recovery, work, env) {
  const payload = path.join(work, 'candidate-recovery.payload'), metadata = await decryptRecovery(recovery, payload, env.RECOVERY_ENCRYPTION_KEY, 'candidate-recovery'), m = validateReleaseManifest(metadata.manifest);
  validateRecoveredManifest(metadata.unsignedManifest, env);
  if (metadata.stage !== 'candidate' || metadata.signingTeamID !== env.APPLE_TEAM_ID || metadata.artifactName !== path.basename(m.artifact.key) || metadata.unsignedManifest?.commit !== m.source.commit || metadata.unsignedManifest?.version !== m.version || metadata.unsignedManifest?.build !== m.build) fail('Candidate recovery provenance mismatch');
  const bytes = await readFile(payload); if (bytes.length !== m.artifact.size + m.appcast.size) fail('Candidate recovery length mismatch');
  const dmg = bytes.subarray(0, m.artifact.size), feed = bytes.subarray(m.artifact.size);
  if (sha256(dmg) !== m.artifact.sha256 || sha256(feed) !== m.appcast.sha256) fail('Candidate recovery artifact hash mismatch');
  await writeFile(path.join(work, metadata.artifactName), dmg, { mode: 0o600, flag: 'wx' }); await writeFile(path.join(work, 'appcast.xml'), feed, { mode: 0o600, flag: 'wx' }); await rm(payload); return metadata;
}
function validateRecoveredManifest(m, env) { return validateUnsignedManifest(m, { schemaVersion: 1, repository: SOURCE_REPOSITORY, commit: m?.commit, releaseTag: `v${m?.version}`, workflow: { path: SOURCE_WORKFLOW, runId: m?.workflowRunId }, artifact: { id: 1, digest: '0'.repeat(64) } }, env); }
async function removeRecovery(receipts) { for (const name of recoveryNames) for (const suffix of ['json', 'bin']) await rm(path.join(receipts, `${name}.${suffix}`), { force: true }); }
export async function candidate(input, verified, receipts, env = process.env) {
  const inspected = await inspectInput(input, verified, env); assertSecrets(env);
  await mkdir(receipts, { recursive: true, mode: 0o700 });
  const work = await privateWork(env); let succeeded = false;
  if (env.GITHUB_ENV) await writeFile(env.GITHUB_ENV, `ETCPRO6_RELEASE_WORK=${work}\n`, { flag: 'a', mode: 0o600 });
  try {
    const archive = await extractArchive(inspected.archive, path.join(work, 'input'));
    await validateApp(path.join(archive, 'Products/Applications/ETCPRO6.app'), inspected.manifest, env, false);
    const tool = await acquireSparkle(work); await prepareSigning(work, env);
    const app = await exportArchive(archive, work, inspected.manifest, env), dmg = await makeDMG(app, work, inspected.manifest, env);
    const notary = await notarize(dmg, inspected.manifest, work, receipts, env);
    const result = await finishSigned(dmg, inspected.manifest, work, receipts, env, notary, tool);
    await saveJSON(path.join(receipts, 'source.json'), { schemaVersion: 1, repository: SOURCE_REPOSITORY, commit: inspected.manifest.commit, workflowRunId: inspected.manifest.workflowRunId, unsignedArchiveSHA256: inspected.manifest.archive.sha256, unsignedManifestSHA256: inspected.unsignedManifestSHA256 });
    succeeded = true; return result;
  } finally {
    let cleaned = false;
    try { try { await lstat(path.join(work, 'state.json')); await cleanupSigning(work); } catch (error) { if (error.code !== 'ENOENT') throw error; } cleaned = true; } finally { if (cleaned) await rm(work, { recursive: true, force: true }); }
    if (succeeded) await removeRecovery(receipts);
  }
}
export async function resume(recovery, receipts, env = process.env) {
  assertSecrets(env, true); const work = await privateWork(env); let succeeded = false;
  if (env.GITHUB_ENV) await writeFile(env.GITHUB_ENV, `ETCPRO6_RELEASE_WORK=${work}\n`, { flag: 'a', mode: 0o600 });
  try {
    let recoveryName = null;
    for (const name of ['candidate-recovery', 'notary-recovery', 'submission-recovery']) { try { await regular(path.join(recovery, `${name}.json`), 128 * 1024); recoveryName = name; break; } catch (error) { if (error.code !== 'ENOENT') throw error; } }
    if (!recoveryName) fail('No authenticated recovery snapshot found');
    if (recoveryName === 'candidate-recovery') {
      const metadata = await restoreCandidate(recovery, work, env); await mkdir(receipts, { recursive: true, mode: 0o700 });
      await saveJSON(path.join(receipts, 'manifest.json'), metadata.manifest); await saveJSON(path.join(receipts, 'notary.json'), metadata.notaryReceipt);
      await publishCandidate(metadata.manifest, work, receipts, env); succeeded = true; return metadata.manifest;
    }
    const envelope = await json(path.join(recovery, `${recoveryName}.json`)), artifactName = envelope.metadata?.artifactName;
    if (typeof artifactName !== 'string' || !/^ETCPRO6-\d+\.\d+\.\d+\+[1-9]\d*\.dmg$/.test(artifactName)) fail('Invalid recovery artifact name');
    const dmg = path.join(work, artifactName), retained = await decryptRecovery(recovery, dmg, env.RECOVERY_ENCRYPTION_KEY, recoveryName), m = retained.unsignedManifest;
    validateRecoveredManifest(m, env);
    if (recoveryName === 'submission-recovery') {
      if (!uuidPattern.test(env.NOTARY_SUBMISSION_ID ?? '') || env.CONFIRM_SUBMISSION_SHA256 !== retained.submittedSHA256) fail('Unknown submission requires operator-confirmed ID and submitted SHA-256; never resubmit automatically');
      retained.submissionId = env.NOTARY_SUBMISSION_ID; retained.status = 'Submitted';
      await saveJSON(path.join(receipts, 'submission-binding.json'), { submissionId: retained.submissionId, submittedSHA256: retained.submittedSHA256, reason: 'operator-confirmed Apple submission history' });
    }
    if (!uuidPattern.test(retained.submissionId) || retained.signingTeamID !== env.APPLE_TEAM_ID || artifactName !== `ETCPRO6-${m?.releaseId}.dmg` || m?.updates?.feedURL !== `${baseURL(env.UPDATE_PUBLIC_BASE_URL)}/stable/appcast.xml` || m.updates.publicKeySHA256 !== sha256(strictBase64(env.ETCPRO6_UPDATE_PUBLIC_KEY, [32]))) fail('Recovery provenance/configuration mismatch');
    await mkdir(receipts, { recursive: true, mode: 0o700 });
    await saveJSON(path.join(work, 'state.json'), { directory: work, keychain: path.join(work, 'signing.keychain-db'), originalSearchList: [], keychainCreated: false });
    await writeFile(path.join(work, 'AuthKey.p8'), env.APPLE_NOTARY_KEY, { mode: 0o600 }); await writeFile(path.join(work, 'sparkle.key'), env.SPARKLE_PRIVATE_KEY, { mode: 0o600 });
    const tool = await acquireSparkle(work), notary = await notarize(dmg, m, work, receipts, env, run, retained);
    const result = await finishSigned(dmg, m, work, receipts, env, notary, tool); succeeded = true; return result;
  } finally { try { await cleanupSigning(work); } catch (error) { if (error.code !== 'ENOENT') throw error; } await rm(work, { recursive: true, force: true }); if (succeeded) await removeRecovery(receipts); }
}
export async function main(args, env = process.env) {
  const [command, ...rest] = args;
  if (command === 'candidate' && rest.length === 3) return candidate(...rest, env);
  if (command === 'promote' && rest.length === 2) return promote(...rest, env);
  if (command === 'resume' && rest.length === 2) return resume(...rest, env);
  if (command === 'cleanup' && rest.length === 1) return cleanupSigning(rest[0]);
  fail('Usage: release.mjs candidate INPUT VERIFIED RECEIPTS | promote CANDIDATE RECEIPTS | resume RECOVERY RECEIPTS');
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(process.argv.slice(2)).catch(() => { console.error('Release operation failed; inspect sanitized receipts and private runner diagnostics. Do not blindly repeat publication or notarization.'); process.exitCode = 1; });
