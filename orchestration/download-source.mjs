import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { sha256, zipEntries } from '../tools/archive.mjs';

const fail = () => { throw new Error('Private artifact download rejected'); };
export async function downloadSource(verified, destination, token, fetcher = fetch) {
  if (verified.repository !== 'AonBit/ETCPRO6-MAC' || !Number.isSafeInteger(verified.artifact?.id) || verified.artifact.id < 1 || !/^[a-f0-9]{64}$/.test(verified.artifact.digest) || !Number.isSafeInteger(verified.artifact.size) || verified.artifact.size < 1 || verified.artifact.size > 1024 ** 3 || typeof token !== 'string' || token.length < 20) fail();
  const response = await fetcher(`https://api.github.com/repos/AonBit/ETCPRO6-MAC/actions/artifacts/${verified.artifact.id}/zip`, {
    redirect: 'manual', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, signal: AbortSignal.timeout(30_000),
  });
  if (response.status !== 302) fail();
  let url; try { url = new URL(response.headers.get('location')); } catch { fail(); }
  // The signed blob URL gets no GitHub authorization header. Never follow another redirect.
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !(url.hostname.endsWith('.blob.core.windows.net') || url.hostname.endsWith('.actions.githubusercontent.com'))) fail();
  const blob = await fetcher(url.href, { redirect: 'error', signal: AbortSignal.timeout(120_000) });
  if (!blob.ok || !blob.body) fail();
  const chunks = []; let size = 0;
  for await (const chunk of blob.body) { size += chunk.length; if (size > verified.artifact.size) fail(); chunks.push(chunk); }
  const bytes = Buffer.concat(chunks);
  if (size !== verified.artifact.size || sha256(bytes) !== verified.artifact.digest) fail();
  const entries = zipEntries(bytes, { maximumBytes: 2 * 1024 ** 3, maximumEntries: 2 });
  if (entries.length !== 2 || entries.some(entry => entry.kind !== 'file') || entries.map(entry => entry.name).sort().join(',') !== 'ETCPRO6-unsigned.xcarchive.zip,unsigned-manifest.json') fail();
  await mkdir(destination, { mode: 0o700 });
  for (const entry of entries) await writeFile(path.join(destination, entry.name), entry.data, { flag: 'wx', mode: 0o600 });
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [verified, destination] = process.argv.slice(2);
  Promise.resolve().then(async () => { if (!verified || !destination) fail(); await downloadSource(JSON.parse(await readFile(verified, 'utf8')), destination, process.env.GH_SOURCE_TOKEN); }).catch(() => { console.error('Private artifact download rejected; details suppressed'); process.exitCode = 1; });
}
