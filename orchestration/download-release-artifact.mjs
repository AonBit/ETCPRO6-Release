import { sha256 } from '../tools/archive.mjs';

const repository = 'AonBit/ETCPRO6-Release';
const fail = () => { throw new Error('Release artifact download rejected'); };

export async function downloadReleaseArtifact(artifact, token, fetcher = fetch) {
  if (artifact?.repository !== repository || !Number.isSafeInteger(artifact.id) || artifact.id < 1 || !Number.isSafeInteger(artifact.size) || artifact.size < 1 || artifact.size > 1024 ** 3 + 4 * 1024 ** 2 || !/^[a-f0-9]{64}$/.test(artifact.digest ?? '') || typeof token !== 'string' || token.length < 20 || token.length > 4096 || /[\r\n\0]/.test(token)) fail();
  let response;
  try {
    response = await fetcher(`https://api.github.com/repos/${repository}/actions/artifacts/${artifact.id}/zip`, {
      redirect: 'manual', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, signal: AbortSignal.timeout(30_000),
    });
  } catch { fail(); }
  if (response.status !== 302) fail();
  let location; try { location = new URL(response.headers.get('Location')); } catch { fail(); }
  if (location.protocol !== 'https:' || location.username || location.password || location.port || !(location.hostname.endsWith('.blob.core.windows.net') || location.hostname.endsWith('.actions.githubusercontent.com'))) fail();
  let body;
  try { body = await fetcher(location.href, { redirect: 'error', signal: AbortSignal.timeout(120_000) }); } catch { fail(); }
  if (!body.ok || !body.body) fail();
  const chunks = []; let size = 0;
  for await (const chunk of body.body) { size += chunk.length; if (size > artifact.size) fail(); chunks.push(chunk); }
  const bytes = Buffer.concat(chunks);
  if (bytes.length !== artifact.size || sha256(bytes) !== artifact.digest) fail();
  return bytes;
}
