try {
  const token = process.env.GH_SOURCE_TOKEN;
  if (!token) throw new Error();
  const response = await fetch('https://api.github.com/installation/token', { method: 'DELETE', redirect: 'error', headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(30_000) });
  if (response.status !== 204) throw new Error();
} catch { console.error('Source token revocation failed; signing is blocked'); process.exitCode = 1; }
