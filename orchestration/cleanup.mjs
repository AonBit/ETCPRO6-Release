import { lstat } from 'node:fs/promises';
import { cleanupSigning } from '../tools/release.mjs';
try {
  const work = process.env.ETCPRO6_RELEASE_WORK;
  if (!work) throw new Error();
  try { await lstat(work); await cleanupSigning(work); } catch (error) { if (error.code !== 'ENOENT') throw error; }
} catch { console.error('Signing cleanup requires attention'); process.exitCode = 1; }
