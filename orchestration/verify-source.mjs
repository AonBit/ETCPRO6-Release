#!/usr/bin/env node
import { chmod, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const expectedRepository = "AonBit/ETCPRO6-MAC";
const expectedWorkflow = ".github/workflows/release-build.yml";
const commitPattern = /^[a-f0-9]{40}$/;
const integerPattern = /^[1-9][0-9]*$/;
const tagPattern = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const digestPattern = /^sha256:([a-f0-9]{64})$/;

function fail(message) {
  throw new Error(message);
}

function input(env, name, pattern) {
  const value = env[name];
  if (typeof value !== "string" || !pattern.test(value)) fail(`Invalid ${name}`);
  return value;
}

async function githubJSON(route, token, fetchImpl) {
  const response = await fetchImpl(`https://api.github.com${route}`, {
    redirect: "error",
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) fail(`GitHub API request failed (${response.status})`);
  try {
    return await response.json();
  } catch {
    fail("GitHub API returned invalid JSON");
  }
}

export async function verifySourceRequest(env, fetchImpl = fetch) {
  if (env.SOURCE_REPOSITORY !== expectedRepository) fail("Unexpected source repository");
  const commit = input(env, "SOURCE_COMMIT", commitPattern);
  const runId = input(env, "SOURCE_RUN_ID", integerPattern);
  const artifactId = input(env, "SOURCE_ARTIFACT_ID", integerPattern);
  if (![runId, artifactId].every(value => Number.isSafeInteger(Number(value)))) fail("Invalid source numeric identifier");
  const releaseTag = input(env, "RELEASE_TAG", tagPattern);
  const token = env.GH_SOURCE_TOKEN;
  if (typeof token !== "string" || token.length < 20 || token.length > 4096 || /[\r\n\0]/.test(token)) fail("Invalid source token");

  const base = `/repos/${expectedRepository}`;
  const [run, artifact, taggedCommit] = await Promise.all([
    githubJSON(`${base}/actions/runs/${runId}`, token, fetchImpl),
    githubJSON(`${base}/actions/artifacts/${artifactId}`, token, fetchImpl),
    githubJSON(`${base}/commits/${encodeURIComponent(releaseTag)}`, token, fetchImpl),
  ]);

  if (String(run.id) !== runId
    || run.repository?.full_name !== expectedRepository
    || run.head_sha !== commit
    || run.head_branch !== "main"
    || run.event !== "workflow_dispatch"
    || run.status !== "completed"
    || run.conclusion !== "success"
    || run.path !== expectedWorkflow
    || !Number.isSafeInteger(run.run_attempt)
    || run.run_attempt < 1) fail("Source workflow run does not match the approved request");

  if (taggedCommit?.sha !== commit) fail("Release tag does not resolve to the approved commit");

  const digestMatch = typeof artifact.digest === "string" ? artifact.digest.match(digestPattern) : null;
  if (String(artifact.id) !== artifactId
    || artifact.name !== `ETCPRO6-unsigned-${commit}`
    || artifact.expired !== false
    || !Number.isSafeInteger(artifact.size_in_bytes)
    || artifact.size_in_bytes <= 0
    || artifact.workflow_run?.id !== Number(runId)
    || artifact.workflow_run?.head_sha !== commit
    || !digestMatch) fail("Source artifact does not match the approved workflow run");

  return {
    schemaVersion: 1,
    repository: expectedRepository,
    commit,
    releaseTag,
    workflow: {
      path: expectedWorkflow,
      runId: Number(runId),
      runAttempt: run.run_attempt,
    },
    artifact: {
      id: Number(artifactId),
      name: artifact.name,
      size: artifact.size_in_bytes,
      digest: digestMatch[1],
    },
  };
}

export async function writeVerifiedRequest(file, report) {
  const parent = path.dirname(path.resolve(file));
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await writeFile(file, `${JSON.stringify(report, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  await chmod(file, 0o600);
}

async function main() {
  if (process.argv.length !== 3) fail("Usage: verify-source.mjs OUTPUT_JSON");
  const report = await verifySourceRequest(process.env);
  await writeVerifiedRequest(process.argv[2], report);
  process.stdout.write(`Verified source request: ${report.commit} / artifact ${report.artifact.id}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === scriptPath) {
  main().catch(error => {
    const safe = error instanceof Error && /^(Invalid |Unexpected |GitHub API |Source |Release tag |Usage:)/.test(error.message)
      ? error.message
      : "Source verification failed";
    console.error(safe);
    process.exitCode = 1;
  });
}
