import assert from "node:assert/strict";
import test from "node:test";
import { verifySourceRequest } from "./verify-source.mjs";

const commit = "a".repeat(40);
const token = "fixture-token-that-must-never-appear";
const env = {
  SOURCE_REPOSITORY: "AonBit/ETCPRO6-MAC",
  SOURCE_COMMIT: commit,
  SOURCE_RUN_ID: "123",
  SOURCE_ARTIFACT_ID: "456",
  RELEASE_TAG: "v0.2.0",
  GH_SOURCE_TOKEN: token,
};
const valid = {
  run: {
    id: 123,
    repository: { full_name: "AonBit/ETCPRO6-MAC" },
    head_sha: commit,
    head_branch: "main",
    event: "workflow_dispatch",
    status: "completed",
    conclusion: "success",
    path: ".github/workflows/release-build.yml",
    run_attempt: 1,
  },
  artifact: {
    id: 456,
    name: `ETCPRO6-unsigned-${commit}`,
    expired: false,
    size_in_bytes: 2048,
    digest: `sha256:${"b".repeat(64)}`,
    workflow_run: { id: 123, head_sha: commit },
  },
  tag: { sha: commit },
};

function fetcher(values = valid, status = 200) {
  return async url => {
    let body;
    if (url.endsWith("/actions/runs/123")) body = values.run;
    else if (url.endsWith("/actions/artifacts/456")) body = values.artifact;
    else if (url.endsWith("/commits/v0.2.0")) body = values.tag;
    else throw new Error(`Unexpected URL ${url}`);
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  };
}

test("binds an exact successful private run, tag, commit and artifact digest", async () => {
  const report = await verifySourceRequest(env, fetcher());
  assert.deepEqual(report, {
    schemaVersion: 1,
    repository: "AonBit/ETCPRO6-MAC",
    commit,
    releaseTag: "v0.2.0",
    workflow: { path: ".github/workflows/release-build.yml", runId: 123, runAttempt: 1 },
    artifact: { id: 456, name: `ETCPRO6-unsigned-${commit}`, size: 2048, digest: "b".repeat(64) },
  });
  assert.equal(JSON.stringify(report).includes(token), false);
});

test("rejects mutable, mismatched, failed or expired source state", async () => {
  const mutations = [
    value => { value.run.head_sha = "c".repeat(40); },
    value => { value.run.head_branch = "feature"; },
    value => { value.run.conclusion = "failure"; },
    value => { value.run.path = ".github/workflows/other.yml"; },
    value => { value.tag.sha = "c".repeat(40); },
    value => { value.artifact.expired = true; },
    value => { value.artifact.name = "latest"; },
    value => { value.artifact.workflow_run.id = 999; },
    value => { value.artifact.digest = "sha256:not-a-digest"; },
  ];
  for (const mutate of mutations) {
    const value = structuredClone(valid);
    mutate(value);
    await assert.rejects(verifySourceRequest(env, fetcher(value)));
  }
});

test("rejects malformed caller inputs before contacting GitHub", async () => {
  for (const patch of [
    { SOURCE_REPOSITORY: "attacker/repo" },
    { SOURCE_COMMIT: "main" },
    { SOURCE_RUN_ID: "latest" },
    { SOURCE_ARTIFACT_ID: "0" },
    { RELEASE_TAG: "v01.2.3" },
    { GH_SOURCE_TOKEN: "short" },
  ]) {
    let called = false;
    await assert.rejects(verifySourceRequest({ ...env, ...patch }, async () => { called = true; throw new Error(); }));
    assert.equal(called, false);
  }
});

test("suppresses GitHub response bodies and token material on API errors", async () => {
  await assert.rejects(
    verifySourceRequest(env, async () => new Response(`${token}: private failure`, { status: 403 })),
    error => error.message === "GitHub API request failed (403)" && !error.message.includes(token),
  );
});
