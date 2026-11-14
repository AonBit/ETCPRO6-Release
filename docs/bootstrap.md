# Cloud release setup

This repository contains public release tooling only. The source repository and unsigned Actions artifacts remain private in `AonBit/ETCPRO6-MAC`. No source checkout or source-provided command is allowed in the signing job.

## Operator model

The owner selected a single operator: `clementatt`. Both `production-candidate` and `production-stable` require this account's manual approval. Self-review must be allowed so the same operator can dispatch and approve. These are two explicit confirmations, not independent two-person review. If a second operator becomes available, use disjoint reviewer groups and enable prevention of self-review.

Protect `main` against force pushes and deletion, enforce protection for administrators, and require the `check` CI status. Keep Actions tokens read-only. Permit deployment only from protected branches. Secrets belong exclusively to the matching Environment.

## Configuration

Keep repository variable `CLOUD_RELEASE_ENABLED` unset until all settings, service identities and credentials below are verified. The release workflow fails closed while it is unset.

Create a GitHub App installed only on `AonBit/ETCPRO6-MAC`, with Contents read and Actions read permissions. Put its client ID in candidate variable `SOURCE_APP_CLIENT_ID` and its private key in candidate secret `SOURCE_APP_PRIVATE_KEY`.

Candidate Environment variables:

- `UPDATE_PUBLIC_BASE_URL`, `UPDATE_ADMIN_BASE_URL`
- `STAGING_UPDATE_PUBLIC_BASE_URL`, `STAGING_UPDATE_ADMIN_BASE_URL` (four distinct HTTPS origins)
- `ETCPRO6_UPDATE_PUBLIC_KEY` (canonical base64 of the 32-byte Sparkle public key)
- `APPLE_SIGNING_IDENTITY` (`Developer ID Application: … (TEAMID)`), `APPLE_TEAM_ID`
- `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER_ID`

Candidate Environment secrets:

- `APPLE_SIGNING_P12`, `APPLE_SIGNING_P12_PASSWORD`
- `APPLE_NOTARY_KEY` (App Store Connect P8 content)
- `SPARKLE_PRIVATE_KEY`
- `RECOVERY_ENCRYPTION_KEY` (random 32 bytes, canonical base64; retain securely for pending submission recovery)
- `CF_CANDIDATE_ACCESS_CLIENT_ID`, `CF_CANDIDATE_ACCESS_CLIENT_SECRET`
- `STAGING_CF_CANDIDATE_ACCESS_CLIENT_ID`, `STAGING_CF_CANDIDATE_ACCESS_CLIENT_SECRET`

Stable Environment variables: production `UPDATE_PUBLIC_BASE_URL`, `UPDATE_ADMIN_BASE_URL` only. Stable secrets: `CF_CHANNEL_ACCESS_CLIENT_ID`, `CF_CHANNEL_ACCESS_CLIENT_SECRET` only. Candidate service identities may upload/finalize releases; the channel identity may promote and may not upload. Apple, Sparkle, source App and recovery keys must not be repository-level secrets or stable secrets.

Never paste private keys or passwords into chat, workflow inputs or public issues. Configure them through GitHub Environment Secrets or a local secure input flow.

## Normal release

1. Push reviewed private source to `main`, with a `vX.Y.Z` tag at the exact source commit.
2. Run private `release-build.yml` with the production stable feed URL and Sparkle public key. Record successful run ID, artifact ID and full commit SHA.
3. Dispatch public `release.yml` from protected `main` with those exact IDs, SHA and tag. Approve candidate after checking the request.
4. The fresh signer validates provenance and exact artifact ZIP digest, revokes the private-read token, signs/notarizes the built application, verifies mounted DMG, signs the feed and finalizes production/staging candidate bytes.
5. Review `candidate.json` and approve stable. A different fresh runner rechecks finalized bytes and uses compare-and-swap to change the stable channel.
6. Perform real Gatekeeper installation and bootstrap-to-next-build Sparkle update acceptance. Automated checks do not establish real client acceptance.

## Interrupted notarization

Failure artifacts contain only AES-256-GCM ciphertext and authenticated metadata: the fixed pairs `submission-recovery.bin/json`, `notary-recovery.bin/json`, and `candidate-recovery.bin/json`. No raw DMG or unsigned archive is published. The first snapshot precedes submission, the second binds the returned submission ID, and the third retains exact stapled DMG/feed/manifest bytes before candidate upload. Do not blindly rerun candidate or resubmit the same version. Download the encrypted recovery artifact from the exact trusted public workflow run, then use the trusted `resume` command described in README with the same recovery key and a candidate-approved credential context. Resume prefers exact candidate bytes or polls the same notary ID. If the submission response was lost, inspect Apple submission history and explicitly bind its ID and submitted hash; absence of a local ID does not mean Apple rejected the request. An automated recovery workflow is a follow-up until its provenance checks are reviewed.

## Current verification boundary

Local tests and unsigned archive fixtures can validate structure and rejection behavior. Developer ID export, Apple notarization, deployed Cloudflare service authorization and a real Sparkle update require configured credentials and end-to-end execution. Do not mark release readiness complete before those checks pass.
