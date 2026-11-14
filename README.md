# ETCPRO6 release automation

This public repository contains release automation and sanitized release metadata.
The application source and unsigned build artifacts stay in `AonBit/ETCPRO6-MAC`.
GitHub-hosted macOS runners export a previously built archive, sign and notarize
the DMG, sign its Sparkle feed, and publish immutable candidates. A separate
Environment controls stable promotion. This pipeline supports an owner approving
both stages; it does not claim two-person approval when the reviewers are the
same person.

The public workflow runs only reviewed tools from this repository's protected
`main`. It never checks out private source in the signing job, runs a downloaded
script, or invokes Xcode build phases. The private build produces a Universal
unsigned `.xcarchive`; the signer uses only `xcodebuild -exportArchive`.
Developer ID export of that archive remains a live Apple-credential acceptance
gate until an actual signing run succeeds.

## Interfaces

Node.js 22 or newer is required. There are no third-party Node dependencies.

```sh
npm test
npm run check
node tools/release.mjs candidate INPUT_DIRECTORY VERIFIED_REQUEST_JSON RECEIPT_DIRECTORY
node tools/release.mjs promote CANDIDATE_JSON RECEIPT_DIRECTORY
node tools/release.mjs resume ENCRYPTED_RECOVERY_DIRECTORY RECEIPT_DIRECTORY
node tools/release.mjs cleanup OWNED_RUNNER_WORK_DIRECTORY
```

`INPUT_DIRECTORY` must contain exactly `ETCPRO6-unsigned.xcarchive.zip` and
`unsigned-manifest.json`. The source verifier binds the repository, exact commit,
tag, successful private workflow run and artifact identity. The download helper
checks the original GitHub artifact ZIP SHA-256 before extracting the two files;
GitHub download-action warnings alone are not accepted as digest verification.
The signer then independently checks the manifest provenance, archive size/hash,
version/build, Sparkle pin and approved feed/public-key fingerprint.

ZIP parsing accepts bounded classic/ZIP64 records and verifies CRC, sizes,
descriptors, paths and duplicate names before extraction. Only the archive's
application tree is accepted. Internal relative framework links are supported;
absolute links, traversal, link cycles, device entries and links used as stored
entry ancestors fail closed. Source files, signing material and executable
scripts are rejected from the app. Extraction happens in a fresh `0700` system
temporary directory.

## Environment variables

The candidate Environment provides these secrets:

- `APPLE_SIGNING_P12`: canonical base64 Developer ID Application P12.
- `APPLE_SIGNING_P12_PASSWORD`, `APPLE_SIGNING_IDENTITY`, `APPLE_TEAM_ID`.
- `APPLE_NOTARY_KEY`: PKCS#8 P-256 PEM; `APPLE_NOTARY_KEY_ID` and
  `APPLE_NOTARY_ISSUER_ID` identify the same API key.
- `SPARKLE_PRIVATE_KEY`: canonical base64 32-byte seed or reviewed 96-byte legacy
  expanded-private-plus-public format. A standalone 64-byte key is rejected.
- `RECOVERY_ENCRYPTION_KEY`: independent canonical base64 32-byte AES key. Keep it
  available for the lifetime of encrypted recovery artifacts; rotating it early
  makes pending recovery impossible.
- `CF_CANDIDATE_ACCESS_CLIENT_ID`, `CF_CANDIDATE_ACCESS_CLIENT_SECRET`,
  `STAGING_CF_CANDIDATE_ACCESS_CLIENT_ID`,
  `STAGING_CF_CANDIDATE_ACCESS_CLIENT_SECRET`.

Candidate variables are `ETCPRO6_UPDATE_PUBLIC_KEY`, `UPDATE_ADMIN_BASE_URL`,
`UPDATE_PUBLIC_BASE_URL`, `STAGING_UPDATE_ADMIN_BASE_URL`,
`STAGING_UPDATE_PUBLIC_BASE_URL`. The four HTTPS origins must differ. The fixed
feed is the production public origin's `/stable/appcast.xml`. `RUNNER_TEMP` is
supplied by GitHub. The executor writes `ETCPRO6_RELEASE_WORK` to `GITHUB_ENV`
before preparing signing material so an `always()` cleanup step can retry.

Stable receives only `CF_CHANNEL_ACCESS_CLIENT_ID`,
`CF_CHANNEL_ACCESS_CLIENT_SECRET` and the production admin/public origins.
Candidate rejects channel credentials. Stable rejects Apple, Sparkle, candidate
and recovery secrets. Neither stage uses a long-lived personal GitHub token.
Private artifact access uses a short-lived, repository-scoped GitHub App token
with Actions read and Contents read; token acquisition and revocation are owned
by the workflow/orchestration layer.

Raw secrets are never command-line arguments or child-process environment
variables. Keychain password/import commands are passed through `security -i`
standard input. Child processes receive a small runtime environment whitelist.
Tool output is captured, and public CLI errors use fixed wording. The temporary
Keychain's original search list is restored; raw P12/P8/Sparkle files are removed
before candidate HTTP upload begins. A cleanup failure stops publication and
retains minimal local recovery state for an `always()` retry. Use disposable
GitHub-hosted runners; the runtime whitelist is not a sandbox for hostile tools.

## Sparkle tool provenance

The signing job downloads the official Sparkle 2.10.1 SPM artifact independently
of the private archive:

- URL: `https://github.com/sparkle-project/Sparkle/releases/download/2.10.1/Sparkle-for-Swift-Package-Manager.zip`
- SHA-256: `4c2e48a3e50ebcc2c88a58a4c7264a1a99c3c31857ce754357afb9cdb323022a`
- Source revision: `ab7d71291238df6e0492143b120c9b696a35f603`

The checksum is the one published in Sparkle's reviewed `Package.swift`.
Only the checksum-verified `bin/sign_update` is executed. The archive signature
and signed-feed trailer are verified with that official tool before uploading.
The distributed app enforces signed feeds, verification before extraction and
zero signature-downgrade interval, with automatic checks/installs off by default.

## Failure and recovery

Only an enumerated set of sanitized JSON receipts and AES-GCM ciphertext may be
uploaded from a public workflow. Raw private archives, source, DMGs, appcasts,
Xcode logs, certificate files and Keychain material must never be Actions
artifacts in this repository. Candidate DMGs become public only through the
authorized update service after finalization.

The executor preserves three independently authenticated recovery stages:

| Snapshot | Meaning | Resume behavior |
| --- | --- | --- |
| `submission-recovery.bin` + `.json` | Exact signed DMG saved before submitting to Apple; response may be lost | Requires an operator to inspect Apple history and provide `NOTARY_SUBMISSION_ID` plus matching `CONFIRM_SUBMISSION_SHA256`; never submits again |
| `notary-recovery.bin` + `.json` | Submission ID and exact submitted bytes are known | Waits/queries the same ID, then staples and signs the feed |
| `candidate-recovery.bin` + `.json` | Final stapled DMG, exact signed appcast and complete manifest are saved | Reuses all bytes, hashes and `createdAt`; retries candidate finalization/staging without signing or notarizing again |

`resume` chooses the most advanced snapshot present and checks ciphertext hash,
AES-GCM authentication, submitted/final hashes, source provenance, team and update
configuration. The JSON envelope is authenticated as additional data. It contains
metadata and random nonce/tag, not the encryption key. Altering the metadata or
ciphertext fails before a recovered artifact is used.

`notary.json`, `manifest.json`, `candidate.json`, `source.json`, `stable.json` and
optional `submission-binding.json` are sanitized receipts. Candidate does not
change stable. Stable rechecks the finalized server manifest and downloaded
DMG/feed bytes before CAS, saves `stable.json` immediately after mutation, then
probes the stable feed. A post-publication timeout can follow a committed change:
inspect that receipt and server audit before retrying. Rollback is an explicit
audited management action using the current channel ETag/build; clients already
on a higher build do not downgrade automatically.

Automated acceptance includes malicious archives/provenance, child-secret
isolation, Keychain cleanup retry, same-ID notary recovery, lost submit response,
encrypted recovery tampering, candidate/channel separation and a production
finalization followed by staging failure/recovery. Real Developer ID export,
notarization, Gatekeeper, Cloudflare Access/R2 behavior and bootstrap-to-next-build
Sparkle installation require the live credentials and clients.
