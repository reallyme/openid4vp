# Rust Publishing

This repository owns the versioned OpenID4VP schema, generated Rust protobuf
bindings, strict proto/domain codecs, Rust-native protocol logic, and
framework-neutral protocol adapters. The crates are versioned in lockstep; a
published leaf crate is an implementation boundary, not an independently
versioned compatibility promise.

## Package Ownership

The following Rust crates are the complete approved crates.io publish set for
the current release:

| Package | Owner | Public role |
| --- | --- | --- |
| `reallyme-openid4vp-proto` | `reallyme/openid4vp` | Canonical generated message and ProtoJSON contract. |
| `reallyme-openid4vp-dcql` | `reallyme/openid4vp` | Standalone DCQL validation and evaluation. |
| `reallyme-openid4vp-types` | `reallyme/openid4vp` | Rust-native validated OpenID4VP domain types. |
| `reallyme-openid4vp-dc-api` | `reallyme/openid4vp` | Digital Credentials API and ISO/IEC 18013-7 handover types. |
| `reallyme-openid4vp-formats` | `reallyme/openid4vp` | Wallet presentation-format adapters. |
| `reallyme-openid4vp-wallet` | `reallyme/openid4vp` | Wallet request verification and response construction boundary. |

Every other workspace crate remains `publish = false`, including the facade,
profiles, verifier, HTTP, codec, runtime, conformance, and fuzz crates. Swift,
Kotlin/Android, FFI/JNI, and
application-facing SDK facades—including the `@reallyme/identity`
TypeScript/Wasm package—belong to `reallyme/identity`; they consume this
repository's generated contract and must not redefine its DTOs.

The service schema and future `reallyme-openid4vp-connect` transport crate are
owned here beside the message schema. Platform-facing Connect clients and SDK
facades remain owned by `reallyme/identity`. The Connect crate must begin
with `publish = false` and cannot be created or published until the dependency
uses the workspace's compatible Buffa version and the adapter gates in
the repository's protobuf-first boundary checks pass.

## Release Order

The exact release order is enforced by release tooling:

1. `reallyme-openid4vp-proto` 0.1.1
2. `reallyme-openid4vp-dcql` 0.1.1
3. `reallyme-openid4vp-types` 0.1.1
4. `reallyme-openid4vp-dc-api` 0.1.1
5. `reallyme-openid4vp-formats` 0.1.1
6. `reallyme-openid4vp-wallet` 0.1.1

Adding or publishing any other crate requires a separately reviewed policy and
release-tooling change. Cargo metadata alone cannot expand the publish set.

## Current Gate

The approved release set is `reallyme-openid4vp-proto`,
`reallyme-openid4vp-dcql`, `reallyme-openid4vp-types`,
`reallyme-openid4vp-dc-api`, `reallyme-openid4vp-formats`, and
`reallyme-openid4vp-wallet`. They must pass package-local
inspection, generated-source freshness where applicable, and locked dry-run
verification. Open sourcing the repository does not itself upload or release a
crate.

All remaining packages retain `publish = false`. The release inspector rejects
an unexpected publishable package, an unapproved version, a public crate whose
`rust-version` is not `1.96`, or a different publication order.

Before changing a publish flag, require all of the following:

```sh
scripts/check-openid4vp-format.sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
node scripts/check-proto-first-boundaries.mjs
npm exec --yes --package=github:reallyme/release-readiness#bdedc88f3f25fcc14242730d4dec6ce6a0c75531 -- \
  reallyme-release-readiness
RELEASE_VERSION=0.1.1 node scripts/publish-crates-in-order.mjs inspect --allow-dirty
```

The inspector derives dependency order from Cargo metadata, constructs the
normalized archives, checks each extracted package against the locked graph,
lists its packaged files, and performs a locked crates.io dry run without
uploading. CI runs the same command without `--allow-dirty`.

## Publication

OpenID4VP uses the same reviewed two-workflow release process as
`reallyme/cose`:

1. Commit the release version to every workspace package manifest, all internal
   dependency requirements, both lockfiles, and the default version displayed
   by **Crates Package Preflight**. Only the six approved public crates are
   packaged and uploaded.
2. Push that exact commit to `main`.
3. Dispatch **Crates Package Preflight** with the release version.
4. Review the successful package summary, the exact archived `.crate` files,
   their SHA-256 hashes, and the GitHub provenance attestations. The preflight
   also records the exact first-attempt CI, protobuf, fuzz, and secret-scan run
   IDs that certified the release commit.
5. Dispatch **Crates.io Release** at the same `main` commit.
6. The release verifies provenance and archive bytes, creates or verifies the
   immutable `reallyme-openid4vp-v<version>` tag and a draft GitHub release,
   then publishes the reviewed bytes in dependency order.
7. After all crates are downloaded back from crates.io and verified
   byte-for-byte, the workflow attaches the attestation, reviewed archives,
   and publication ledger and finalizes the GitHub release.

The release button exposes no version input; it derives the version from the
public manifests and rejects disagreement. Rerun preflights are rejected. A
changed commit or version requires a new preflight.

Publication uses the `crates-io` GitHub environment as the credential boundary.
Store the narrowly scoped crates.io token only as the environment secret named
`CARGO_REGISTRY_TOKEN`. Only the publish job enters that environment, after the
exact commit and reviewed package evidence have been verified. The workflow
deliberately does not request an OIDC token and does not use crates.io Trusted Publishing.
The token must never be stored in repository configuration, caches, logs, or
release artifacts.

For local review only:

```sh
RELEASE_VERSION=0.1.1 node scripts/publish-crates-in-order.mjs order
RELEASE_VERSION=0.1.1 node scripts/publish-crates-in-order.mjs inspect --allow-dirty
node --test scripts/*.test.mjs
```

Local inspection is not release authorization. An already-published version is
accepted only when its crates.io archive is byte-for-byte identical to the
reviewed preflight archive. The credential-bearing job re-verifies the
attestation, regenerates each crate, and rejects any size or SHA-256 mismatch
before every upload attempt. Its atomic publication ledger records pending,
attempting, newly published, and verified-existing states so a partial registry
release can be recovered without accepting different source bytes.

## One-time 0.1.0 wallet supplement

The first 0.1.0 release published only the proto, DCQL, and domain-type crates.
To complete the immutable 0.1.0 dependency graph required by ReallyMe Wallet,
publish the remaining crates from one clean, reviewed commit in this order:

```sh
cargo publish --locked -p reallyme-openid4vp-dc-api
cargo publish --locked -p reallyme-openid4vp-formats
cargo publish --locked -p reallyme-openid4vp-wallet
```

Do not use `--allow-dirty` or `--no-verify` for this local supplement. After
each upload, wait until crates.io exposes the new version before advancing. Run
`cargo info <package>@0.1.0 --registry crates-io` outside this workspace so
Cargo cannot satisfy the query from the local package; do not attempt the wallet
upload until both dependency versions resolve from crates.io. If crates.io
rate-limits an upload, wait for the registry's reported retry interval and rerun
only the same command. The general
`reallyme-openid4vp` facade is not part of this supplement. Starting with
0.1.1, use the reviewed main release workflow for the complete six-crate
cohort.
