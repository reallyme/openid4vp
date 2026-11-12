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
| `reallyme-openid4vp-profiles` | `reallyme/openid4vp` | Shared OpenID4VP presentation-profile adapter. |
| `reallyme-openid4vp-verifier` | `reallyme/openid4vp` | Verifier request and response validation boundary. |
| `reallyme-openid4vp-http` | `reallyme/openid4vp` | Framework-neutral HTTP transport adapter traits. |
| `reallyme-openid4vp-proto-codec` | `reallyme/openid4vp` | Strict protobuf/domain conversion boundary. |
| `reallyme-openid4vp-runtime` | `reallyme/openid4vp` | Runtime protobuf operations and transport adapters. |
| `reallyme-openid4vp` | `reallyme/openid4vp` | Public feature-gated protocol facade. |

The conformance and fuzz packages remain `publish = false`. Swift,
Kotlin/Android, FFI/JNI, and
application-facing SDK facades—including the `@reallyme/identity`
TypeScript/Wasm package—belong to `reallyme/identity`; they consume this
repository's generated contract and must not redefine its DTOs.

The transport-neutral service declarations live beside the message schema.
This workspace contains no Connect transport implementation. Platform-facing
clients and SDK facades consume the generated messages without redefining their
fields or JSON representation.

## Release Order

The exact release order is enforced by release tooling:

1. `reallyme-openid4vp-proto` 0.3.1
2. `reallyme-openid4vp-dcql` 0.3.1
3. `reallyme-openid4vp-types` 0.3.1
4. `reallyme-openid4vp-dc-api` 0.3.1
5. `reallyme-openid4vp-formats` 0.3.1
6. `reallyme-openid4vp-wallet` 0.3.1
7. `reallyme-openid4vp-profiles` 0.3.1
8. `reallyme-openid4vp-verifier` 0.3.1
9. `reallyme-openid4vp-http` 0.3.1
10. `reallyme-openid4vp-proto-codec` 0.3.1
11. `reallyme-openid4vp-runtime` 0.3.1
12. `reallyme-openid4vp` 0.3.1

Adding or publishing any other crate requires a separately reviewed policy and
release-tooling change. Cargo metadata alone cannot expand the publish set.

## Current Gate

The approved release set is the 12 packages listed above. They must pass package-local
inspection, generated-source freshness where applicable, and locked dry-run
verification. Open sourcing the repository does not itself upload or release a
crate.

Every exact external dependency version in the package manifests must be
available in the crates.io index before package preflight. Source-checkout,
local patch, and Git substitutions are rejected by the release gate.

The conformance and fuzz packages retain `publish = false`. The release inspector rejects
an unexpected publishable package, an unapproved version, a public crate whose
`rust-version` is not `1.99`, or a different publication order.

Before changing a publish flag, require all of the following:

```sh
scripts/check-openid4vp-format.sh
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
node scripts/check-proto-first-boundaries.mjs
# v0.6.9: https://github.com/reallyme/release-readiness/releases/tag/v0.6.9
npm exec --yes --package=github:reallyme/release-readiness#9cf40c7da1def8a8d809af51789284097c572dd5 -- \
  reallyme-release-readiness
RELEASE_VERSION=0.3.1 node scripts/publish-crates-in-order.mjs inspect --allow-dirty
```

The inspector derives dependency order from Cargo metadata, constructs the
normalized archives, checks each extracted package against the locked graph,
lists its packaged files, and performs a locked crates.io dry run without
uploading. CI runs the same command without `--allow-dirty`.

## Publication

The two-workflow release process binds publication to reviewed source and
package bytes:

1. Commit the release version to every workspace package manifest, all internal
   dependency requirements, both lockfiles, and the default version displayed
   by **Crates Package Preflight**. Only the 12 approved public crates are
   packaged and uploaded.
2. Push that exact commit to `main`.
3. Dispatch **Crates Package Preflight** with the release version.
4. Review the successful package summary, the exact archived `.crate` files,
   their SHA-256 hashes, and the GitHub provenance attestations. The preflight
   also records the exact first-attempt CI, protobuf, fuzz, and secret-scan run
   IDs that validated the release commit.
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
RELEASE_VERSION=0.3.1 node scripts/publish-crates-in-order.mjs order
RELEASE_VERSION=0.3.1 node scripts/publish-crates-in-order.mjs inspect --allow-dirty
node --test scripts/*.test.mjs
```

Local inspection is not release authorization. An already-published version is
accepted only when its crates.io archive is byte-for-byte identical to the
reviewed preflight archive. The credential-bearing job re-verifies the
attestation, regenerates each crate, and rejects any size or SHA-256 mismatch
before every upload attempt. Its atomic publication ledger records pending,
attempting, newly published, and verified-existing states so a partial registry
release can be recovered without accepting different source bytes.
