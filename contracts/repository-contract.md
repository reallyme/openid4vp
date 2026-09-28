# OpenID4VP Repository Contract

This repository is the ReallyMe protocol engine for OpenID for Verifiable
Presentations. It owns the OpenID4VP protocol model, DCQL evaluation, verifier
and wallet validation policy, Digital Credentials API protocol projections,
HAIP profile descriptors, canonical protobuf schemas, bounded wire-to-domain
conversion, and framework-neutral runtime operations.

## Owned Boundaries

- `crates/proto` is the only canonical protobuf package. It owns versioned wire
  DTOs, operation envelopes, service declarations, and public protocol errors.
- `crates/proto-codec` is the only authored protobuf conversion boundary. It
  validates untrusted generated DTOs and maps them to strongly typed domain
  values under explicit size and recursion limits.
- Focused crates under `crates/` own protocol behavior. The facade crate exposes
  those boundaries without duplicating their implementation.
- `contracts/` records public behavior, specification coverage, compatibility,
  and compliance commitments.
- `conformance/` owns executable cross-component verification, suite-specific
  fixtures, runner integration, and evidence.
- `vectors/` owns stable reusable interoperability vectors; `fuzz/` owns fuzz
  targets and corpora.

## Delegated Boundaries

- Credential-format primitives and shared identity envelopes belong to
  `reallyme/ssi`.
- Cryptographic primitives and provider implementations belong to
  `reallyme/crypto` and the relevant JOSE, COSE, or ZK repositories.
- Wallet inventory, consent UX, service deployment, storage, key custody, and
  platform SDK packaging belong to their host repositories.
- Cross-repository certification orchestration belongs to private downstream
  systems; this repository retains protocol-specific adapters and evidence and
  must not require private repositories in its CI.

## Compatibility Rules

Generated protobuf messages and ProtoJSON are the stable SDK DTO boundary.
Handwritten Serde models are internal protocol projections and are not a second
public compatibility surface. Unsupported modes and missing providers fail
closed. Sensitive request, presentation, session, and cryptographic material
must remain bounded, redacted, and explicitly zeroized by its owning layer.

The root Cargo manifest is a virtual workspace. Public crates must preserve
their documented dependency direction and publication policy. A change to the
canonical schemas, operation envelopes, public errors, or these ownership rules
is release-significant.
