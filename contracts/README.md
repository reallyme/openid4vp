# OpenID4VP Contracts

This directory owns the repository's public protocol-engine commitments. These
documents define repository ownership, specification coverage, and the evidence
required for compatibility and compliance claims.

The canonical machine-readable DTO, operation, service, and error contract
remains the versioned protobuf package under `crates/proto`. Documents here map
that wire contract to specifications, domain ownership, and verification
evidence; they do not define a competing wire model.

- `repository-contract.md` defines repository responsibilities and dependency
  boundaries.
- `spec-map.md` maps normative sources to implementation and evidence.
- `compliance-map.md` maps supported requirements to modules, tests, vectors,
  and conformance assets.

Changes to these documents are release-significant and must pass the same
release-readiness gates as implementation changes.
