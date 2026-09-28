# Protocol Vectors

This directory owns reusable, implementation-independent OpenID4VP vectors:

- `vectors/protojson/` contains canonical generated ProtoJSON examples and malicious
  boundary inputs.
- `vectors/protobuf/` contains the matching protobuf bytes as reviewable lowercase
  hexadecimal text.
- `vectors/dc-api/` and `vectors/mdoc/` contain reusable protocol-flow examples.
- `openid4vp-malicious-json.json` contains parser accept/reject cases shared by
  the conformance harness.
- `openid4vp-x509-request-binding.json` contains cross-implementation vectors
  for OpenID4VP 1.0 Final Section 5.9.3, RFC 7515 Section 4.1.6, RFC 8399
  Section 2.3, and the repository's strict endpoint-authority policy.

OIDF runner configuration and standards-suite-specific interoperability
fixtures remain under `conformance/`.
