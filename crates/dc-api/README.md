# reallyme-openid4vp-dc-api

OpenID4VP bindings for the W3C Digital Credentials API and ISO/IEC 18013-7 mdoc
handover construction.

The mdoc CBOR model remains delegated to ReallyMe Identity envelope crates; this
crate owns only the OpenID4VP/DC API protocol boundary.

The request model covers unsigned, compact-signed, and multi-signed
`openid4vp-v1-*` entries. Multi-signed requests use a bounded JWS JSON General
Serialization model with duplicate-member rejection, at most 16 signatures,
redacted debug output, and best-effort zeroization on drop.

Unsigned entries are deserialized according to OpenID4VP Appendix A.2: wire
`client_id` and `expected_origins` members are consumed and ignored before the
typed request is built, even when `client_id` contains an unknown prefix.
Protocol identifiers are checked against the data representation at JSON and
protobuf boundaries so signed, multi-signed, and unsigned shapes cannot be
substituted for one another.

The `generate_iso_transport_evidence` example is compiled from the public
handover types and emits a non-sensitive JSON inventory of their field-level
transport semantics. It exists to detect documentation drift in downstream ISO
conformance evidence; it does not emit credentials, keys, or runtime values.
