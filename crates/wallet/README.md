# reallyme-openid4vp-wallet

Wallet-side OpenID4VP request parsing, Request Object verification boundaries,
transport validation, and presentation preparation hooks.

Network access, trust resolution, JOSE verification, and ZK proving are owned by
hosts or higher-level SDK crates. This crate validates the backend-neutral ZK
envelope before including it in an authorization response.

X.509 Request Object resolvers return one atomic key-and-trust result. For the
X.509 modes, that result contains a typed `Trusted`, `Rejected`, or `Indeterminate` WRPAC
decision, a bounded leaf-first chain, the leaf public key, DNS SANs, evaluation
interval, policy version, source-snapshot digest, and selected-anchor digest.
DNS SAN strings are bounded and converted to typed canonical A-label names when
the trusted signer result is constructed, so unchecked certificate identities
cannot cross into the receipt-building pipeline.
The wallet binds that result to the exact `x5c` header and JWS verification key
before it creates the opaque `VerifiedX509CertificateBinding` receipt.

The rules are anchored in OpenID4VP 1.0 Final Section 5.9.3 and RFC 7515
Section 4.1.6. `x509_hash` is compared with unpadded
base64url(SHA-256(DER leaf)). `x509_san_dns` uses RFC 8399 Section 2.3's
case-insensitive exact whole-name comparison after IDNA A-label conversion;
TLS wildcard matching is not used. HTTPS authorities are parsed and
canonicalized under RFC 3986 Sections 3.2 and 6.2, with percent-encoded
authorities, all userinfo (including empty userinfo), reverse-solidus parser
aliases, and trailing-root-dot aliases rejected by the versioned local policy.
Embedded or remote JOSE key-selection alternatives (`jwk`, `jku`, and `x5u`)
and unsupported critical-header processing are rejected; the only X.509 key
material admitted for these modes is the bounded protected `x5c` chain.

Digital Credentials API multi-signed Request Objects are verified as JWS JSON
General Serialization. Each protected header supplies its own `client_id`; the
wallet binds that identifier to the exact signature and trust evidence, applies
the complete request policy independently, and accepts only when at least one
signature path is valid. Payload size, protected-header size, and signature
count are bounded before trust resolution.

Unsigned DC API requests have a separate validation path because browser
invoking-origin security replaces signed client identity. The DC API model
discards `client_id` and `expected_origins` on that path—even when an invalid
client-id prefix appears on the wire, as required by Appendix A.2—then the
wallet validator enforces response mode, endpoint cardinality, nonce, DCQL,
metadata-reference, and transaction-data policy.

Application-defined `transaction_data` semantics are deny-by-default. Hosts
must construct a `WalletTransactionDataPolicy` containing exact supported type
identifiers and pass it to the policy-aware validation or verification API.
Empty policy entries, duplicates, empty transaction-data arrays, and any
unlisted type produce the stable `InvalidTransactionData` reason without
including transaction content in errors.

Nested signed-then-encrypted Request Objects follow RFC 9101 Section 10.1 and
return the same atomic result from the exact decrypted inner JWS, preserving
certificate, verifier-attestation, and trusted metadata evidence. Unprefixed
pre-registered clients are explicitly unsupported by the production
`WalletClientIdentifierPolicy`; OpenID4VP does not define a Wallet Metadata
field that advertises Client Identifier Prefix support, so this mode is not
advertised elsewhere.
