# reallyme-openid4vp-verifier

Verifier-side OpenID4VP request construction and authorization-response
validation.

The crate is network-free. Signing, holder-binding verification, clock access,
and session storage are injected through explicit traits. The versioned ZK
adapter uses the same `HolderBindingVerifier` boundary and delegates proof
verification to injected `reallyme-zk-api` verifiers. A direct or private
claim also requires the issuer-credential-status proof and a trusted current
issuer-status authority.
Without that verifier, ZK presentations fail closed. mdoc verification also
requires a transcript provider that canonically rebuilds the active request
binding; retained bytes alone are rejected.

## ZK credential query

Use DCQL format `reallyme.openid4vp.zk_presentation.v1`. Its `meta` object
contains three required strings: `profile` (`credential_subject_claim_v1` or
`private_persona_claim_v1`), `hash_strategy`
(`sha256` or `poseidon2`), and `claim_name_hash` (32 bytes as lowercase hex).
Optional `claim_value_b64u` constrains the result to an exact 1–64-byte value
encoded as canonical unpadded base64url. Without it, the authenticated claim
bytes are returned as a zeroizing `VerifiedZkClaim` disclosure.
The claim-name hash must come from the issuer's agreed credential schema;
this adapter does not infer the semantic claim name from the hash. The v1
query has no additional DCQL `claims`, `claim_sets`, or `trusted_authorities`.
The presentation's free-form `derived_claims` list must be empty. The adapter
compares the requested hash and any requested exact value with the API's
verified statement, so an unverified label cannot become an authenticated
claim.

Configure `ZkVerificationRequirements` explicitly. A direct or private
credential presentation requires issuer-signed validity and current status.
The four claim proofs alone are insufficient: the adapter requires a fifth
issuer-credential-status proof joined to the same hidden credential and a
signature-verified current issuer list admitted by a durable rollback floor.
Missing proof, verifier, status authority, or trust policy fails closed.

Each bundle yields one independently verified claim. For a product decision
that several claims use the same presenting key, compare their typed
`VerifiedZkClaim` values with `same_presenting_key_in_session`. This comparison
is conclusive only when true: it requires the same profile, hash lane, and
session-link commitment. Different transaction bindings or expiry values can
produce different commitments for the same persona. The generic response
verifier does not impose this product composition rule automatically.

## Common-credential-root verification

The common-credential-root profile verifies both issuer-signed credentials, their current
signed status lists, the ReallyMe root attestation, the current active-root
snapshot, and all nine linked proofs against the active presentation session.
The verifier supplies the trusted issuers, attestation signer, assurance policy,
status authority, and a stable `status_feed_id` for the active-root feed.
That feed ID is a deployment configuration value: it remains the same when the
feed's HTTPS endpoint or trusted status signing key changes and differs for
unrelated feeds. The durable rollback floor is keyed by this ID, so transport
and signer changes preserve the highest accepted sequence.
