# Formal Models

This directory contains symbolic models for security-critical OpenID4VP
protocol composition. The models are checked with
[Tamarin](https://tamarin-prover.github.io/); parser safety, concrete JOSE/COSE
algorithms, and wire encodings remain covered by conformance vectors, property
tests, and coverage-instrumented fuzzing.

## Models

| Model | Composition | Proves |
| --- | --- | --- |
| [`tamarin/openid4vp_session_binding.spthy`](tamarin/openid4vp_session_binding.spthy) | Signed Request Object, holder-bound presentation, verifier session consumption, and hosted `request_uri` | Accepted presentations are bound to the exact session tuple unless the holder key was revealed; a verifier session cannot accept twice; a hosted Request Object can be fetched repeatedly |

The model represents Request Object and holder-proof authentication with
Tamarin's symbolic signing theory and explicit verification equations. The
concrete algorithm implementations remain owned and tested by
`reallyme-jose`, `reallyme-cose`, and `reallyme/crypto`; the model proves that
an attacker cannot substitute any OpenID4VP nonce, audience, state,
credential, session, or key without a matching signature or a prior holder-key
compromise.

Every universal security lemma is accompanied by an `exists-trace` sanity
lemma so a disconnected or over-constrained model cannot pass vacuously.

## Checking

Requires `tamarin-prover` on `PATH`:

```sh
tamarin-prover --prove formal/tamarin/openid4vp_session_binding.spthy
```

[`scripts/check-formal-models.sh`](../scripts/check-formal-models.sh) pins the
accepted prover version and fails unless every expected lemma is verified. CI
installs checksum-pinned Tamarin 1.12.0 and Maude 3.5.1 release binaries before
running that gate.

The expected result is that all five lemmas verify:

- `sanity_acceptance_exists`
- `sanity_request_object_refetch_exists`
- `accepted_presentation_has_exact_session_binding`
- `verifier_session_accepts_at_most_once`
- `accepted_presentation_follows_session_start`
