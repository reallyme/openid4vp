# reallyme-openid4vp-formats

Format-specific OpenID4VP presentation glue for SD-JWT VC, mdoc, and ZK
presentation entries.

Concrete cryptography and ZK backends stay outside this crate. It owns the
typed ZK presentation envelope, bounded parsing, canonical stage layout, and
constant-time session-binding comparison. Proving and cryptographic proof
verification are deliberately delegated to the composed product.
