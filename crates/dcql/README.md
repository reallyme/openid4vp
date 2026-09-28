# ReallyMe OpenID4VP DCQL

Standalone Rust model, validator, and evaluation engine for Digital Credentials
Query Language as used by OpenID4VP 1.0 final.

This crate is intentionally protocol-focused: it validates DCQL structures,
evaluates credential-query matches, and reports typed errors without depending
on wallet storage, verifier transport, JOSE, credential envelopes, or ZK
backends.

## License

Licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at your option.
