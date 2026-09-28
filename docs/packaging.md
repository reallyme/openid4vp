# Rust Binary Packaging Policy

ReallyMe Rust packages follow the Russian-doll rule: each higher layer embeds
all lower Rust layers through Cargo dependencies and exposes one top-level
binary artifact to the consuming app.

## Rules

- Every native FFI crate must retain `rlib` when it also emits a platform
  library, because higher-layer packages aggregate symbols through ordinary
  Cargo dependency linking.
- A platform package at layer N embeds all lower Rust layers in its single
  binary. For example, an identity xcframework contains crypto's Rust code
  because identity depends on crypto. It must not link or load crypto's separate
  xcframework, dylib, JNI library, or wasm module.
- An app must not contain two ReallyMe Rust binaries. Standalone layer packages
  exist for single-layer consumers; composed consumers use the highest-layer
  package, or an SDK repository's combined package when multiple top-level
  layers are intentionally bundled.
- Swift and Kotlin facade source stays binary-agnostic. It programs against C
  ABI names, JNI names, or wasm exports. The top-level package decides which
  artifact provides those symbols.
- ReallyMe Identity owns the single composed Wasm module and TypeScript facade.
  Lower-level repositories expose ordinary Rust libraries with a `wasm`
  feature where they participate in that composition; they do not expose a
  separate JavaScript API or Wasm package.

## Practical Consequences

- Add native FFI exports only at deliberate package boundaries. Wasm exports
  belong exclusively to ReallyMe Identity.
- Prefer source-level facade crates over platform binaries for lower layers.
- Do not make lower-layer native or wasm artifacts runtime dependencies of a
  higher-layer package.
- This repository must not depend on `wasm-bindgen`, declare a `cdylib` or a
  standalone binary for a crate with a `wasm` feature, commit a `.wasm` binary,
  or contain an npm package manifest.
- If a native leaf crate needs `staticlib` or `dylib`, keep `rlib` in the crate
  type list and add a test or CI check that the top-level package can link it
  through Cargo.
- Documentation for platform package consumers should name the highest package
  they should install, not a stack of lower ReallyMe binaries.
