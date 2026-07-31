# Architecture

openappx is a **host-side** toolchain. It does not run on the target OS of the package; it _produces_ packages that target Windows Appx/MSIX installers (desktop, server, or other devices that accept that format).

## Layers

```
L7  Deploy helpers
      openappx.deploy — Windows Device Portal REST client (Xbox, HoloLens,
      IoT, desktop). Doubles as the only end-to-end validator we have:
      the device accepts the package or explains why not.
L6  Sign
      openappx.sign — creates and verifies AppxSignature.p7x. Creation
      needs the optional [sign] extra; the DER encoding is ours.
L5  Pack
      blockmap + content types + OPC zip  ← v0 focus
L4  Validate
      manifest/layout checks before pack
L3  Layout (input contract)
      directory tree supplied by the app’s own build
L2  App binary build (out of tree)
      PE/DLL/assets produced by MSVC, clang-cl, dotnet, etc.
L1  Target platform (not openappx)
      Windows package manager / device OS
```

## v0 components

| Module               | Role                                                                      |
| -------------------- | ------------------------------------------------------------------------- |
| `openappx.blockmap`  | 64 KiB SHA-256 block hashes; `AppxBlockMap.xml`; ZIP local-header parsing |
| `openappx.validate`  | Layout / manifest sanity checks (**before** pack)                         |
| `openappx.pack_core` | Pack backends: `python`, `makemsix`                                       |
| `openappx.pack`      | CLI over `pack_core`                                                      |
| `openappx.inspect`   | Package / blockmap coherence checks (**after** pack)                      |
| `openappx.sign`      | `AppxSignature.p7x`: digests, DER encoding, signing, verification          |
| `openappx.deploy`    | Windows Device Portal client (install / list / uninstall / trust a cert)   |

`validate` and `inspect` bracket the pack step and never share code paths: the first
greps a layout that may be broken, the second re-derives hashes from a finished
archive. A package that survives both is structurally sound. That is still weaker than
"installs": the device also checks the signature, the manifest's semantics, and
its own policy. `docs/signing.md` maps which stage produces which error code.

## Backends

1. **`python`** — pure stdlib. Fast, portable, unsigned packages. Default.
2. **`makemsix`** — subprocess to Microsoft's open MSIX SDK CLI, when built with
   pack support. It produces **unsigned** packages too: upstream ships a
   signature *validator*, not a creator, and `makemsix pack` accepts only
   `-d`/`-p`. Kept as an alternative packer; not covered by tests, since the
   binary is rarely available.

## Extension points

- **New validators** — plug into `validate.layout_problems`
- **New pack backends** — implement `pack_with_backend(...)` contract
- **Deploy** — separate optional package; must not hard-depend on a single device brand

## Trust model

- Packaging tools never invent publisher identity: `AppxManifest.xml` `Identity/@Publisher` must match the signing certificate subject when signing is enabled.
- Public `.cer` files are safe to distribute for device trust; private `.pfx` material is a secret.
