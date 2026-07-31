# Architecture

openappx is a **host-side** toolchain. It does not run on the target OS of the package; it *produces* packages that target Windows Appx/MSIX installers (desktop, server, or other devices that accept that format).

## Layers

```
L7  Deploy helpers (optional, future)
      device portals, sideload scripts — product-agnostic HTTP/CLI
L6  Sign
      AppxSignature.p7x from PFX / cert pipeline
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

| Module | Role |
|--------|------|
| `openappx.blockmap` | 64 KiB SHA-256 block hashes; `AppxBlockMap.xml` |
| `openappx.validate` | Layout / manifest sanity checks |
| `openappx.pack` | Assemble zip; backends: `python`, `makemsix` |
| `openappx.sign` | Placeholder package for future signing API |

## Backends

1. **`python`** — pure stdlib. Fast, portable, unsigned packages. Default.
2. **`makemsix`** — subprocess to Microsoft’s open MSIX SDK CLI (when built with pack support). Can attach a PFX for signing.

## Extension points

- **New validators** — plug into `validate.layout_problems`
- **New pack backends** — implement `pack_with_backend(...)` contract
- **Deploy** — separate optional package; must not hard-depend on a single device brand

## Trust model

- Packaging tools never invent publisher identity: `AppxManifest.xml` `Identity/@Publisher` must match the signing certificate subject when signing is enabled.
- Public `.cer` files are safe to distribute for device trust; private `.pfx` material is a secret.
