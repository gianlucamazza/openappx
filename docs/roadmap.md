# Roadmap

## v0.1 — Pack foundation (current)

- [x] Project skeleton + MIT license
- [x] Blockmap generation (64 KiB SHA-256)
- [x] Pure-Python pack → `.msix`
- [x] Layout validation (manifest, executable, logos)
- [x] Minimal example layout + unit tests
- [x] Optional makemsix backend hook + bootstrap script

## v0.2 — Robustness

- [x] Golden tests against Microsoft-signed reference packages (fetched on demand)
- [x] LfhSize / ZIP parity asserted against the headers actually written
- [x] Byte-reproducible pack (asserted in tests)
- [x] `openappx inspect` — contents, blockmap summary, archive coherence (`--json`)
- [x] CI (GitHub Actions, Linux, Python 3.10–3.13)

### Known non-conformance in the packer (found by the golden tests)

Comparing our output with a Microsoft-signed package showed `pack_python` gets two
things wrong. Both are tracked by `test_our_own_packages_are_conformant` (xfail):

- [ ] **`Block/@Size` must be the _compressed_ length of each 64 KiB block**, and
      must be omitted entirely for stored parts. We currently write the
      uncompressed length. Fixing this means emitting the deflate stream
      block-by-block (`zlib.compressobj` + `Z_FULL_FLUSH`) so the per-block
      compressed boundaries are known — which `zipfile.writestr` cannot express,
      so the archive writer has to be hand-rolled.
- [ ] **An empty file must have zero `<Block>` elements**, not one block hashing
      `b""`.

Block _hashes_ are correct: they cover uncompressed data, as verified against the
reference package.

## v0.3 — Signing

- [x] Establish what `AppxSignature.p7x` actually contains → [signing.md](signing.md)
- [x] Parse the digest blob and verify a package against its own signature
- [x] `openappx inspect` reports signature digests and mismatches
- [x] Correct the false claim that `makemsix` can sign (it cannot: `pack` takes
      only `-d`/`-p`, and upstream has no signature creator)
- [ ] **Decision needed**: signing requires CMS/PKCS#7 + ASN.1 + RSA, none of
      which are in the standard library. Either add `cryptography` as an optional
      `[sign]` extra, or declare signature creation out of scope.
- [ ] Verify `Identity/@Publisher` against the signing certificate subject
      (needs certificate parsing, so it depends on the decision above)

## Later (research, not committed)

- Generic Device Portal / sideload deploy module (HTTP, no product lock-in)
- Notes on PE cross-compilation sysroots (documentation only unless a maintainer owns it)
- Bundle (`.msixbundle`) support

## Explicitly not planned as core

- Full UWP/WinRT application framework
- Shipping a Windows SDK sysroot inside this repo
