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

### Conformance fixes (found by the golden tests)

Comparing our output with a Microsoft-signed package exposed two format errors,
both now fixed:

- [x] **`Block/@Size` is the _compressed_ length of each 64 KiB block**, omitted
      entirely for stored parts. Getting this right required emitting the deflate
      stream block-by-block (`zlib.compressobj` + `Z_FULL_FLUSH`) so per-block
      compressed extents are known — which `zipfile.writestr` cannot express, so
      `pack_python` now writes the archive itself (local headers, central
      directory, EOCD).
- [x] **An empty file has zero `<Block>` elements**, not one hashing `b""`.
- [x] Payload is deflated only when it actually shrinks; otherwise stored.

Block _hashes_ were already correct: they cover uncompressed data.

## v0.3 — Signing

- [x] Establish what `AppxSignature.p7x` actually contains → [signing.md](signing.md)
- [x] Parse the digest blob and verify a package against its own signature
- [x] `openappx inspect` reports signature digests and mismatches
- [x] Correct the false claim that `makemsix` can sign (it cannot: `pack` takes
      only `-d`/`-p`, and upstream has no signature creator)
- [x] **Decision taken: signature creation is out of scope for v0.** It needs
      CMS/PKCS#7 + ASN.1 + RSA, none of which are in the standard library, and —
      more importantly — nothing in a Linux-only environment can tell us whether
      a signature we produce would actually be accepted. Shipping unverifiable
      signing code is worse than shipping none. [signing.md](signing.md) records
      exactly what a signer must produce, so the work is ready to pick up if a
      maintainer has a way to validate the result (a Windows host, or a locally
      built `makemsix` whose validator can be pointed at our output).
- [ ] Verify `Identity/@Publisher` against the signing certificate subject
      (needs certificate parsing; depends on the decision above)
