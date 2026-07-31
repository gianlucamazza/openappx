# Roadmap

## v0.1 — Pack foundation

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

Comparing our output with a Microsoft-signed package exposed format errors, all
now fixed:

- [x] **`Block/@Size` is the _compressed_ length of each 64 KiB block**, omitted
      entirely for stored parts. Getting this right required emitting the deflate
      stream block-by-block (`zlib.compressobj` + `Z_FULL_FLUSH`) so per-block
      compressed extents are known — which `zipfile.writestr` cannot express, so
      `pack_python` writes the archive itself (local headers, central directory,
      EOCD).
- [x] **An empty file has zero `<Block>` elements**, not one hashing `b""`.
- [x] Payload is deflated only when it actually shrinks; otherwise stored.
- [x] **Appx archives must be ZIP64.** Not a size question: a ZIP32 package of
      any size fails to open on the device with `0x8007000B`.

Block _hashes_ were already correct: they cover uncompressed data.

## v0.3 — Signing (done)

- [x] Establish what `AppxSignature.p7x` actually contains → [signing.md](signing.md)
- [x] Parse the digest blob and verify a package against its own signature
- [x] `openappx inspect` reports signature digests and mismatches
- [x] Correct the false claim that `makemsix` can sign (it cannot: `pack` takes
      only `-d`/`-p`, and upstream has no signature creator)
- [x] **`openappx sign` creates signatures on Linux.** `cryptography` sits behind
      the optional `[sign]` extra for RSA and PKCS#12; the DER encoding is ours
      (`sign/asn1.py`). An Xbox One dev kit installed a package packed and signed
      entirely by this project, and rejected the same package with one byte
      changed (`0x80096010 TRUST_E_BAD_DIGEST`).
- [x] Check `Identity/@Publisher` against the certificate subject before signing,
      so a mismatch fails locally instead of on the device with an opaque code
- [ ] Timestamping (countersignature), so signatures outlive certificate expiry

## v0.4 — Device validation

- [x] Generic Device Portal deploy module (`openappx deploy`) — stdlib HTTP, no
      product lock-in; the same REST API serves Xbox, HoloLens, IoT and desktop
- [x] `--install-cert` to trust a certificate on the device
- [x] End-to-end proof on real hardware: pack → sign → deploy → installed
- [x] Mapped the full validation chain by deploying deliberately-broken packages:
      container → signature → blockmap → manifest syntax → manifest semantics →
      deployment. See the table in [signing.md](signing.md).
- [x] `validate` now catches `runFullTrust` locally, a rule the device reports
      only as `0x80080204` plus a line number
- [ ] Repackage a real application (xllama) with openappx and install it — the
      remaining gap is that its layout is produced on a Windows VM, so nothing
      here has yet packaged a genuine UWP binary
- [ ] Optional: read back `GET /state` phases for progress reporting

## Later (research, not committed)

- Notes on PE cross-compilation sysroots (documentation only unless a maintainer
  owns it)
- Bundle (`.msixbundle`) support
- `AppxMetadata/CodeIntegrity.cat` (the `AXCI` digest is already handled on read)

## Explicitly not planned as core

- Full UWP/WinRT application framework
- Shipping a Windows SDK sysroot inside this repo
