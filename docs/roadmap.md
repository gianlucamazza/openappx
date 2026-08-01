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
- [x] CI (GitHub Actions, Linux, Python 3.10–3.14)

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
- [x] Timestamping (RFC 3161 countersignature) — `openappx sign --timestamp`.
      Verified as far as possible: `openssl ts -verify` accepts the token against
      the RSA signature it covers, and a timestamped package still installs. Not
      verifiable: that Windows honours it once the certificate has expired.
- [x] Certificate inspection — subject, issuer, validity dates, publisher
      agreement. Chain of trust remains out of scope: that is the device's
      policy, not ours.

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
- [x] **Repackaged a real application** — 47.7 MB of binaries, taken from a
      shipped release built on Windows — and installed it on the console. Pack 3.9 s,
      sign 0.6 s, deploy 5.3 s. Doing so also found that `inspect` wrongly
      expected `CodeIntegrity.cat` in the blockmap.
- [x] `--start` / `--stop` through `/api/taskmanager/app`
- [x] Install phases reported while waiting, so a slow install is
      distinguishable from a hang

### Repackaging

- [x] `openappx unpack` — extract a layout a packer can consume again. Verified
      by round-tripping a real 19 MB package to byte-identical output.
- [x] **`0x8d160120` on launch is the console's, not ours — settled.**
      `/api/taskmanager/app` returns it for every sideloaded package on this
      device, including **Microsoft Edge**, which Microsoft signed and shipped.
      Four packages with nothing in common but the hardware fail identically:
      a shipped application built on Windows with MSBuild, that same application
      repackaged here, a UWP app compiled from scratch on Linux, and Edge. Every one installs; none
      launches. `/api/app/packagemanager/packages` also reports `AppListEntry: 0`
      for all four and `1` for everything preinstalled, which is what sideloading
      looks like on this console rather than a defect.

      What this does *not* prove is that a repackaged app runs correctly once
      started — only that failing to start it through Device Portal says nothing
      about the packaging.

### Size limits

- [x] Established that a file above 4 GiB cannot be carried: describing it needs
      ZIP64 extra fields on the record, and a package with those is refused with
      `0x8007000B` — measured, using a package that installs without them.
      `pack` now fails with that explanation instead of emitting one.
- [ ] `pack` holds the whole archive in memory; fine at 47 MB, not at 2 GB.

## v0.6 — Bundles

- [x] `openappx bundle` — combine packages into an `.msixbundle`, reusing the
      ZIP writer and the signer unchanged. Built the same way as everything else
      here: read Microsoft's own bundles rather than the schema.
- [x] `inspect` reads bundles, and reports each of upstream's deliberately-broken
      reference bundles as the fault its filename claims.
- [x] **A bundle built and signed here installs on the console.**
- [x] Five bundle-specific rules established on hardware, none of them in the
      shape they first appeared: a different SIP GUID, payloads that must each be
      signed, resource packages identified by `Identity/@ResourceId`, application
      packages that must _not_ carry a `ResourceId`, and `Offset` pointing at the
      payload data rather than its record. See [format.md](format.md).
- [ ] A bundle mixing an application and a language pack registers only if both
      `resources.pri` files merge. Ours do not yet: `0x80070002` at registration.
      Building a PRI that expects to be merged is a `makepri` question, not a
      packaging one.

## Not done, and why

- **Generating `AppxMetadata/CodeIntegrity.cat`** — we verify it (`AXCI`) but do
  not produce it. It is an Authenticode catalogue, a second format to get right,
  and only matters where Device Guard is enforced.
- **Streaming pack** — the archive is assembled in memory. The writer is the
  most carefully verified code here, so reworking it deserves a session where
  the result can be re-checked on hardware, not the end of one.
- **Proving a repackaged app launches** — blocked externally, and now known to
  be so: Device Portal cannot launch _any_ sideloaded package on this console,
  Microsoft Edge included. It would take a device where that path works.

## Later (research, not committed)

- `AppxMetadata/CodeIntegrity.cat` (the `AXCI` digest is already handled on read)

## Explicitly not planned as core

- Full UWP/WinRT application framework
- Shipping a Windows SDK sysroot inside this repo
