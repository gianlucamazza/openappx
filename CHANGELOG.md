# Changelog

Notable changes per release. Dates are the day the work landed.

## 0.6.0 — 2026-08-01

First release published to PyPI.

### Added

- `inspect` rejects an `Application/@Executable` that is not linked for the app
  container. MSBuild sets `IMAGE_DLLCHARACTERISTICS_APPCONTAINER` from
  `<AppContainerApplication>`; cross-compiling you have to ask the linker for
  it, and forgetting is silent — the binary still runs on a desktop. The flag is
  readable from the PE stored in the archive, so this is a local check. It
  reports only the confident no: an `Executable` that is not a parseable PE is
  left alone.
- `validate` reports a managed `EntryPoint="ns.Class"` with no `ns.winmd` in the
  layout. The activation lookup needs that file; without it the package
  installs and then refuses to start, which reads like an application bug.
- `validate` reports build artefacts (`*.obj`, `*.pch`, `*.pdb`, …) in a layout.
  Everything in the directory gets packed, and a stray precompiled header is
  around 190 MB.

### Fixed

- The manifest greps no longer match the manifest's own comments. These files
  document themselves, and the attributes worth explaining are exactly the ones
  being searched for, so a comment mentioning `Executable=` was read as markup.

### Established

- `0x8d160120` on app launch is a property of this console, not of any packer. A
  UWP application compiled from scratch on Linux — different toolchain,
  different manifest, two pages of code — installs and fails to launch with the
  same code that the repackaged and the original Windows-built xllama give.

## 0.5.0 — 2026-08-01

### Added

- `openappx sign --timestamp` — RFC 3161 countersignature, so a signature
  outlives its certificate. The token covers the RSA signature (Authenticode's
  arrangement) and `openssl ts -verify` accepts it against exactly those bytes;
  a timestamped package still installs. Unlike the rest of the format work this
  was not copied from a reference package — neither available Microsoft package
  is timestamped — so what remains unproven is that Windows honours it after
  expiry.
- `inspect` now reports the signer: subject, self-signed or issued, expiry, and
  whether a timestamp is present. It checks publisher agreement and validity
  dates, never chain of trust.

- `openappx unpack` — extract a layout a packer can consume again, the missing
  half of repackaging. Round-trips a real 19 MB package to byte-identical
  output. Archive member names are validated, so a crafted package cannot write
  outside the destination.
- `openappx deploy --start/--stop` — launch and stop apps through
  `/api/taskmanager/app`.
- [docs/format.md](docs/format.md) — the container and blockmap rules in one
  place, each with the measurement that established it.
- `CONTRIBUTING.md`, `SECURITY.md`, Dependabot, `.editorconfig`.

### Fixed

- **Non-ASCII entry names were corrupted.** Names were written as UTF-8 without
  flag bit 11, so every reader decoded them as CP437: `città-日本.png` became
  `citt├á-µùÑµ£¼.png`.
- **Files above 4 GiB now fail with an explanation.** Describing one needs ZIP64
  extra fields on the record, and a package carrying those is refused by a
  device with `0x8007000B` — the same code a ZIP32 archive gets, measured
  against a package that installs without them. Appx wants the ZIP64
  end-of-central-directory and nothing on the entries.
- Nine type errors, mypy never having been run: a dataclass holding the
  certificate and private key as bare `object`, and a check that summed values
  it had just established could be `None`.
- An empty `--uninstall` value fell through to the install branch and crashed.

### Testing and CI

- The two command-line entry points had no tests at all; they now have 26.
  Coverage 90% → 95%, tests 106 → 170.
- CI installs `[dev,sign]` — without it every signature test skipped itself —
  and now runs ruff, mypy and a coverage gate.
- `actions/checkout` v4 → v5, `setup-python` v5 → v6, Python matrix gains 3.14.
- The makemsix backend, previously the only code nobody had ever run, is covered
  by a stub binary.

### Known limits

- A repackaged application has been proven to **install**, not to **run**:
  launching it fails on the console, but so does the original Windows-built
  package, so the two are at parity and neither has been seen to start.
- No timestamping, so signatures expire with the certificate.
- No `.msixbundle`, and `CodeIntegrity.cat` is read but not generated.
- `pack` holds the archive in memory; fine at 47 MB, not at 2 GB.

## 0.4.0 — 2026-08-01

The whole chain now works from Linux, with no Windows tooling: **pack → sign →
deploy**. A real 47 MB UWP application, repackaged and signed by this project,
installs on an Xbox One dev kit.

### Added

- `openappx sign` — creates `AppxSignature.p7x`. The CMS/PKCS#7 structure was
  copied from a decoded Microsoft signature; the DER encoder is ours
  (`sign/asn1.py`). `cryptography` sits behind the optional `[sign]` extra for
  RSA and PKCS#12; packing, inspecting and verifying stay stdlib-only.
- `openappx sign --make-test-cert` — mint a self-signed certificate whose subject
  matches `Identity/@Publisher`.
- `openappx deploy` — Windows Device Portal client (install, list, uninstall,
  `--install-cert`). The same REST API serves Xbox, HoloLens, IoT and desktop.
- `openappx inspect` — contents, blockmap summary and signature verification for
  any `.msix`, not only ours (`--json` for machine output).
- `openappx.sign.digest` — parse the `APPX` digest blob and recompute
  `AXPC`/`AXCD`/`AXCT`/`AXBM`/`AXCI` from an archive.
- `examples/resource-only/` — a layout that genuinely installs on a device.
- Golden tests against Microsoft's own signed packages, fetched on demand
  (`OPENAPPX_NO_NETWORK=1` to skip).

### Fixed — format conformance

Comparing our output with a Microsoft-signed package, and then with what a
console accepts, exposed four ways the packer was wrong:

- **Appx archives must be ZIP64.** Not a size question: a ZIP32 package of any
  size fails to open with `0x8007000B`.
- **`Block/@Size` is the _compressed_ length** of each 64 KiB block, and is
  omitted entirely for stored parts. Emitting it required deflating block by
  block (`Z_FULL_FLUSH`), which `zipfile.writestr` cannot express — so the
  archive is now written by hand.
- **An empty file has zero `<Block>` elements**, not one hashing `b""`.
- `inspect` wrongly expected `AppxMetadata/CodeIntegrity.cat` in the blockmap;
  the signature covers it through `AXCI`.

### Fixed — false documentation

- `makemsix` cannot sign. `makemsix pack` accepts only `-d`/`-p`, and upstream
  ships a signature _validator_, not a creator. The documented
  `--cert`/`--cert-password` flow never worked and now fails with an explanation.
- The README quickstart did not run: the package lives under `src/`.

### Added — local checks for opaque device errors

Each of these was first seen as a hex code from a console:

- `Windows.FullTrustApplication` without the `runFullTrust` capability
  (`0x80080204`, reported with only a line number).
- A certificate subject differing from `Identity/@Publisher` — refused before
  signing instead of failing on the device.
- Malformed manifest XML (`0xC00CEE23`). `--` inside a comment is invalid XML and
  easy to introduce while documenting a manifest.
- Real per-attribute checks for `Identity` `Name`/`Publisher`/`Version`,
  replacing a check whose outer condition made it unreachable.

## 0.1.0

Initial skeleton: blockmap generation, pure-Python pack, layout validation,
minimal example, optional makemsix backend hook.
