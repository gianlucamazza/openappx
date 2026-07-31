# Changelog

Notable changes per release. Dates are the day the work landed.

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
