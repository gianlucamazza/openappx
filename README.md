# openappx

**Build, sign, bundle and install Windows app packages — from Linux, without Windows tooling.**

`openappx` replaces the `makeappx` and `signtool` half of a Windows app pipeline:
it turns a layout directory into a signed `.msix` or `.msixbundle`, checks it,
and installs it on a real device over the Windows Device Portal. Pure Python,
standard library only — signing is the one optional extra.

> **Status: beta.** The whole chain works and is verified on hardware:
> **pack → sign → deploy, from Linux, with no Windows tooling**. A real 47 MB
> UWP application, repackaged and signed by this project, installs on an Xbox
> One dev kit. Compiling PE/UWP binaries stays **out of scope** (see
> [Non-goals](#non-goals)) — [uwp-crossbuild](https://github.com/gianlucamazza/uwp-crossbuild)
> is the companion project that does that part.

```bash
pip install openappx           # signing needs the extra: openappx[sign]
```

---

## What this is

| You have                                                           | openappx gives you                                                                     |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| A **layout directory** (manifest, assets, binaries, payload files) | A valid **`.msix` / Appx-style ZIP** with `AppxBlockMap.xml` and `[Content_Types].xml` |
| A code-signing certificate (or none — one can be minted)           | A **signed** `.msix` that a real device installs                                       |
| A signed `.msix` from anyone                                       | Verification that the package matches the digests its signature covers                 |
| Packages for several architectures                                 | An `.msixbundle` carrying them all                                                     |
| A device in developer mode                                         | Installation over the Windows Device Portal, and the error if it is refused            |
| CI on Linux                                                        | Deterministic pack tests without Windows                                               |

It is **not** a replacement for MSBuild and the Windows SDK: it does not compile
anything. It replaces the packaging half — `makeappx`, `signtool`, and the
sideload step — of a Windows app pipeline.

---

## Goals

- Pack an Appx/MSIX layout on Linux, macOS, or any host with Python 3.10+
- Generate a conformant `AppxBlockMap` (64 KiB SHA-256 blocks, compressed block
  sizes) — checked against Microsoft-signed reference packages, not guessed
- Sign packages without Windows, and prove it by installing them on a device
- Validate common layout mistakes before pack (missing `AppxManifest.xml`, missing `Executable`, missing logos)
- Stay **dependency-light** (default path: Python standard library only)
- Produce **byte-reproducible** packages (fixed timestamps; same layout → same `.msix`)
- Remain **product-agnostic**: any app that ships as Appx/MSIX layout can use it

## Non-goals

| Non-goal                                   | Why                                                                                                         |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| Compiling Win32/UWP C++/C# into PE         | A separate problem, with a separate tool: [uwp-crossbuild](https://github.com/gianlucamazza/uwp-crossbuild) |
| Emulating Windows or ReactOS as a build OS | Different problem domain                                                                                    |
| Guaranteeing Store certification           | Store has additional policies beyond package shape                                                          |
| Replacing a device lab                     | `deploy` drives one device over Device Portal; orchestration is yours                                       |

---

## Architecture (host tools)

```
┌─────────────────────────────────────────────────────────────┐
│  Your app build (elsewhere)                                 │
│  produces: PE/DLLs + assets + AppxManifest.xml              │
└────────────────────────────┬────────────────────────────────┘
                             │ layout directory
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  openappx                                                   │
│  validate → blockmap → content types → zip (.msix)          │
│  [optional] sign → AppxSignature.p7x → deploy to a device   │
└────────────────────────────┬────────────────────────────────┘
                             │ .msix
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  Install / sideload / store upload (your process)           │
└─────────────────────────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the layers and extension
points, and [docs/format.md](docs/format.md) for the container and blockmap rules
— each recorded with the measurement that established it, since several are not
what the specification suggests.

---

## Quickstart

```bash
# From repo root (no install required)
./scripts/pack.sh --root examples/minimal-layout --out /tmp/example.msix

unzip -l /tmp/example.msix | head
```

`scripts/pack.sh` is a thin wrapper that puts `src/` on `PYTHONPATH`. The equivalent
without the wrapper:

```bash
PYTHONPATH=src python3 -m openappx.pack --root examples/minimal-layout --out /tmp/example.msix
```

With an editable install:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
openappx pack --root examples/minimal-layout --out /tmp/example.msix
pytest -q
```

### Layout contract

A pack root must contain at least:

```
AppxManifest.xml
…payload files referenced by the manifest (exe, logos, etc.)
```

openappx **writes** (do not pre-seed):

- `[Content_Types].xml`
- `AppxBlockMap.xml`
- `AppxSignature.p7x` — written by `openappx sign`, never by `pack`

---

## CLI

```text
openappx pack --root DIR --out FILE.msix [options]

  --backend python|makemsix   default: python (unsigned)
  --makemsix PATH             makemsix binary (default: tools/bin/makemsix)
  --allow-missing             pack even if validation reports gaps
```

```text
openappx sign --package FILE.msix --pfx CERT.pfx
openappx sign --make-test-cert "CN=Publisher" --cert-out mycert
openappx validate --root DIR      # check a layout before packing
openappx unpack --package FILE.msix --out DIR
openappx inspect --package FILE.msix [--json]
openappx deploy --device URL --user NAME --package FILE.msix [--insecure]
openappx bundle --package A.msix --package B.msix --out X.msixbundle
```

A bundle carries one application across architectures, plus any resource
packages. **Sign the packages first, then the bundle** — signing only the
container is rejected as if the container were unsigned:

```bash
openappx sign --package app-x64.msix --pfx cert.pfx
openappx sign --package app-x86.msix --pfx cert.pfx
openappx bundle --package app-x64.msix --package app-x86.msix --out app.msixbundle
openappx sign --package app.msixbundle --pfx cert.pfx
```

`inspect` is the read side of `pack`: it re-derives every block hash from the bytes
stored in the archive and compares them with `AppxBlockMap.xml`, checks `LfhSize`
against the ZIP local headers actually written, and verifies that `[Content_Types].xml`
covers every part. On a signed package it also recomputes the digests the signature
covers and reports any mismatch — see [docs/signing.md](docs/signing.md). It works on
packages produced by any tool, not just openappx.

```text
Package: /tmp/example.msix (3139 bytes)
Identity: Name=OpenAppx.Example  Publisher=CN=OpenAppx-Example  Version=0.1.0.0  ProcessorArchitecture=x64
Signature: absent

Part                        Size      Stored   Method  Blocks
app.exe                       31          31    store       1
AppxManifest.xml            1659         737  deflate       1
Assets/StoreLogo.png          67          66  deflate       1
[Content_Types].xml         1061        1061    store       -
AppxBlockMap.xml             610         610    store       -

OK: blockmap and content types are consistent with the archive
```

### Deploying to a device

`deploy` talks to the [Windows Device Portal](https://learn.microsoft.com/en-us/windows/uwp/debug-test-perf/device-portal),
the same REST service on Xbox, HoloLens, IoT and Windows desktop — so a real
device tells you whether a package is actually installable:

```bash
export OPENAPPX_DEVICE_PASSWORD='…'        # keeps it out of `ps`
openappx deploy --device https://192.168.1.50:11443 --user devuser \
  --package example.msix --insecure
```

- The device must be in **Developer Mode** with Device Portal enabled
  (on Xbox: Dev Home → Home → Remote Access → Remote Access Settings).
- `--insecure` is required because devices serve a self-signed certificate.
- CSRF is handled by the cookie-to-header handshake the Device Portal UI uses
  (`CSRF-Token` cookie → `X-CSRF-Token` header). `--csrf-bypass` switches to
  Microsoft's `auto-<username>` escape hatch instead; that account must then
  never be used in the web UI.
- `--list` shows installed packages, `--uninstall PACKAGE_FULL_NAME` removes one,
  `--install-cert CERT.cer` trusts a certificate on the device.

**Sideloading requires a signed package** and a certificate the device trusts.
The full loop, entirely from Linux:

```bash
openappx sign --make-test-cert "CN=OpenAppx-Example" --cert-out mycert
openappx deploy --device https://<ip>:11443 --user NAME --install-cert mycert.cer
openappx pack --root examples/resource-only --out app.msix
openappx sign --package app.msix --pfx mycert.pfx --timestamp
openappx deploy --device https://<ip>:11443 --user NAME --package app.msix
```

`examples/resource-only/` is the layout this loop was verified with: it installs
on an Xbox One dev kit. `examples/minimal-layout/` shows a desktop full-trust
manifest instead, and deliberately ships a placeholder executable, so it packs
and signs but stops at the deployment stage.

Signing needs `pip install 'openappx[sign]'`; everything else is stdlib-only.
[docs/signing.md](docs/signing.md) has the format details and the console
responses that verify each step.

Exit codes: `0` success, `1` failure (pack error, a failed deploy, or problems
found by `validate` / `inspect`), `2` bad usage or an unreadable input.

Without an editable install, replace `openappx pack` with
`PYTHONPATH=src python3 -m openappx.pack` (same for `validate` and `inspect`).

---

## Optional: makemsix backend

Microsoft’s open-source MSIX SDK can pack on Linux when built with pack support:

```bash
./scripts/bootstrap-makemsix.sh   # may fail on bleeding-edge toolchains
openappx pack --backend makemsix --root … --out …
```

It produces **unsigned** packages, exactly like the Python backend: `makemsix pack`
takes only `-d`/`-p`, and upstream implements signature _validation_, not creation.
See [docs/signing.md](docs/signing.md). The pure-Python backend remains the default
and is the one covered by the test suite.

---

## Project layout

```
openappx/
├── src/openappx/
│   ├── cli.py         # the `openappx` entry point; dispatches lazily
│   ├── blockmap.py    # block hashing, XML rendering, ZIP header parsing
│   ├── pack_core.py   # the ZIP writer and the two pack backends
│   ├── pack.py        # pack CLI
│   ├── bundle.py      # .msixbundle assembly
│   ├── validate.py    # pre-pack layout checks
│   ├── inspect.py     # post-pack package and bundle checks
│   ├── unpack.py      # extract a layout back out of a package
│   ├── deploy.py      # Windows Device Portal client
│   └── sign/          # digests, DER encoder, signature creation
├── docs/
│   ├── architecture.md   # the layers and where to extend them
│   ├── format.md         # container and blockmap rules, with their evidence
│   ├── signing.md        # what AppxSignature.p7x contains, decoded
│   └── roadmap.md        # done, not done, and why
├── examples/
│   ├── minimal-layout/   # desktop, full-trust; placeholder exe, so it never installs
│   └── resource-only/    # installs on a device — used to prove the chain
├── tests/
└── scripts/
```

---

## Known limits

| Limit             | Detail                                                                                                                                                                                                         |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Files above 4 GiB | Cannot be carried. Describing one needs ZIP64 extra fields on the record, and a device refuses a package with those (`0x8007000B`) — see [docs/format.md](docs/format.md). `pack` fails with that explanation. |
| Memory            | `pack` builds the archive in memory: fine for tens of MB, not for GB.                                                                                                                                          |
| Running an app    | Packages are proven to **install**. None has been seen to run: the test console refuses to launch every sideloaded package, Microsoft Edge included, so it cannot answer the question either way.              |
| Timestamping      | `--timestamp` implemented; that Windows honours it past certificate expiry is untestable here.                                                                                                                 |
| Bundles           | A bundle mixing an application and a language pack registers only if both `resources.pri` merge; ours do not yet (`0x80070002`).                                                                               |
| CodeIntegrity     | `AppxMetadata/CodeIntegrity.cat` is verified when present, never generated. It matters only where Device Guard is enforced.                                                                                    |
| Certificate trust | `inspect` reports the signer and checks publisher agreement and expiry, but never the chain of trust.                                                                                                          |

## Roadmap

Pack, sign, bundle and deploy are done and verified on hardware. What remains is
in [docs/roadmap.md](docs/roadmap.md), with the reason for each: streaming pack,
`CodeIntegrity.cat`, and merged resource bundles.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and the checks CI runs, and
[SECURITY.md](SECURITY.md) for how keys, device credentials and untrusted
archives are handled.

The short version: keep the default pack path dependency-free, and when a format
detail is in doubt, verify it against a real package or a real device rather than
against the specification — that is how every serious bug here was found.

## License

MIT — see [LICENSE](LICENSE).
