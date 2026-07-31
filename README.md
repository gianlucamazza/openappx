# openappx

**Linux-first, open-source tooling for Appx / MSIX package layout, validation, and packing.**

Build and inspect Windows app packages from a POSIX host without Visual Studio for the _packaging_ stage. Written in Python (stdlib-first). Optional integration with the upstream [MSIX SDK](https://github.com/microsoft/msix-packaging) `makemsix` CLI as an alternative pack backend.

> **Status:** experimental (v0), but the whole chain works: **pack → sign →
> deploy, from Linux, with no Windows tooling**. A real 47 MB UWP application,
> repackaged and signed by this project, installs on an Xbox One dev kit. Compiling PE/UWP binaries stays
> **out of scope** (see [Non-goals](#non-goals), [docs/signing.md](docs/signing.md)).

---

## What this is

| You have                                                           | openappx gives you                                                                     |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| A **layout directory** (manifest, assets, binaries, payload files) | A valid **`.msix` / Appx-style ZIP** with `AppxBlockMap.xml` and `[Content_Types].xml` |
| A code-signing certificate (or none — one can be minted)           | A **signed** `.msix` that a real device installs                                       |
| A signed `.msix` from anyone                                       | Verification that the package matches the digests its signature covers                 |
| CI on Linux                                                        | Deterministic pack tests without Windows                                               |

It is **not** a full replacement for MSBuild + Windows SDK. It replaces (or complements) the **makeappx / Appx packaging** slice of a Windows app pipeline.

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

| Non-goal                                   | Why                                                              |
| ------------------------------------------ | ---------------------------------------------------------------- |
| Compiling Win32/UWP C++/C# into PE         | Requires MSVC/clang-cl + Windows SDK (or equivalent ABI sysroot) |
| Emulating Windows or ReactOS as a build OS | Different problem domain                                         |
| Guaranteeing Store certification           | Store has additional policies beyond package shape               |
| Replacing Device Portal / full device labs | Deploy helpers may appear later as optional modules              |

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

See [docs/architecture.md](docs/architecture.md) for layers and extension points (sign, deploy, future cross-ABI).

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
openappx inspect --package FILE.msix [--json]
openappx deploy --device URL --user NAME --package FILE.msix [--insecure]
```

`inspect` is the read side of `pack`: it re-derives every block hash from the bytes
stored in the archive and compares them with `AppxBlockMap.xml`, checks `LfhSize`
against the ZIP local headers actually written, and verifies that `[Content_Types].xml`
covers every part. On a signed package it also recomputes the digests the signature
covers and reports any mismatch — see [docs/signing.md](docs/signing.md). It works on
packages produced by any tool, not just openappx.

```text
Package: /tmp/example.msix (2916 bytes)
Identity: Name=OpenAppx.Example  Publisher=CN=OpenAppx-Example  Version=0.1.0.0
Signature: absent

Part                        Size      Stored   Method  Blocks
app.exe                       31          31    store       1
AppxManifest.xml            1265         590  deflate       1
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
openappx pack --root layout --out app.msix
openappx sign --package app.msix --pfx mycert.pfx
openappx deploy --device https://<ip>:11443 --user NAME --package app.msix
```

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
takes only `-d`/`-p`, and upstream implements signature *validation*, not creation.
See [docs/signing.md](docs/signing.md). The pure-Python backend remains the default
and is the one covered by the test suite.

---

## Project layout

```
openappx/
├── README.md
├── LICENSE
├── pyproject.toml
├── docs/
│   ├── architecture.md
│   ├── signing.md
│   └── roadmap.md
├── src/openappx/
│   ├── blockmap.py    # block hashing, XML rendering, ZIP header parsing
│   ├── pack_core.py   # pack backends (python, makemsix)
│   ├── pack.py        # pack CLI
│   ├── validate.py    # pre-pack layout checks
│   ├── inspect.py     # post-pack package checks
│   ├── deploy.py      # Windows Device Portal client (install/list/uninstall)
│   ├── sign/          # digests, DER encoder, signature creation
├── tests/
├── scripts/
└── examples/minimal-layout/
```

---

## Roadmap

High level: solid pack → sign → optional device deploy helpers → research notes on cross-ABI (not a commitment). Details: [docs/roadmap.md](docs/roadmap.md).

---

## Contributing

- Python 3.10+
- `pytest` for tests; keep the default pack path free of native deps
- No product-specific branding or sample IP in `examples/`

## License

MIT — see [LICENSE](LICENSE).
