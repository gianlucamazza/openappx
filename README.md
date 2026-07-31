# openappx

**Linux-first, open-source tooling for Appx / MSIX package layout, validation, and packing.**

Build and inspect Windows app packages from a POSIX host without Visual Studio for the _packaging_ stage. Written in Python (stdlib-first). Optional integration with the upstream [MSIX SDK](https://github.com/microsoft/msix-packaging) `makemsix` CLI as an alternative pack backend.

> **Status:** experimental (v0). Pack + blockmap + layout validation + package inspection work. Appx code-signing and PE/UWP compilation are **out of scope for v0** (see [Non-goals](#non-goals) and [docs/roadmap.md](docs/roadmap.md)).

---

## What this is

| You have                                                           | openappx gives you                                                                     |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------- |
| A **layout directory** (manifest, assets, binaries, payload files) | A valid **`.msix` / Appx-style ZIP** with `AppxBlockMap.xml` and `[Content_Types].xml` |
| A signed `.msix` from anyone                                       | Verification that the package matches the digests its signature covers                 |
| CI on Linux                                                        | Deterministic pack tests without Windows                                               |

It is **not** a full replacement for MSBuild + Windows SDK. It replaces (or complements) the **makeappx / Appx packaging** slice of a Windows app pipeline.

---

## Goals

- Pack an Appx/MSIX layout on Linux, macOS, or any host with Python 3.10+
- Generate standards-oriented `AppxBlockMap` (64 KiB SHA-256 blocks)
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
│  [optional] makemsix backend (also unsigned — see signing.md)│
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
- `AppxSignature.p7x` is **never** written: no backend can sign ([docs/signing.md](docs/signing.md))

---

## CLI

```text
openappx pack --root DIR --out FILE.msix [options]

  --backend python|makemsix   default: python (unsigned)
  --makemsix PATH             makemsix binary (default: tools/bin/makemsix)
  --allow-missing             pack even if validation reports gaps
```

```text
openappx validate --root DIR      # check a layout before packing
openappx inspect --package FILE.msix [--json]
```

`inspect` is the read side of `pack`: it re-derives every block hash from the bytes
stored in the archive and compares them with `AppxBlockMap.xml`, checks `LfhSize`
against the ZIP local headers actually written, and verifies that `[Content_Types].xml`
covers every part. On a signed package it also recomputes the digests the signature
covers and reports any mismatch — see [docs/signing.md](docs/signing.md). It works on
packages produced by any tool, not just openappx.

```text
Package: /tmp/example.msix (2915 bytes)
Identity: Name=OpenAppx.Example  Publisher=CN=OpenAppx-Example  Version=0.1.0.0
Signature: absent

Part                        Size      Stored   Method  Blocks
app.exe                       31          33  deflate       1
AppxManifest.xml            1265         583  deflate       1
Assets/StoreLogo.png          67          59  deflate       1
[Content_Types].xml         1061        1061    store       -
AppxBlockMap.xml             621         621    store       -

OK: blockmap and content types are consistent with the archive
```

Exit codes: `0` success, `1` failure (pack error, or problems found by
`validate` / `inspect`), `2` bad usage or an unreadable input.

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
│   └── sign/          # signature digests: parse + verify (no signing)
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
