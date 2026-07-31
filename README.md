# openappx

**Linux-first, open-source tooling for Appx / MSIX package layout, validation, and packing.**

Build and inspect Windows app packages from a POSIX host without Visual Studio for the *packaging* stage. Written in Python (stdlib-first). Optional integration with the upstream [MSIX SDK](https://github.com/microsoft/msix-packaging) `makemsix` CLI for signing-capable pack.

> **Status:** experimental (v0). Pack + blockmap + layout validation work. Appx code-signing and PE/UWP compilation are **out of scope for v0** (see [Non-goals](#non-goals) and [docs/roadmap.md](docs/roadmap.md)).

---

## What this is

| You have | openappx gives you |
|----------|-------------------|
| A **layout directory** (manifest, assets, binaries, payload files) | A valid **`.msix` / Appx-style ZIP** with `AppxBlockMap.xml` and `[Content_Types].xml` |
| Optional `makemsix` + PFX | Pack *and* sign (when the native backend is available) |
| CI on Linux | Deterministic pack tests without Windows |

It is **not** a full replacement for MSBuild + Windows SDK. It replaces (or complements) the **makeappx / Appx packaging** slice of a Windows app pipeline.

---

## Goals

- Pack an Appx/MSIX layout on Linux, macOS, or any host with Python 3.10+
- Generate standards-oriented `AppxBlockMap` (64 KiB SHA-256 blocks)
- Validate common layout mistakes before pack (missing `AppxManifest.xml`, missing `Executable`, missing logos)
- Stay **dependency-light** (default path: Python standard library only)
- Remain **product-agnostic**: any app that ships as Appx/MSIX layout can use it

## Non-goals

| Non-goal | Why |
|----------|-----|
| Compiling Win32/UWP C++/C# into PE | Requires MSVC/clang-cl + Windows SDK (or equivalent ABI sysroot) |
| Emulating Windows or ReactOS as a build OS | Different problem domain |
| Guaranteeing Store certification | Store has additional policies beyond package shape |
| Replacing Device Portal / full device labs | Deploy helpers may appear later as optional modules |

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
│  [optional] makemsix backend → signed package               │
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
python3 -m openappx.pack \
  --root examples/minimal-layout \
  --out /tmp/example.msix \
  --allow-missing

unzip -l /tmp/example.msix | head
```

With an editable install:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
openappx pack --root examples/minimal-layout --out /tmp/example.msix --allow-missing
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
- `AppxSignature.p7x` only when using a signing backend

---

## CLI

```text
python3 -m openappx.pack --root DIR --out FILE.msix [options]

  --backend python|makemsix   default: python (unsigned)
  --makemsix PATH             makemsix binary (default: tools/bin/makemsix)
  --cert PATH --cert-password  for makemsix signing
  --allow-missing             pack even if validation reports gaps
```

```text
python3 -m openappx.validate --root DIR
```

---

## Optional: makemsix backend

Microsoft’s open-source MSIX SDK can pack (and sign with a PFX) on Linux when built with pack support:

```bash
./scripts/bootstrap-makemsix.sh   # may fail on bleeding-edge toolchains
python3 -m openappx.pack --backend makemsix --root … --out … \
  --cert signing.pfx --cert-password '…'
```

The pure-Python backend remains the default and is fully tested in CI-style unit tests.

---

## Project layout

```
openappx/
├── README.md
├── LICENSE
├── pyproject.toml
├── docs/
│   ├── architecture.md
│   └── roadmap.md
├── src/openappx/
│   ├── blockmap.py
│   ├── pack.py
│   ├── validate.py
│   └── sign/          # API stubs (roadmap)
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
