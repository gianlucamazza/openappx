# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`openappx` — Linux-first, stdlib-only tooling to validate and pack an Appx/MSIX **layout directory** into a `.msix` (OPC ZIP + `AppxBlockMap.xml` + `[Content_Types].xml`). It replaces the `makeappx` slice of a Windows pipeline; it does **not** compile PE binaries or sign packages natively (v0). See `docs/roadmap.md` for what is committed vs. research.

## Commands

The package lives under `src/`, so `python3 -m openappx.pack` only works with `PYTHONPATH=src` (or an editable install). `scripts/pack.sh` exists precisely to set it.

```bash
pytest -q                                   # pythonpath=["src"] comes from pyproject.toml
pytest tests/test_pack.py::test_pack_example -q   # single test
./scripts/pack.sh --root examples/minimal-layout --out /tmp/x.msix
PYTHONPATH=src python3 -m openappx.validate --root examples/minimal-layout
pip install -e ".[dev]"                     # then the `openappx` console script works
./scripts/bootstrap-makemsix.sh             # optional native backend; often fails on new toolchains
```

Exit codes are part of the contract: `0` ok, `1` pack/runtime failure, `2` usage or layout-validation failure.

## Architecture

Entry points fan out, logic lives in leaf modules:

- `cli.py` — `openappx <pack|validate>` dispatcher; imports subcommand modules **lazily** so a broken/optional path never breaks the other command.
- `pack.py` — argparse CLI only (arg parsing, validation gate, error printing).
- `pack_core.py` — the two backends, `pack_python` and `pack_makemsix`. Keep it argparse-free: tests and any future API consumer import from here, not from `pack.py`.
- `blockmap.py` — all format-level logic (block hashing, path mangling, XML rendering).
- `validate.py` — `layout_problems(root) -> list[str]`; the extension point for new checks.
- `sign/` — API stub only.

### Format invariants (easy to break, hard to notice)

- **Two path spellings for the same file.** `package_path()` produces backslash names (`Assets\StoreLogo.png`) used in `AppxBlockMap.xml` and in `SKIP_NAMES`; `_zip_name()` converts back to forward slashes for the actual ZIP entry. Any new code touching names must pick the right one.
- **XML is rendered as byte strings, not ElementTree** — CRLF line endings, UTF-8, fixed attribute order. Blockmap/content-types bytes are compared against reference tooling, so don't "clean this up" with a serializer.
- **Compression differs by part**: payload files are DEFLATE (level 6), `[Content_Types].xml` and `AppxBlockMap.xml` are STORED. UTF-8 flag bit `0x800` is set explicitly on every entry.
- **`LfhSize` is computed, not measured**: `30 + len(utf8_name) + len(extra)` with `extra=b""`. If `zipfile` ever emits extra fields, the blockmap silently disagrees with the archive — this is the open parity item in the v0.2 roadmap.
- **Empty files still get one block** (SHA-256 of `b""`, size 0) — required by the format.
- **Generated parts are never read as payload**: `SKIP_NAMES` in `blockmap.py` guards against a re-pack picking up a previous run's output.
- Files are sorted case-insensitively by package path before hashing, so pack output is deterministic.

### Validation is regex over the manifest text

`validate.py` deliberately greps `AppxManifest.xml` (`Executable=`, `*Logo=`, `Image=`) instead of parsing XML — it must stay tolerant of partially broken manifests, since its job is to report them. New checks append human-readable strings to `problems`; an empty list means "ok to pack". `--allow-missing` downgrades every problem to a warning.

## Constraints

- **Zero runtime dependencies.** The default pack path must remain Python-stdlib only; `dev` extras are pytest only. Anything native goes behind the optional `makemsix` backend.
- **Product-agnostic**: no branding, real app names, or sample IP in `examples/` — `minimal-layout` is a synthetic fixture the tests assert against.
- Never commit `.pfx`/`.p12` material; public `.cer` is fine (see the trust model in `docs/architecture.md`).
