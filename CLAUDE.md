# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`openappx` — Linux-first, stdlib-only tooling to validate and pack an Appx/MSIX **layout directory** into a `.msix` (OPC ZIP + `AppxBlockMap.xml` + `[Content_Types].xml`). It replaces the `makeappx` slice of a Windows pipeline; it packs, signs and deploys without Windows tooling; it does **not** compile PE binaries. See `docs/roadmap.md` for what is committed vs. research.

## Commands

The package lives under `src/`, so `python3 -m openappx.pack` only works with `PYTHONPATH=src` (or an editable install). `scripts/pack.sh` exists precisely to set it.

```bash
pytest -q                                   # pythonpath=["src"] comes from pyproject.toml
pytest tests/test_pack.py::test_pack_example -q   # single test
./scripts/pack.sh --root examples/minimal-layout --out /tmp/x.msix
PYTHONPATH=src python3 -m openappx.validate --root examples/minimal-layout
PYTHONPATH=src python3 -m openappx.inspect --package /tmp/x.msix   # --json for machine output
OPENAPPX_DEVICE_PASSWORD=… PYTHONPATH=src python3 -m openappx.deploy \
  --device https://<ip>:11443 --user <name> --package /tmp/x.msix --insecure
pip install -e ".[dev]"                     # then the `openappx` console script works
./scripts/bootstrap-makemsix.sh             # optional native backend; often fails on new toolchains
```

Exit codes are part of the contract: `0` ok, `1` pack/runtime failure, `2` usage or layout-validation failure.

`tests/test_pack.py` covers the happy path; `tests/test_format.py` holds the format invariants below; `tests/test_inspect.py` deliberately corrupts packages (via its `rebuild()` helper) and asserts `inspect` catches each one — add a case there whenever you add a check; `tests/test_signature.py` checks the signature reading against Microsoft's own signed packages, downloaded on demand by `tests/conftest.py` into a gitignored cache (`OPENAPPX_NO_NETWORK=1` skips them); `tests/test_deploy.py` runs the Device Portal client against a stub HTTP server, which proves the wire format but never that a real device accepts a package.

Those golden tests are the only thing standing between this project and a plausible-looking misreading of the format. When in doubt about a format detail, get a real signed package and check — do not reason it out. CI (`.github/workflows/ci.yml`) runs the suite on Python 3.10–3.13 plus a smoke pack of `examples/minimal-layout`.

## Architecture

Entry points fan out, logic lives in leaf modules:

- `cli.py` — `openappx <pack|validate|inspect>` dispatcher; imports subcommand modules **lazily** so a broken/optional path never breaks the other commands.
- `pack.py` — argparse CLI only (arg parsing, validation gate, error printing).
- `pack_core.py` — the two backends, `pack_python` and `pack_makemsix`. Keep it argparse-free: tests and any future API consumer import from here, not from `pack.py`.
- `blockmap.py` — all format-level logic: block hashing, path mangling, XML rendering, and `read_local_header()` for reading real ZIP headers back.
- `validate.py` — `layout_problems(root) -> list[str]`, run **before** pack on a possibly-broken layout.
- `inspect.py` — `inspect_package(msix) -> dict`, run **after** pack on a finished archive; recomputes every block hash from stored bytes. Keep the two apart: `validate` must tolerate garbage input, `inspect` must not.
- `deploy.py` — Windows Device Portal REST client. Details that were established against a working client (`../xllama/scripts/deploy.sh`), not guessed: every uploaded part goes under the form field name **`file`** (the file's own name goes in the `package=` query parameter); CSRF uses the cookie-to-header handshake (`CSRF-Token` cookie → `X-CSRF-Token`), with `auto-<username>` as an opt-in alternative; `GET /state` returns **204 while installing**, 404 when nothing was deployed, 200 with the result; `Success: false` in that result means failure even when `Code` is 0. `--insecure` is required because devices serve self-signed certificates. Installing touches someone's hardware: never pick a target device implicitly, and never uninstall as a side effect of installing.
- `sign/` — `digest.py` (parse/recompute the digests a signature covers), `asn1.py` (a small DER encoder), `signer.py` (build the CMS structure and attach it), `cli.py`. Signing needs the optional `[sign]` extra; everything else stays stdlib-only. **Read `docs/signing.md` before touching anything signature-shaped** — every structure there was copied from a real Microsoft signature and confirmed by a console accepting or rejecting a package, not derived from the spec.

Both checkers return a list of human-readable problem strings rather than raising; an empty list means "coherent". New checks append to that list — that is the extension point in each.

### Format invariants (easy to break, hard to notice)

- **Two path spellings for the same file.** `package_path()` produces backslash names (`Assets\StoreLogo.png`) used in `AppxBlockMap.xml` and in `SKIP_NAMES`; `_zip_name()` converts back to forward slashes for the actual ZIP entry. Any new code touching names must pick the right one.
- **XML is rendered as byte strings, not ElementTree** — CRLF line endings, UTF-8, fixed attribute order. Blockmap/content-types bytes are compared against reference tooling, so don't "clean this up" with a serializer.
- **`LfhSize` is computed, not measured**: `30 + len(utf8_name)`, valid only because the writer emits no extra fields. `tests/test_format.py::test_lfh_size_matches_written_headers` parses the real headers back to keep that honest.
- `[Content_Types].xml` and `AppxBlockMap.xml` are always STORED, so a reader can reach them without inflating.
- **Output is byte-reproducible**: timestamps are hard-coded to the 1980 DOS epoch. Never stamp wall-clock time into an entry.
- **Block hashes cover uncompressed data; `Block/@Size` is the *compressed* length** of that 64 KiB block, omitted entirely for stored parts, and an empty file has zero blocks. All three were established against a Microsoft-signed package, not inferred — `tests/test_signature.py` re-checks them on every run.
- **Appx archives must be ZIP64** — `vMade=45` on every central directory entry, ZIP64 EOCD + locator, and `0xFFFF`/`0xFFFFFFFF` sentinels in the classic EOCD. This is not about size: a ZIP32 package fails to open on a device with `0x8007000B`, whatever it contains.
- **The archive is written by hand** (`pack_core.py`: `_write_entry`, `_write_central_directory`). This is not gratuitous: reporting per-block compressed sizes means feeding a pre-built deflate stream (`blockmap.deflate_blocks`, `Z_FULL_FLUSH` per block) into each entry, which `zipfile.writestr` cannot express. Writing it ourselves also pins `LfhSize` (no extra fields) and the 1980 timestamps that make output reproducible.
- Payload is deflated only when compression actually shrinks it; otherwise it is stored, and then `Block/@Size` must be absent.
- **Generated parts are never read as payload**: `SKIP_NAMES` in `blockmap.py` guards against a re-pack picking up a previous run's output.
- Files are sorted case-insensitively by package path before hashing, so pack output is deterministic.

### Validation is regex over the manifest text

`validate.py` deliberately greps `AppxManifest.xml` (`Executable=`, `*Logo=`, `Image=`) instead of parsing XML — it must stay tolerant of partially broken manifests, since its job is to report them. New checks append human-readable strings to `problems`; an empty list means "ok to pack". `--allow-missing` downgrades every problem to a warning.

## Constraints

- **Zero runtime dependencies.** The default pack path must remain Python-stdlib only; `dev` extras are pytest only. Anything native goes behind the optional `makemsix` backend.
- **Product-agnostic**: no branding, real app names, or sample IP in `examples/` — `minimal-layout` is a synthetic fixture the tests assert against.
- Never commit `.pfx`/`.p12` material; public `.cer` is fine (see the trust model in `docs/architecture.md`).
