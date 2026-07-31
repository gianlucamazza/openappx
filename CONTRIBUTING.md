# Contributing

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,sign]"
pytest -q
```

`[sign]` matters: without `cryptography`, the signature tests skip themselves
and the least forgiving code in the project goes unexercised.

## Before opening a pull request

```bash
ruff check src tests
mypy
coverage run -m pytest && coverage report   # fails below 90%
```

CI runs exactly these on Python 3.10 through 3.14.

## How this codebase learns things

Nearly every serious defect here was found by comparing against something real —
a Microsoft-signed package, or a device accepting or rejecting an install — not
by reasoning about the specification. Two examples, both of which looked correct
and were not:

- `Block/@Size` is the *compressed* length of a block, not the uncompressed one.
- Appx requires a ZIP64 end-of-central-directory but rejects ZIP64 extra fields
  on the records. `zipfile` and `unzip` accept either.

So: **when a format detail is in doubt, check it against an artefact, and write
the check down as a test.** `tests/test_signature.py` fetches Microsoft's own
signed packages on demand for this purpose (`OPENAPPX_NO_NETWORK=1` skips them).
`docs/signing.md` records which install error corresponds to which mistake.

## Conventions

- The default pack path stays dependency-free. Anything needing a library goes
  behind an optional extra, as signing does.
- `validate` runs before packing and must tolerate broken input; `inspect` runs
  after and must not. Keep them apart.
- No branding, real application names, or third-party binaries in `examples/`.
- Never commit `.pfx`/`.p12` material. Public `.cer` files are fine.
