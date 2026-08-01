# Best practices and sources of truth

This is the canonical maintainer guide for keeping implementation, tests,
documentation and release artefacts aligned. When another document disagrees,
the source listed here wins and the disagreement should be fixed in the same
change.

## Source-of-truth map

| Question | Source of truth |
| --- | --- |
| Published version | `pyproject.toml` and `src/openappx/__init__.py` |
| Release history | `CHANGELOG.md` |
| Supported Python versions | `.github/workflows/ci.yml` and `pyproject.toml` classifiers |
| CLI syntax and exit codes | `src/openappx/*` argparse definitions and CLI tests |
| Package/container invariants | `docs/format.md`, format tests and measured reference packages |
| Signature behavior | `docs/signing.md`, signing tests and device evidence |
| Threat model | `SECURITY.md` |
| Current roadmap | `docs/roadmap.md` |
| PyPI release | `.github/workflows/release.yml` |
| AUR release | `.github/workflows/aur.yml`, `packaging/PKGBUILD` and `packaging/publish-aur.sh` |

## Development loop

1. Inspect the current worktree and preserve unrelated changes.
2. Make the smallest root-cause change that fixes the behavior.
3. Add a regression test for every new invariant or user-visible error.
4. Run `pytest -q`, `ruff check src tests`, `mypy`, and `git diff --check`.
5. Build a wheel and sdist; install the wheel in a clean environment and run
   `openappx --help`, `validate`, `pack`, and `inspect`.
6. Update the owning source-of-truth document, not every copy of the same fact.

## Packaging rules

- Run `validate` before `pack`; use `--allow-missing` only for deliberate
  diagnostic packages.
- Keep generated parts out of layouts. `pack` regenerates blockmap and content
  types, while `sign` appends the signature as the final archive record.
- Treat layout paths as untrusted input: references stay inside the layout and
  symlinks are rejected.
- Use `inspect` after packing or signing. A coherent digest report is not proof
  that the device trusts the certificate or that the application launches.
- Sign payload packages before signing a bundle, and verify the finished bundle.

## Security rules

- Keep PFX passwords and Device Portal passwords in environment variables or
  interactive prompts, never in shell history or process arguments.
- Use `--insecure` only on a trusted network when the Device Portal certificate
  is self-signed; never silently disable TLS verification in code.
- Do not commit private key material. Public `.cer` files are safe only for the
  trust workflow they are intended to support.
- Keep archive extraction path-safe and reject ambiguous duplicate members.
- Keep output writes atomic so failed operations cannot destroy a previous
  package.

## Release rules

- Bump `pyproject.toml` and `src/openappx/__init__.py` together.
- Add the release section to `CHANGELOG.md` before tagging.
- Confirm the tag is exactly `v<version>`; the release workflow rejects drift.
- Let the release workflow build and attest the exact artefacts before AUR
  packaging. AUR checksums must be calculated from the published PyPI sdist,
  never from a local build.
- Verify CI, PyPI, the GitHub release/tag and AUR state after publication.
- Treat a published PyPI version as immutable; fixes require a new version.

## Documentation rules

- Prefer links back to this guide and the owning source document over copied
  command/version tables.
- Keep examples executable and test their command names and referenced paths.
- Mark hardware observations, external limitations and unverified assumptions
  explicitly; do not turn a local experiment into a general guarantee.
- When behavior changes, update tests, help text, the owning guide and the
  changelog together.
