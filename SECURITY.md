# Security

## Scope

openappx builds, signs and inspects Appx/MSIX packages, and can install them on
a device over the Windows Device Portal. Relevant to security:

- **Signing keys.** `openappx sign` reads a PKCS#12 file. Prefer the
  `OPENAPPX_PFX_PASSWORD` environment variable over `--pfx-password`, which is
  visible to anything that can read the process list.
- **Device credentials.** Likewise `OPENAPPX_DEVICE_PASSWORD` rather than
  `--password`.
- **`--insecure`.** Device Portal serves a self-signed certificate, so deploying
  requires disabling TLS verification. That makes the connection trivially
  interceptable: use it on a network you trust, not over the open internet.
- **`openappx unpack` reads untrusted archives.** Member names are checked so a
  crafted package cannot write outside the destination, and a duplicate member
  is refused rather than silently overwriting; see `tests/test_unpack.py`.
- **`pack` reads a layout that may not be yours.** A symlink anywhere under the
  pack root is refused rather than followed, and a manifest reference that
  escapes the root — `../`, an absolute path, a drive letter — is reported as
  missing rather than resolved. Both would otherwise pull host files into a
  package.
- **Output is written atomically.** A failed pack or sign leaves the previous
  file intact instead of a truncated archive, which would be a valid ZIP that
  fails much later, on a device.

Please report any way around these.

## What verification does and does not prove

`openappx inspect` checks that a package matches the digests its own signature
covers, that `Identity/@Publisher` agrees with the certificate subject, and that
the certificate is inside its validity dates.

It does **not** validate the certificate chain, or check revocation. **A package
reported as consistent may still be signed by anyone at all** — including with a
self-signed certificate minted a minute ago naming any publisher it likes. Trust
is the installing device's decision, and this tool does not make it.

## Reporting

Use GitHub's private vulnerability reporting (Security → Report a vulnerability)
for anything affecting package integrity, the traversal guard in `unpack`, or
credential handling. Anything else can be a normal issue.

This is a beta project maintained in spare time: expect a best-effort response,
not a service level.
