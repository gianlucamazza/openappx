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
  crafted package cannot write outside the destination; see
  `tests/test_unpack.py`. Please report any way around that.

## What verification does and does not prove

`openappx inspect` checks that a package matches the digests its own signature
covers. It does **not** validate the certificate chain, check expiry or
revocation, or confirm that `Identity/@Publisher` matches the signer. A package
reported as consistent may still be signed by anyone at all.

## Reporting

Open a GitHub issue for anything affecting package integrity, the traversal
guard, or credential handling. This is an experimental project with no security
support commitment; there is no private disclosure channel.
