# Signing

**Status: openappx can read and verify Appx signatures. It cannot create them.**

This document records what was established by reading the upstream MSIX SDK and
by dissecting Microsoft-signed packages, so the next person does not have to
repeat it.

## The short version

| Question                       | Answer                                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Can `makemsix` sign a package? | **No.** `makemsix pack` accepts only `-d` and `-p`. Upstream ships `SignatureValidator`, no signature _creator_.                           |
| Can openappx sign?             | No. It would need CMS/PKCS#7 + ASN.1 + RSA — none in the standard library.                                                                 |
| What can openappx do?          | Parse `AppxSignature.p7x`, recompute the digests it covers, and report tampering.                                                          |
| What does verification prove?  | That the package matches what its signature covers — **not** that the certificate is trusted, unexpired, or matches `Identity/@Publisher`. |

Earlier versions of this project documented a `--cert` / `--cert-password` flow
through `makemsix`. That flow never existed; the flags are now rejected with an
explanatory error.

## AppxSignature.p7x layout

```
AppxSignature.p7x
├── b"PKCX"                       4-byte magic (P7X_FILE_ID = 0x58434b50)
└── PKCS#7 SignedData (DER)
    └── SpcIndirectDataContent    OID 1.3.6.1.4.1.311.2.1.4
        └── b"APPX" + N × (4-byte digest name + 32-byte SHA-256)
```

Digest names and what each one covers:

| Name   | Covers                                                                | Recomputable from a finished package? |
| ------ | --------------------------------------------------------------------- | ------------------------------------- |
| `AXPC` | every byte of the archive before the `AppxSignature.p7x` local record | **yes**                               |
| `AXCD` | the central directory as it was _before_ the signature was inserted   | **no**                                |
| `AXCT` | `[Content_Types].xml`, uncompressed                                   | **yes**                               |
| `AXBM` | `AppxBlockMap.xml`, uncompressed                                      | **yes**                               |
| `AXCI` | `AppxMetadata/CodeIntegrity.cat`, uncompressed (optional)             | **yes**                               |

`AXCD` is a one-way street: inserting the signature rewrites the central
directory and the end-of-central-directory records, and the original bytes
cannot be reconstructed from the signed file. Upstream does not verify it either
— see the `// TODO: unnamed stream for central directory?` in
`src/msix/unpack/AppxSignature.cpp`.

Note that upstream _locates_ the digest blob by scanning the DER for the `APPX`
marker rather than parsing ASN.1 (`SignatureValidator.cpp`, `ReadDigestHashes`).
`openappx.sign.digest` does the same, which is why it needs no ASN.1 support.

## What a signer would have to produce

1. Pack the package **without** `AppxSignature.p7x`.
2. Compute `AXPC` (all bytes up to the central directory), `AXCD` (central
   directory through end of file), `AXCT`, `AXBM`, and `AXCI` if present.
   `openappx.sign.compute_digests()` already does exactly this for an unsigned
   package.
3. Build the blob: `b"APPX"` followed by each name and its 32-byte digest.
4. Wrap it in `SpcIndirectDataContent` and sign that as PKCS#7 SignedData with
   the publisher certificate.
5. Append the result as `AppxSignature.p7x`, **as the last part of the archive**,
   with `b"PKCX"` prepended.
6. `Identity/@Publisher` in `AppxManifest.xml` must match the certificate subject
   exactly, or Windows rejects the package regardless of signature validity.

Step 4 is the blocker: it needs an ASN.1 encoder and a signing primitive. Adding
`cryptography` (or `asn1crypto`) as an **optional** extra would make it feasible
without touching the dependency-free pack path. That decision is open — see the
v0.3 roadmap entry.

## Practical options today

- **Windows**: `signtool sign /fd SHA256 /a /f cert.pfx /p <password> package.msix`
- **Linux**: no maintained open-source signer exists. `osslsigncode` handles PE
  and MSI, not Appx.
- **Verification anywhere**: `openappx inspect --package FILE.msix` reports which
  digests are declared, which were verified, and any mismatch.

## Verified against

`tests/test_signature.py` checks this reading of the format against Microsoft's
own signed test packages, downloaded on demand (not committed):

- `SignedUntrustedCert-CERT_E_CHAINING.appx` — valid digests, untrusted chain:
  `AXPC`, `AXCT`, `AXBM` all match what we recompute.
- `SignedTamperedBlockMap-TRUST_E_BAD_DIGEST.appx` — detected as an `AXBM`
  mismatch.

Set `OPENAPPX_NO_NETWORK=1` to skip those tests.

## Trust model

Unchanged from `architecture.md`: private `.pfx` material is a secret and never
belongs in the repo; public `.cer` files are safe to distribute for device trust.
Packaging tools must never invent publisher identity.
