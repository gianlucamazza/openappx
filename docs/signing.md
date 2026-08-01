# Signing

This document records what was established by reading the upstream MSIX SDK, by
dissecting Microsoft-signed packages, and by testing against a real console — so
the next person does not have to repeat it.

## Status: signing works, and a console accepts it

`openappx sign` produces `AppxSignature.p7x` on Linux with no Windows tooling.
The proof is not that the code runs — it is that an Xbox One dev kit installed
a package packed *and* signed entirely by this project, and rejected the same
package with one byte altered:

| Package                                     | Console response |
| ------------------------------------------- | ---------------- |
| unsigned                                     | `0x800B0100 TRUST_E_NOSIGNATURE` — "must be digitally signed" |
| signed, ZIP32                                | `0x8007000B ERROR_BAD_FORMAT` — "opening the package failed" |
| signed, ZIP64, resource-only                 | **installed successfully** |
| signed, ZIP64, one payload byte flipped      | `0x80096010 TRUST_E_BAD_DIGEST` — "the digital signature did not verify" |
| signed, `Windows.FullTrustApplication` without `runFullTrust` | `0x80080204` — manifest validation error, with a line number |
| signed, valid manifest, placeholder `app.exe` | `0x80070490 ERROR_NOT_FOUND` — during "Deployment Add" |
| signed, ZIP64 **extra fields on entries**     | `0x8007000B` again — Appx wants the ZIP64 EOCD but no per-record extras |

Read as a sequence, those rows map the whole validation chain: container →
signature → blockmap → manifest syntax → manifest semantics → deployment. Each
error moved the failure one stage later, and the last one is about the payload
being a 31-byte placeholder rather than a real binary — nothing to do with
packaging. `openappx validate` now catches the `runFullTrust` case locally,
since the device only reports it as a line number.

Rows three and four are the proof of signing: Windows opened the container,
parsed the CMS structure, verified the RSA signature and checked the digests
against the actual bytes — rejecting exactly the two digests (`AXPC`, `AXBM`)
that `openappx inspect` independently flagged.

**Appx archives must be ZIP64.** This is not optional and not about size: a
ZIP32 archive of the same package fails to open with `0x8007000B`. Microsoft's
packages mark every central directory entry as made by version 4.5 and put the
ZIP64 sentinels (`0xFFFF` / `0xFFFFFFFF`) in the classic EOCD, followed by a
ZIP64 EOCD record and its locator. `pack_core` does the same.

### A real application, repackaged

The strongest test available: a shipped UWP application built on Windows — 47.7 MB
of real binaries, an ONNX Runtime, a DirectML, an executable and a WinMD — was
unpacked to a layout, repackaged and signed by openappx on Linux, and installed on
the console.

```
pack   47.7 MB layout  → 3.9 s   (19,775,489 bytes, vs 19,747,250 from MakeAppx)
sign                   → 0.6 s
deploy + install       → 5.3 s
```

Only `Identity/@Publisher` was changed, to a certificate we hold the key for. The
result installs alongside the original as a separate package, since a different
publisher yields a different package family name. This is the end-to-end
replacement of MakeAppx + SignTool for a genuine UWP application.

Inspecting that same original package also exposed a bug of ours:
`AppxMetadata/CodeIntegrity.cat` is deliberately **not** listed in the blockmap —
the signature covers it through `AXCI` — and `inspect` was reporting it as a
missing entry.

### Using it

```bash
# 1. A certificate whose subject equals Identity/@Publisher in the manifest
openappx sign --make-test-cert "CN=OpenAppx-Example" --cert-out mycert

# 2. Trust it on the device (once)
openappx deploy --device https://<ip>:11443 --user NAME --install-cert mycert.cer

# 3. Pack, sign, deploy
openappx pack --root layout --out app.msix
openappx sign --package app.msix --pfx mycert.pfx
openappx deploy --device https://<ip>:11443 --user NAME --package app.msix
```

Signing needs the optional extra: `pip install 'openappx[sign]'`. Packing,
inspecting and verifying remain dependency-free.

The certificate subject must match `Identity/@Publisher` **exactly**, and the
device must already trust the certificate. `openappx sign` refuses a publisher
mismatch locally (`--no-publisher-check` to override); an untrusted certificate
is still only visible as an install failure.

## Sideloading requires a signature — measured, not assumed

Uploading an unsigned openappx package to an Xbox One in Developer Mode
(`openappx deploy`) produces:

```json
{
  "Code": -2146762496,
  "CodeText": "No signature was present in the subject.",
  "Reason": "error 0x800B0100: The app package must be digitally signed for signature validation.",
  "Success": false
}
```

`0x800B0100` is `TRUST_E_NOSIGNATURE`. Two things follow:

- **No signature, no install.** There is no developer-mode escape hatch. A
  sideloading workflow has to mint or supply a certificate and install the
  `.cer` on the device first (`openappx deploy --install-cert`).
- **The container itself was readable.** Windows opened the package and looked
  for a signature, rather than rejecting it as a malformed archive. That is
  evidence our ZIP and OPC structure are acceptable — but *not* evidence the
  blockmap is correct, since the blockmap is validated through the signature
  that was missing. Proving the blockmap end-to-end requires signing first.

## The short version

| Question                       | Answer                                                                                                                                     |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Can `makemsix` sign a package? | **No.** `makemsix pack` accepts only `-d` and `-p`. Upstream ships `SignatureValidator`, no signature _creator_.                           |
| Can openappx sign?             | **Yes**, via `openappx sign` with the optional `[sign]` extra (`cryptography` for RSA and PKCS#12; the DER encoding is ours). |
| What can openappx do?          | Parse `AppxSignature.p7x`, recompute the digests it covers, and report tampering.                                                          |
| What does verification prove?  | That the package matches what its signature covers and, when `[sign]` is installed, that the certificate dates and `Identity/@Publisher` agree — **not** that the certificate is trusted. |

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

All six steps are implemented in `openappx.sign.signer`. Two hashing rules are
easy to get silently wrong, and both were confirmed against a real signature:

- the signed attributes' `messageDigest` covers the **content** of the
  `SpcIndirectDataContent` SEQUENCE, without its own tag and length;
- the RSA signature covers those attributes encoded as a `SET` (tag `0x31`), not
  with the `[0] IMPLICIT` tag they carry inside the `SignerInfo`.

## Practical options today

- **Windows**: `signtool sign /fd SHA256 /a /f cert.pfx /p <password> package.msix`
- **Linux**: `openappx sign` (this project). `osslsigncode` handles PE and MSI,
  not Appx.
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
