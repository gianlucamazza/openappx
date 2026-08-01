# The Appx/MSIX package format, as measured

Everything here was established by dissecting Microsoft-signed packages and by
watching an Xbox One dev kit accept or reject deliberately-broken ones. Where a
rule contradicts what the format documentation seems to say, the measurement
wins and the method is noted, because several of these look wrong until you see
the error code.

For signature internals see [signing.md](signing.md); this file covers the
container and the blockmap.

## Parts of a package

| Part                             | Written by                     | In the blockmap?                  |
| -------------------------------- | ------------------------------ | --------------------------------- |
| `AppxManifest.xml`               | you                            | yes                               |
| payload (binaries, assets, …)    | you                            | yes                               |
| `[Content_Types].xml`            | the packer                     | no                                |
| `AppxBlockMap.xml`               | the packer                     | no                                |
| `AppxMetadata/CodeIntegrity.cat` | the packer (openappx does not) | no — covered by the `AXCI` digest |
| `AppxSignature.p7x`              | the signer                     | no — must be the **last** record  |

A layout must never pre-seed the generated parts: `blockmap.SKIP_NAMES` drops
them so a re-pack cannot pick up a previous run's output.

## The ZIP container

### ZIP64 is required at the end, forbidden on the records

This is the rule that costs the most time to discover, because it is not about
size at all.

- **The archive needs a ZIP64 end-of-central-directory record**, its locator, and
  a classic EOCD whose fields are the sentinels `0xFFFF` / `0xFFFFFFFF`. Without
  it, installation fails with `0x8007000B` — "opening the package failed" — even
  for a 3 KB package.
- **Individual records must not carry ZIP64 extra fields.** A package whose
  entries have them is refused with the _same_ `0x8007000B`, while the identical
  package without them installs. Microsoft's own packages have `extraLen=0` on
  every record.

Standard ZIP tooling accepts either form, so neither rule shows up until a
device sees the package. The consequence is that a file above 4 GiB cannot be
carried at all: `pack` refuses it rather than emitting an archive nothing opens.

Central directory entries are marked "made by" version 4.5; the entries
themselves need only 2.0 features.

### Names

- Entry names use **forward slashes**; the blockmap spells the same file with
  **backslashes**. Both appear in this codebase — `package_path()` produces one,
  `_zip_name()` the other.
- Non-ASCII names need **flag bit 11** (`0x800`) set on the record. Without it a
  reader falls back to CP437 and `città-日本.png` arrives as `citt├á-µùÑµ£¼.png`.
  `zipfile` sets this automatically; a hand-rolled writer must remember to.

### Determinism

Timestamps are fixed to the 1980 DOS epoch, so packing the same layout twice
yields byte-identical output. Nothing may stamp wall-clock time into a record.

## AppxBlockMap.xml

Each `<File>` carries `Name`, `Size` (the uncompressed file size), `LfhSize`,
and a `<Block>` per 64 KiB of content.

| Attribute       | Covers                                       | Notes                                  |
| --------------- | -------------------------------------------- | -------------------------------------- |
| `Block/@Hash`   | SHA-256 of the **uncompressed** 64 KiB block | base64                                 |
| `Block/@Size`   | the **compressed** length of that block      | **omitted entirely** for stored parts  |
| `File/@LfhSize` | `30 + len(utf8 name) + len(extra)`           | must match the record actually written |

Two consequences that are easy to get backwards:

- Reporting per-block compressed lengths means compressing block by block
  (`zlib.compressobj` + `Z_FULL_FLUSH`), which `zipfile.writestr` cannot express.
  That is why `pack_core` writes the archive by hand. The 2-byte deflate
  end-of-stream marker belongs to no block, so the sizes sum to
  `compress_size - 2`.
- **An empty file has zero `<Block>` elements** — `<File Name="…" Size="0"
LfhSize="…"/>` — not one block hashing `b""`.

Files are sorted case-insensitively by package path before hashing, which is part
of what makes output reproducible.

## Manifest rules a device enforces

`validate` checks these locally because the device reports them as a hex code
and, at best, a line number.

| Rule                                                                              | Device error if broken             |
| --------------------------------------------------------------------------------- | ---------------------------------- |
| The manifest must be well-formed XML — note that `--` is invalid inside a comment | `0xC00CEE23`, with line and column |
| `Windows.FullTrustApplication` requires the `runFullTrust` capability             | `0x80080204`, with a line number   |
| `Identity/@Publisher` must equal the signing certificate subject exactly          | rejected at install                |
| A managed `EntryPoint` (`ns.Class`) needs `ns.winmd` in the layout                | installs, then fails to launch     |

## The executable must be linked for the app container

An `Application/@Executable` has to carry
`IMAGE_DLLCHARACTERISTICS_APPCONTAINER` (`0x1000`) in its PE
`DllCharacteristics`, or the device refuses the package. MSBuild sets it from
`<AppContainerApplication>true`; cross-compiling, it comes from
`lld-link /appcontainer`.

`inspect` reads the flag straight out of the PE stored in the archive —
optional-header offset `0x46`, the same in PE32 and PE32+:

```
$ objdump -p hello.exe | grep DllCharacteristics
DllCharacteristics	00009160        # 0x8160 without /appcontainer
```

It only reports the confident no: an `Executable` that is not a parseable PE is
left alone, because a package may legitimately carry one (the `minimal-layout`
example does).

## Bundles

An `.msixbundle` is the same container with different contents. Five things
differ, and each was found by a device refusing a bundle that looked right.

|                                     | Package                            | Bundle                                |
| ----------------------------------- | ---------------------------------- | ------------------------------------- |
| manifest                            | `AppxManifest.xml`                 | `AppxMetadata/AppxBundleManifest.xml` |
| blockmap covers                     | every payload file                 | **the bundle manifest only**          |
| payload                             | deflated when it helps             | **always stored**                     |
| `[Content_Types].xml` `xml` default | `manifest+xml`                     | `bundlemanifest+xml`                  |
| SIP GUID in the signature           | `4BDFC50A07CEE24DB76E23C839A09FD1` | `B3585F0FDEAA9A4BA43495742D92ECEB`    |

- **`Package/@Offset` is where the payload's data starts** — the local header
  offset plus `LfhSize`, not the record offset. It is the only number here that
  cannot be recomputed from the parts, which is why `inspect` checks it.
- **Application packages carry no `ResourceId`.** Put one there and the device
  stops matching them by architecture: _"does not have an appropriate
  application package for x64 architecture"_, with a perfectly good x64 package
  in the bundle.
- **A package is a resource package because `Identity/@ResourceId` is set**, not
  because it has no `<Applications>`. The obvious guess earns `0x80080204`,
  _"its package type doesn't match the value found in the bundle manifest"_.
- **Every payload in a signed bundle must be signed too.** Signing only the
  bundle is answered with `0x800B0100` against the _bundle_, which reads as if
  the bundle itself were unsigned. Upstream's unsigned unpack fixtures have
  unsigned payloads, so this only applies once a bundle is signed.
- A bundle of nothing but resource packages is legal (upstream ships one); a
  bundle mixing an app and a language pack needs both to carry a `resources.pri`
  that merges, or registration fails with `0x80070002`.

## Install error codes

The sequence a package goes through, and what each failure means. Read top to
bottom: fixing one moves the failure to the next line.

| Code         | Meaning                             | Cause                                       |
| ------------ | ----------------------------------- | ------------------------------------------- |
| `0x8007000B` | opening the package failed          | no ZIP64 EOCD, or ZIP64 extras on records   |
| `0x800B0100` | `TRUST_E_NOSIGNATURE`               | package is unsigned                         |
| `0x80096010` | `TRUST_E_BAD_DIGEST`                | contents do not match the signature         |
| `0xC00CEE23` | manifest is not valid XML           | malformed manifest                          |
| `0x80080204` | manifest validation error           | a semantic rule, e.g. missing capability    |
| `0x80070490` | `ERROR_NOT_FOUND` during deployment | the payload itself — e.g. not a real binary |

Reaching `0x80070490` means container, signature, blockmap and manifest were all
accepted.

## How to check a claim in this file

```bash
openappx inspect --package some.msix     # any package, not just ours
openappx deploy --device https://<ip>:11443 --user NAME --package some.msix
```

`tests/test_signature.py` fetches Microsoft's own signed packages on demand and
re-checks the blockmap rules against them on every run, so a drift in our reading
of the format fails the suite rather than shipping.
