# Roadmap

## v0.1 — Pack foundation (current)

- [x] Project skeleton + MIT license
- [x] Blockmap generation (64 KiB SHA-256)
- [x] Pure-Python pack → `.msix`
- [x] Layout validation (manifest, executable, logos)
- [x] Minimal example layout + unit tests
- [x] Optional makemsix backend hook + bootstrap script

## v0.2 — Robustness

- [ ] Golden tests against packages produced by makeappx (when available)
- [x] LfhSize / ZIP parity asserted against the headers actually written
- [x] Byte-reproducible pack (asserted in tests)
- [ ] `openappx inspect` — list package contents + blockmap summary
- [x] CI (GitHub Actions, Linux, Python 3.10–3.13)

## v0.3 — Signing

- [ ] Document makemsix sign path end-to-end
- [ ] Research pure-Python / OpenSSL Appx SIP signing feasibility
- [ ] `openappx sign` CLI (wrapper or native)

## Later (research, not committed)

- Generic Device Portal / sideload deploy module (HTTP, no product lock-in)
- Notes on PE cross-compilation sysroots (documentation only unless a maintainer owns it)
- Bundle (`.msixbundle`) support

## Explicitly not planned as core

- Full UWP/WinRT application framework
- Shipping a Windows SDK sysroot inside this repo
