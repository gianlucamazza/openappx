"""Unified `openappx` console entrypoint."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("-V", "--version"):
        from openappx import __version__

        print(f"openappx {__version__}")
        return 0
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: openappx <pack|bundle|unpack|sign|validate|inspect|deploy> …")
        print("  openappx pack --root DIR --out FILE.msix")
        print("  openappx bundle --package A.msix --package B.msix --out X.msixbundle")
        print("  openappx unpack --package FILE.msix --out DIR")
        print("  openappx sign --package FILE.msix --pfx CERT.pfx")
        print("  openappx validate --root DIR")
        print("  openappx inspect --package FILE.msix [--json]")
        print("  openappx deploy --device URL --user NAME --package FILE.msix")
        return 0 if argv else 2

    cmd, rest = argv[0], argv[1:]
    if cmd == "pack":
        from openappx.pack import main as pack_main

        return pack_main(rest)
    if cmd == "bundle":
        from openappx.bundle import main as bundle_main

        return bundle_main(rest)
    if cmd == "validate":
        from openappx.validate import main as validate_main

        return validate_main(rest)
    if cmd == "inspect":
        from openappx.inspect import main as inspect_main

        return inspect_main(rest)
    if cmd == "unpack":
        from openappx.unpack import main as unpack_main

        return unpack_main(rest)
    if cmd == "sign":
        from openappx.sign.cli import main as sign_main

        return sign_main(rest)
    if cmd == "deploy":
        from openappx.deploy import main as deploy_main

        return deploy_main(rest)

    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
