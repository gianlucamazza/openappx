"""Unified `openappx` console entrypoint."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: openappx <pack|validate|inspect> …")
        print("  openappx pack --root DIR --out FILE.msix")
        print("  openappx validate --root DIR")
        print("  openappx inspect --package FILE.msix [--json]")
        return 0 if argv else 2

    cmd, rest = argv[0], argv[1:]
    if cmd == "pack":
        from openappx.pack import main as pack_main

        return pack_main(rest)
    if cmd == "validate":
        from openappx.validate import main as validate_main

        return validate_main(rest)
    if cmd == "inspect":
        from openappx.inspect import main as inspect_main

        return inspect_main(rest)

    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
