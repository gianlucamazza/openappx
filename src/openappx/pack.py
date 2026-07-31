"""CLI: pack a layout directory into .msix."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from openappx.pack_core import pack_makemsix, pack_python
from openappx.validate import layout_problems


def default_makemsix() -> Path:
    # repo_root/scripts → repo_root/tools/bin or sibling
    here = Path(__file__).resolve()
    candidates = [
        here.parents[2] / "tools" / "bin" / "makemsix",
        Path.home() / ".local" / "bin" / "makemsix",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return candidates[0]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="openappx pack — create an .msix from a layout")
    ap.add_argument("--root", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--backend", choices=("python", "makemsix"), default="python")
    ap.add_argument("--makemsix", type=Path, default=None)
    ap.add_argument("--cert", type=Path, default=None)
    ap.add_argument("--cert-password", default=None)
    ap.add_argument("--allow-missing", action="store_true")
    args = ap.parse_args(argv)

    root = args.root.resolve()
    if not root.is_dir():
        print(f"error: root is not a directory: {root}", file=sys.stderr)
        return 2

    problems = layout_problems(root)
    if problems and not args.allow_missing:
        print("Layout validation failed:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("Use --allow-missing to pack anyway.", file=sys.stderr)
        return 2
    for p in problems:
        print(f"warning: {p}", file=sys.stderr)

    try:
        if args.backend == "python":
            if args.cert:
                print(
                    "warning: --cert ignored with --backend python "
                    "(use --backend makemsix for signing)",
                    file=sys.stderr,
                )
            out = pack_python(root, args.out)
        else:
            bin_path = args.makemsix or default_makemsix()
            if not bin_path.is_file():
                print(
                    f"error: makemsix not found at {bin_path}\n"
                    "  Run: ./scripts/bootstrap-makemsix.sh",
                    file=sys.stderr,
                )
                return 2
            out = pack_makemsix(
                root,
                args.out,
                bin_path,
                cert=args.cert,
                cert_password=args.cert_password,
            )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"Wrote {out} ({out.stat().st_size} bytes) backend={args.backend}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
