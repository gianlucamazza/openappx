"""CLI: sign a package, or create a test certificate to sign it with."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from openappx.sign.signer import (
    SigningUnavailable,
    load_pfx,
    make_test_certificate,
    sign_package,
)

PASSWORD_ENV = "OPENAPPX_PFX_PASSWORD"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Sign an .msix with a PFX, or mint a self-signed test certificate"
    )
    ap.add_argument("--package", type=Path, help="unsigned package to sign")
    ap.add_argument("--pfx", type=Path, help="PKCS#12 file holding key + certificate")
    ap.add_argument(
        "--pfx-password",
        default=None,
        help=f"prefer the {PASSWORD_ENV} environment variable",
    )
    ap.add_argument(
        "--out", type=Path, default=None, help="defaults to signing in place"
    )

    ap.add_argument(
        "--make-test-cert",
        metavar="PUBLISHER",
        help="create a self-signed certificate, e.g. 'CN=OpenAppx-Example'. Must match "
        "Identity/@Publisher in the manifest exactly.",
    )
    ap.add_argument(
        "--cert-out", type=Path, default=None, help="where to write .pfx/.cer"
    )
    args = ap.parse_args(argv)

    try:
        if args.make_test_cert:
            stem = args.cert_out or Path("openappx-test")
            pfx, cer = make_test_certificate(
                args.make_test_cert,
                stem.with_suffix(".pfx"),
                stem.with_suffix(".cer"),
                args.pfx_password or os.environ.get(PASSWORD_ENV),
            )
            print(f"Wrote {pfx} and {cer}")
            print(
                "Trust it on the device with:\n"
                f"  openappx deploy --device URL --user NAME --install-cert {cer}"
            )
            return 0

        if not args.package or not args.pfx:
            ap.error("--package and --pfx are required unless --make-test-cert is used")

        identity = load_pfx(args.pfx, args.pfx_password or os.environ.get(PASSWORD_ENV))
        out = sign_package(args.package, identity, args.out)
    except SigningUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"Signed {out} as {identity.subject_rfc4514}")
    print(
        "Reminder: Identity/@Publisher in the manifest must equal that subject, "
        "and the device must already trust the certificate."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
