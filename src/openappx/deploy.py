"""Deploy packages to a device through the Windows Device Portal (WDP).

WDP is the same REST service on Xbox, HoloLens, IoT and Windows desktop, so this
stays product-agnostic:

    POST   /api/app/packagemanager/package?package=<name>   install (multipart)
    GET    /api/app/packagemanager/state                    installation progress
    GET    /api/app/packagemanager/packages                 installed packages
    DELETE /api/app/packagemanager/package?package=<pfn>    uninstall

Two WDP quirks drive the design:

- **CSRF**: non-GET requests need an `X-CSRF-Token` header derived from a session
  cookie, which standalone clients cannot easily produce. Microsoft's documented
  escape hatch is to prefix the username with `auto-`; we do that by default.
  That username must never be used to log into the web UI, or the console is
  open to CSRF attacks.
- **TLS**: devices serve a self-signed certificate, so verification fails by
  default. `--insecure` is required to accept it, explicitly rather than
  silently.

Installing a package is a change to someone's device: this module never picks a
target on its own, and never uninstalls as a side effect of installing.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

INSTALL_PATH = "/api/app/packagemanager/package"
STATE_PATH = "/api/app/packagemanager/state"
PACKAGES_PATH = "/api/app/packagemanager/packages"

PASSWORD_ENV = "OPENAPPX_DEVICE_PASSWORD"
DEFAULT_TIMEOUT = 300


class DeviceError(RuntimeError):
    """The device rejected a request, or could not be reached."""


@dataclass
class InstallState:
    """A snapshot of `GET /state`; `code` 0 means success, None means idle."""

    code: int | None
    message: str
    phase: str
    raw: dict

    @property
    def done(self) -> bool:
        return self.code is not None

    @property
    def failed(self) -> bool:
        return self.code is not None and self.code != 0


class DevicePortal:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        insecure: bool = False,
        bypass_csrf: bool = True,
        timeout: int = 30,
    ) -> None:
        self.base_url = self._normalise(base_url)
        # See the module docstring: `auto-` is how a CLI escapes CSRF protection.
        self.username = (
            f"auto-{username}"
            if bypass_csrf and not username.startswith("auto-")
            else username
        )
        self.password = password
        self.timeout = timeout
        self.context = ssl._create_unverified_context() if insecure else None

    @staticmethod
    def _normalise(base_url: str) -> str:
        if "://" not in base_url:
            base_url = f"https://{base_url}"
        return base_url.rstrip("/")

    def _auth_header(self) -> str:
        raw = f"{self.username}:{self.password}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _open(self, request: urllib.request.Request) -> tuple[int, bytes]:
        request.add_header("Authorization", self._auth_header())
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.context
            ) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace").strip()
            if e.code == 401:
                raise DeviceError(
                    "authentication rejected (401) — check the Device Portal "
                    "username and password set in Dev Home"
                ) from e
            if e.code == 403:
                raise DeviceError(
                    f"forbidden (403): {body or 'likely CSRF protection'} — the "
                    "username must be usable with the `auto-` prefix"
                ) from e
            raise DeviceError(f"device returned HTTP {e.code}: {body}") from e
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError):
                raise DeviceError(
                    "TLS verification failed — devices use a self-signed "
                    "certificate; pass --insecure to accept it"
                ) from e
            raise DeviceError(f"cannot reach {self.base_url}: {reason}") from e

    def _url(self, path: str, params: dict | None = None) -> str:
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return url

    def packages(self) -> list[dict]:
        _status, body = self._open(urllib.request.Request(self._url(PACKAGES_PATH)))
        return json.loads(body or b"{}").get("InstalledPackages", [])

    def install_state(self) -> InstallState:
        status, body = self._open(urllib.request.Request(self._url(STATE_PATH)))
        if status == 204 or not body.strip():
            return InstallState(code=None, message="", phase="idle", raw={})
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return InstallState(
                code=None,
                message=body.decode("utf-8", errors="replace"),
                phase="unknown",
                raw={},
            )
        return InstallState(
            code=data.get("Code"),
            message=data.get("Reason") or data.get("CodeText") or "",
            phase=data.get("InstallState") or data.get("Phase") or "",
            raw=data,
        )

    def install(self, package: Path, extra_files: list[Path] | None = None) -> None:
        """Upload a package. Returns once the device accepts it, not once installed."""
        package = Path(package)
        if not package.is_file():
            raise DeviceError(f"no such package: {package}")

        files = [package, *(extra_files or [])]
        boundary = f"----openappx-{uuid.uuid4().hex}"
        with tempfile.TemporaryFile() as body:
            for path in files:
                body.write(f"--{boundary}\r\n".encode())
                body.write(
                    f'Content-Disposition: form-data; name="{path.name}"; '
                    f'filename="{path.name}"\r\n'.encode()
                )
                body.write(b"Content-Type: application/octet-stream\r\n\r\n")
                with path.open("rb") as source:  # streamed: packages can be large
                    while chunk := source.read(1 << 20):
                        body.write(chunk)
                body.write(b"\r\n")
            body.write(f"--{boundary}--\r\n".encode())
            length = body.tell()
            body.seek(0)

            request = urllib.request.Request(
                self._url(INSTALL_PATH, {"package": package.name}),
                data=body,
                method="POST",
            )
            request.add_header(
                "Content-Type", f"multipart/form-data; boundary={boundary}"
            )
            request.add_header("Content-Length", str(length))
            self._open(request)

    def wait_for_install(
        self, timeout: int = DEFAULT_TIMEOUT, poll: float = 2.0
    ) -> InstallState:
        deadline = time.monotonic() + timeout
        state = self.install_state()
        while not state.done and time.monotonic() < deadline:
            time.sleep(poll)
            state = self.install_state()
        return state

    def uninstall(self, package_full_name: str) -> None:
        request = urllib.request.Request(
            self._url(INSTALL_PATH, {"package": package_full_name}), method="DELETE"
        )
        self._open(request)


def resolve_password(explicit: str | None) -> str:
    """Prefer the environment over argv, so the password stays out of `ps`."""
    if explicit:
        return explicit
    from_env = os.environ.get(PASSWORD_ENV)
    if from_env:
        return from_env
    if not sys.stdin.isatty():
        raise DeviceError(
            f"no password: set {PASSWORD_ENV} or pass --password on a terminal"
        )
    return getpass.getpass("Device Portal password: ")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Install or remove packages on a device via Windows Device Portal"
    )
    ap.add_argument("--device", required=True, help="e.g. https://192.168.1.50:11443")
    ap.add_argument("--user", required=True, help="Device Portal username")
    ap.add_argument(
        "--password",
        default=None,
        help=f"prefer the {PASSWORD_ENV} environment variable",
    )
    ap.add_argument(
        "--insecure", action="store_true", help="accept the self-signed cert"
    )
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)

    action = ap.add_mutually_exclusive_group(required=True)
    action.add_argument("--package", type=Path, help="package to install")
    action.add_argument("--list", action="store_true", help="list installed packages")
    action.add_argument("--uninstall", metavar="PACKAGE_FULL_NAME")

    ap.add_argument(
        "--also-upload",
        type=Path,
        nargs="*",
        default=[],
        help="dependency packages or a .cer to send alongside",
    )
    ap.add_argument("--no-wait", action="store_true", help="do not poll for the result")
    args = ap.parse_args(argv)

    try:
        portal = DevicePortal(
            args.device,
            args.user,
            resolve_password(args.password),
            insecure=args.insecure,
            timeout=max(30, args.timeout),
        )

        if args.list:
            for pkg in portal.packages():
                print(f"{pkg.get('PackageFullName', '?')}\t{pkg.get('Name', '')}")
            return 0

        if args.uninstall:
            portal.uninstall(args.uninstall)
            print(f"Removed {args.uninstall}")
            return 0

        print(f"Uploading {args.package.name} to {portal.base_url} …")
        portal.install(args.package, args.also_upload)
        if args.no_wait:
            print("Upload accepted; not waiting for the install to finish.")
            return 0

        state = portal.wait_for_install(args.timeout)
    except DeviceError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    if not state.done:
        print(
            f"Still installing after {args.timeout}s; last phase: {state.phase or '?'}"
        )
        return 1
    if state.failed:
        print(f"Install failed (code {state.code}): {state.message}", file=sys.stderr)
        if state.raw:
            print(json.dumps(state.raw, indent=2), file=sys.stderr)
        return 1

    print("Installed successfully.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
