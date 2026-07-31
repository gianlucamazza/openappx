"""Deploy packages to a device through the Windows Device Portal (WDP).

WDP is the same REST service on Xbox, HoloLens, IoT and Windows desktop, so this
stays product-agnostic:

    POST   /api/app/packagemanager/package?package=<name>   install (multipart)
    GET    /api/app/packagemanager/state                    installation progress
    GET    /api/app/packagemanager/packages                 installed packages
    DELETE /api/app/packagemanager/package?package=<pfn>    uninstall

Two WDP quirks drive the design:

- **CSRF**: non-GET requests need an `X-CSRF-Token` header whose value comes from
  the `CSRF-Token` session cookie. We do a GET first, keep the cookie and echo it
  back — the scheme the Device Portal web UI itself uses, and the one proven
  against a real Xbox. Microsoft also documents an `auto-<username>` prefix that
  bypasses CSRF for CLI clients; it is available via `bypass_csrf=True`, but that
  account must then never be used in the web UI, or the console is open to CSRF.
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
import re
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
TASKMANAGER_PATH = "/api/taskmanager/app"
CERTIFICATE_PATH = "/api/app/packagemanager/certificate"
STATE_PATH = "/api/app/packagemanager/state"
PACKAGES_PATH = "/api/app/packagemanager/packages"

# WDP expects every uploaded part under the form field name "file", regardless of
# the file's own name; the file name goes in the `package` query parameter.
FORM_FIELD = "file"
CSRF_COOKIE = "CSRF-Token"
CSRF_HEADER = "X-CSRF-Token"

PASSWORD_ENV = "OPENAPPX_DEVICE_PASSWORD"
DEFAULT_TIMEOUT = 300


def package_family_name(package_full_name: str) -> str:
    """`Name_1.2.3.4_x64__hash` -> `Name__hash`, the identity WDP launches by."""
    match = re.fullmatch(r"(.+?)_[\d.]+_[^_]*__(.+)", package_full_name)
    if not match:
        raise ValueError(f"not a package full name: {package_full_name}")
    return f"{match.group(1)}__{match.group(2)}"


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
        if self.code is None:
            return False
        if self.raw.get("Success") is False:
            return True
        return self.code != 0


class DevicePortal:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        insecure: bool = False,
        bypass_csrf: bool = False,
        timeout: int = 30,
    ) -> None:
        self.base_url = self._normalise(base_url)
        # `auto-` is Microsoft's documented CSRF escape hatch; off by default
        # because the cookie-to-header scheme below is what a real Xbox accepts.
        self.username = (
            f"auto-{username}"
            if bypass_csrf and not username.startswith("auto-")
            else username
        )
        self.password = password
        self.timeout = timeout
        self.context = self._tls_context() if insecure else None
        self._csrf_token: str | None = None

    @staticmethod
    def _tls_context() -> ssl.SSLContext:
        """Accept the device's self-signed certificate, deliberately and visibly.

        Built from the public API rather than `ssl._create_unverified_context()`,
        so what is being switched off is spelled out.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    @staticmethod
    def _normalise(base_url: str) -> str:
        if "://" not in base_url:
            base_url = f"https://{base_url}"
        return base_url.rstrip("/")

    def _auth_header(self) -> str:
        raw = f"{self.username}:{self.password}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def _fetch_csrf_token(self) -> str | None:
        """GET the root page to establish the CSRF session cookie.

        The Device Portal UI copies the `CSRF-Token` cookie into the
        `X-CSRF-Token` header on every non-GET request; so do we.
        """
        if self._csrf_token is not None:
            return self._csrf_token
        request = urllib.request.Request(self.base_url + "/")
        request.add_header("Authorization", self._auth_header())
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.context
            ) as response:
                cookies = response.headers.get_all("Set-Cookie") or []
        except (urllib.error.HTTPError, urllib.error.URLError):
            return None  # let the actual request report the real failure

        for cookie in cookies:
            for part in cookie.split(";"):
                name, _, value = part.strip().partition("=")
                if name.lower() == CSRF_COOKIE.lower() and value:
                    self._csrf_token = value
                    return value
        return None

    def _open(
        self, request: urllib.request.Request, allow: tuple[int, ...] = ()
    ) -> tuple[int, bytes]:
        request.add_header("Authorization", self._auth_header())
        if request.get_method() != "GET":
            token = self._fetch_csrf_token()
            if token:
                request.add_header(CSRF_HEADER, token)
                request.add_header("Cookie", f"{CSRF_COOKIE}={token}")
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.context
            ) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace").strip()
            if e.code in allow:
                return e.code, body.encode()
            if e.code == 401:
                raise DeviceError(
                    "authentication rejected (401) — check the Device Portal "
                    "username and password set in Dev Home"
                ) from e
            if e.code == 403:
                raise DeviceError(
                    f"forbidden (403): {body or 'likely CSRF protection'} — the "
                    f"{CSRF_HEADER} handshake failed; retry with bypass_csrf "
                    "(sends the username as `auto-<name>`)"
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
        """Poll the deployment result.

        WDP status codes carry the meaning here: 200 is the result of the last
        deployment, 204 means one is still running, 404 means none was found.
        """
        status, body = self._open(
            urllib.request.Request(self._url(STATE_PATH)), allow=(404,)
        )
        if status == 204:
            return InstallState(code=None, message="", phase="installing", raw={})
        if status == 404:
            return InstallState(code=None, message="", phase="none", raw={})
        if not body.strip():
            return InstallState(code=None, message="", phase="unknown", raw={})
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
            phase=data.get("InstallState") or data.get("Phase") or "done",
            raw=data,
        )

    def _upload(self, path: str, files: list[Path], package_name: str) -> bytes:
        boundary = f"----openappx-{uuid.uuid4().hex}"
        with tempfile.TemporaryFile() as body:
            for item in files:
                body.write(f"--{boundary}\r\n".encode())
                body.write(
                    f'Content-Disposition: form-data; name="{FORM_FIELD}"; '
                    f'filename="{item.name}"\r\n'.encode()
                )
                body.write(b"Content-Type: application/octet-stream\r\n\r\n")
                with item.open("rb") as source:  # streamed: packages can be large
                    while chunk := source.read(1 << 20):
                        body.write(chunk)
                body.write(b"\r\n")
            body.write(f"--{boundary}--\r\n".encode())
            length = body.tell()
            body.seek(0)

            request = urllib.request.Request(
                self._url(path, {"package": package_name}), data=body, method="POST"
            )
            request.add_header(
                "Content-Type", f"multipart/form-data; boundary={boundary}"
            )
            request.add_header("Content-Length", str(length))
            _status, response = self._open(request)
            return response

    def install(self, package: Path, extra_files: list[Path] | None = None) -> None:
        """Upload a package. Returns once the device accepts it, not once installed.

        `extra_files` carries dependency packages (framework .appx) alongside it;
        WDP accepts them as further parts of the same upload.
        """
        package = Path(package)
        if not package.is_file():
            raise DeviceError(f"no such package: {package}")
        self._upload(INSTALL_PATH, [package, *(extra_files or [])], package.name)

    def install_certificate(self, certificate: Path) -> None:
        """Trust a .cer on the device so packages signed with it can install."""
        certificate = Path(certificate)
        if not certificate.is_file():
            raise DeviceError(f"no such certificate: {certificate}")
        self._upload(CERTIFICATE_PATH, [certificate], certificate.name)

    def wait_for_install(
        self, timeout: int = DEFAULT_TIMEOUT, poll: float = 2.0
    ) -> InstallState:
        deadline = time.monotonic() + timeout
        state = self.install_state()
        while not state.done and time.monotonic() < deadline:
            time.sleep(poll)
            state = self.install_state()
        return state

    def start_app(self, package_full_name: str, app_id: str) -> None:
        """Launch an installed app.

        WDP identifies apps by AUMID — `<PackageFamilyName>!<ApplicationId>`,
        base64-encoded — where the family name is the full name with the version
        and architecture removed. The `Id` comes from `<Application Id="...">`
        in the manifest.
        """
        aumid = f"{package_family_name(package_full_name)}!{app_id}"
        encoded = base64.b64encode(aumid.encode("utf-8")).decode("ascii")
        request = urllib.request.Request(
            self._url(TASKMANAGER_PATH, {"appid": encoded}), data=b"", method="POST"
        )
        request.add_header("Content-Length", "0")
        self._open(request)

    def stop_app(self, package_full_name: str) -> None:
        request = urllib.request.Request(
            self._url(TASKMANAGER_PATH, {"package": package_full_name}), method="DELETE"
        )
        self._open(request)

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
    action.add_argument(
        "--start",
        metavar="PACKAGE_FULL_NAME",
        help="launch an installed app (see --app-id)",
    )
    action.add_argument("--stop", metavar="PACKAGE_FULL_NAME")
    action.add_argument(
        "--install-cert",
        type=Path,
        metavar="CERT.cer",
        help="trust a certificate on the device so packages signed with it install",
    )

    ap.add_argument(
        "--also-upload",
        type=Path,
        nargs="*",
        default=[],
        help="dependency packages or a .cer to send alongside",
    )
    ap.add_argument(
        "--app-id",
        default=None,
        help="Application/@Id from the manifest, required with --start",
    )
    ap.add_argument("--no-wait", action="store_true", help="do not poll for the result")
    ap.add_argument(
        "--csrf-bypass",
        action="store_true",
        help="send the username as `auto-<name>` instead of the cookie handshake",
    )
    args = ap.parse_args(argv)

    try:
        portal = DevicePortal(
            args.device,
            args.user,
            resolve_password(args.password),
            insecure=args.insecure,
            bypass_csrf=args.csrf_bypass,
            timeout=max(30, args.timeout),
        )

        if args.list:
            for pkg in portal.packages():
                print(f"{pkg.get('PackageFullName', '?')}\t{pkg.get('Name', '')}")
            return 0

        if args.install_cert:
            portal.install_certificate(args.install_cert)
            print(f"Installed certificate {args.install_cert.name}")
            return 0

        if args.start:
            if not args.app_id:
                raise DeviceError("--start needs --app-id (Application/@Id)")
            portal.start_app(args.start, args.app_id)
            print(f"Started {args.start}!{args.app_id}")
            return 0

        if args.stop:
            portal.stop_app(args.stop)
            print(f"Stopped {args.stop}")
            return 0

        if args.uninstall is not None:
            if not args.uninstall.strip():
                raise DeviceError("--uninstall needs a PackageFullName")
            portal.uninstall(args.uninstall)
            print(f"Removed {args.uninstall}")
            return 0

        print(f"Uploading {args.package.name} to {portal.base_url} …", flush=True)
        portal.install(args.package, args.also_upload)
        if args.no_wait:
            print("Upload accepted; not waiting for the install to finish.", flush=True)
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
