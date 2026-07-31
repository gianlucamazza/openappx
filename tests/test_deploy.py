"""Device Portal client, exercised against a stub server.

The stub speaks the same REST shapes as WDP, so the wire format (multipart body,
basic auth, the CSRF cookie-to-header handshake, state polling) is verified
without a console. It cannot tell us whether a real device *accepts* a package —
only a device can.
"""

from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from openappx.deploy import DeviceError, DevicePortal, main, resolve_password

RECEIVED: dict = {}


class StubHandler(BaseHTTPRequestHandler):
    """Minimal WDP stand-in. Behaviour is driven by RECEIVED['scenario']."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep test output clean
        pass

    def _auth_ok(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        RECEIVED["user"] = user
        RECEIVED["password"] = password
        return password == "hunter2"

    def _send(self, code: int, payload: dict | None = None) -> None:
        body = json.dumps(payload).encode() if payload is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if not self._auth_ok():
            return self._send(401, {"Reason": "nope"})
        if self.path == "/":
            self.send_response(200)
            self.send_header("Set-Cookie", "CSRF-Token=token-from-cookie; Path=/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.startswith("/api/app/packagemanager/state"):
            status = RECEIVED.get("state_status", 200)
            if status != 200:
                return self._send(status)
            return self._send(200, RECEIVED.get("state", {"Code": 0, "CodeText": "OK"}))
        if self.path.startswith("/api/app/packagemanager/packages"):
            return self._send(
                200,
                {
                    "InstalledPackages": [
                        {"PackageFullName": "Test_1.0_x64__abc", "Name": "Test"}
                    ]
                },
            )
        return self._send(404)

    def do_POST(self):
        if not self._auth_ok():
            return self._send(401, {"Reason": "nope"})
        if RECEIVED.get("scenario") == "csrf":
            return self._send(403, {"Reason": "CSRF token required"})
        length = int(self.headers.get("Content-Length", 0))
        RECEIVED["csrf_header"] = self.headers.get("X-CSRF-Token", "")
        RECEIVED["cookie"] = self.headers.get("Cookie", "")
        RECEIVED["body"] = self.rfile.read(length)
        RECEIVED["content_type"] = self.headers.get("Content-Type", "")
        RECEIVED["path"] = self.path
        return self._send(200, {"Reason": "accepted"})

    def do_DELETE(self):
        if not self._auth_ok():
            return self._send(401, {"Reason": "nope"})
        RECEIVED["deleted"] = self.path
        return self._send(200, {"Reason": "removed"})


@pytest.fixture
def stub():
    RECEIVED.clear()
    server = HTTPServer(("127.0.0.1", 0), StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def portal(stub: str) -> DevicePortal:
    return DevicePortal(stub, "admin", "hunter2", timeout=10)


@pytest.fixture
def package(tmp_path: Path) -> Path:
    pkg = tmp_path / "example.msix"
    pkg.write_bytes(b"PK\x03\x04" + b"payload" * 100)
    return pkg


def test_username_is_sent_unchanged_by_default(portal: DevicePortal, package: Path):
    """Default is the cookie-to-header CSRF scheme, so no `auto-` mangling."""
    portal.install(package)
    assert RECEIVED["user"] == "admin"


def test_csrf_bypass_prefixes_the_username_when_asked(stub: str):
    portal = DevicePortal(stub, "admin", "hunter2", bypass_csrf=True)
    portal.packages()
    assert RECEIVED["user"] == "auto-admin"


def test_prefix_is_not_applied_twice(stub: str):
    assert (
        DevicePortal(stub, "auto-admin", "x", bypass_csrf=True).username == "auto-admin"
    )


def test_csrf_token_is_taken_from_the_cookie_and_echoed_back(
    portal: DevicePortal, package: Path
):
    portal.install(package)
    assert RECEIVED["csrf_header"] == "token-from-cookie"
    assert "CSRF-Token=token-from-cookie" in RECEIVED["cookie"]


def test_install_state_204_means_still_running(portal: DevicePortal):
    RECEIVED["state_status"] = 204
    state = portal.install_state()
    assert not state.done and state.phase == "installing"


def test_install_state_404_means_nothing_was_deployed(portal: DevicePortal):
    RECEIVED["state_status"] = 404
    state = portal.install_state()
    assert not state.done and state.phase == "none"


def test_success_false_marks_a_failure_even_with_code_zero(portal: DevicePortal):
    RECEIVED["state"] = {"Code": 0, "Success": False, "Reason": "signature invalid"}
    assert portal.install_state().failed


def test_certificate_upload_uses_the_certificate_endpoint(
    portal: DevicePortal, tmp_path: Path
):
    cert = tmp_path / "test.cer"
    cert.write_bytes(b"certificate-bytes")
    portal.install_certificate(cert)
    assert "/api/app/packagemanager/certificate" in RECEIVED["path"]
    assert b"certificate-bytes" in RECEIVED["body"]


def test_install_sends_the_package_as_multipart(portal: DevicePortal, package: Path):
    portal.install(package)
    assert "package=example.msix" in RECEIVED["path"]
    assert RECEIVED["content_type"].startswith("multipart/form-data; boundary=")
    body = RECEIVED["body"]
    # WDP wants every part under the field name "file", whatever the file is called
    assert b'name="file"' in body
    assert b'filename="example.msix"' in body
    assert package.read_bytes() in body  # payload survives intact


def test_install_can_carry_extra_files(
    portal: DevicePortal, package: Path, tmp_path: Path
):
    cert = tmp_path / "test.cer"
    cert.write_bytes(b"certificate-bytes")
    portal.install(package, [cert])
    assert b'filename="test.cer"' in RECEIVED["body"]
    assert b"certificate-bytes" in RECEIVED["body"]


def test_install_rejects_a_missing_file(portal: DevicePortal, tmp_path: Path):
    with pytest.raises(DeviceError, match="no such package"):
        portal.install(tmp_path / "nope.msix")


def test_packages_are_listed(portal: DevicePortal):
    assert portal.packages()[0]["PackageFullName"] == "Test_1.0_x64__abc"


def test_uninstall_targets_the_package_full_name(portal: DevicePortal):
    portal.uninstall("Test_1.0_x64__abc")
    assert "package=Test_1.0_x64__abc" in RECEIVED["deleted"]


def test_failed_install_surfaces_the_device_reason(portal: DevicePortal):
    RECEIVED["state"] = {"Code": 0x80073CF0, "Reason": "package could not be opened"}
    state = portal.install_state()
    assert state.failed
    assert "could not be opened" in state.message


def test_successful_install_state(portal: DevicePortal):
    RECEIVED["state"] = {"Code": 0, "CodeText": "OK"}
    state = portal.install_state()
    assert state.done and not state.failed


def test_bad_password_is_reported_clearly(stub: str):
    portal = DevicePortal(stub, "admin", "wrong")
    with pytest.raises(DeviceError, match="authentication rejected"):
        portal.packages()


def test_csrf_rejection_is_explained(portal: DevicePortal, package: Path):
    RECEIVED["scenario"] = "csrf"
    with pytest.raises(DeviceError, match="auto-"):
        portal.install(package)


def test_unreachable_device_is_reported(package: Path):
    portal = DevicePortal("http://127.0.0.1:1", "admin", "x", timeout=2)
    with pytest.raises(DeviceError, match="cannot reach"):
        portal.packages()


def test_base_url_defaults_to_https():
    assert (
        DevicePortal("192.168.1.5:11443", "a", "b").base_url
        == "https://192.168.1.5:11443"
    )
    assert DevicePortal("http://host/", "a", "b").base_url == "http://host"


def test_password_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "from-env")
    assert resolve_password(None) == "from-env"
    assert resolve_password("explicit") == "explicit"


def test_password_is_required_when_not_interactive(monkeypatch):
    monkeypatch.delenv("OPENAPPX_DEVICE_PASSWORD", raising=False)
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    with pytest.raises(DeviceError, match="no password"):
        resolve_password(None)


def test_cli_installs_and_reports_success(
    stub: str, package: Path, monkeypatch, capsys
):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    code = main(["--device", stub, "--user", "admin", "--package", str(package)])
    assert code == 0
    assert "Installed successfully" in capsys.readouterr().out


def test_cli_reports_a_failed_install(stub: str, package: Path, monkeypatch, capsys):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    RECEIVED["state"] = {"Code": 0x80073CF0, "Reason": "blockmap is invalid"}
    code = main(["--device", stub, "--user", "admin", "--package", str(package)])
    assert code == 1
    assert "blockmap is invalid" in capsys.readouterr().err


def test_cli_lists_packages(stub: str, monkeypatch, capsys):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    assert main(["--device", stub, "--user", "admin", "--list"]) == 0
    assert "Test_1.0_x64__abc" in capsys.readouterr().out


def test_cli_installs_a_certificate(stub: str, tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    cert = tmp_path / "trust.cer"
    cert.write_bytes(b"certificate-bytes")
    code = main(["--device", stub, "--user", "admin", "--install-cert", str(cert)])
    assert code == 0
    assert "/api/app/packagemanager/certificate" in RECEIVED["path"]
    assert "Installed certificate trust.cer" in capsys.readouterr().out


def test_cli_uninstalls(stub: str, monkeypatch, capsys):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    code = main(
        ["--device", stub, "--user", "admin", "--uninstall", "Some_1.0_x64__abc"]
    )
    assert code == 0
    assert "Some_1.0_x64__abc" in RECEIVED["deleted"]
    assert "Removed" in capsys.readouterr().out


def test_cli_rejects_an_empty_uninstall_target(stub: str, monkeypatch, capsys):
    """An empty value used to fall through to the install branch and crash."""
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    assert main(["--device", stub, "--user", "admin", "--uninstall", "  "]) == 1
    assert "needs a PackageFullName" in capsys.readouterr().err


def test_cli_can_skip_waiting(stub: str, package: Path, monkeypatch, capsys):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    code = main(
        ["--device", stub, "--user", "admin", "--package", str(package), "--no-wait"]
    )
    assert code == 0
    assert "not waiting" in capsys.readouterr().out


def test_cli_reports_an_install_that_never_finishes(
    stub: str, package: Path, monkeypatch, capsys
):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    RECEIVED["state_status"] = 204  # still running, forever
    code = main(
        [
            "--device", stub, "--user", "admin",
            "--package", str(package), "--timeout", "1",
        ]
    )
    assert code == 1
    assert "Still installing" in capsys.readouterr().out


def test_cli_reports_an_unreachable_device(
    tmp_path: Path, package: Path, monkeypatch, capsys
):
    monkeypatch.setenv("OPENAPPX_DEVICE_PASSWORD", "hunter2")
    code = main(
        ["--device", "http://127.0.0.1:1", "--user", "admin", "--package", str(package)]
    )
    assert code == 1
    assert "cannot reach" in capsys.readouterr().err


def test_tls_context_disables_verification_explicitly():
    """Built from the public ssl API, so what is switched off is visible."""
    import ssl

    context = DevicePortal._tls_context()
    assert context.check_hostname is False
    assert context.verify_mode == ssl.CERT_NONE
