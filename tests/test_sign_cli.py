"""The `openappx sign` command line."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from openappx.pack_core import pack_python
from openappx.sign.digest import SIGNATURE_PART

pytest.importorskip("cryptography", reason="signing needs the optional [sign] extra")

from openappx.sign.cli import PASSWORD_ENV, main  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"
PUBLISHER = "CN=OpenAppx-Example"


@pytest.fixture
def cert(tmp_path: Path) -> Path:
    """A certificate pair, created through the CLI itself."""
    stem = tmp_path / "mycert"
    assert main(["--make-test-cert", PUBLISHER, "--cert-out", str(stem)]) == 0
    return stem


def test_make_test_cert_writes_both_files(cert: Path, capsys):
    assert cert.with_suffix(".pfx").is_file()
    assert cert.with_suffix(".cer").is_file()


def test_make_test_cert_explains_the_next_step(tmp_path: Path, capsys):
    main(["--make-test-cert", PUBLISHER, "--cert-out", str(tmp_path / "c")])
    out = capsys.readouterr().out
    assert "--install-cert" in out  # the certificate is useless until trusted


def test_signing_in_place(tmp_path: Path, cert: Path, capsys):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    assert main(["--package", str(pkg), "--pfx", str(cert.with_suffix(".pfx"))]) == 0
    with zipfile.ZipFile(pkg) as zf:
        assert SIGNATURE_PART in zf.namelist()
    assert PUBLISHER in capsys.readouterr().out


def test_signing_to_a_separate_output(tmp_path: Path, cert: Path):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    out = tmp_path / "signed.msix"
    code = main(
        [
            "--package",
            str(pkg),
            "--pfx",
            str(cert.with_suffix(".pfx")),
            "--out",
            str(out),
        ]
    )
    assert code == 0
    assert SIGNATURE_PART not in zipfile.ZipFile(pkg).namelist()  # original untouched
    assert SIGNATURE_PART in zipfile.ZipFile(out).namelist()


def test_password_is_read_from_the_environment(tmp_path: Path, monkeypatch):
    stem = tmp_path / "protected"
    monkeypatch.setenv(PASSWORD_ENV, "secret")
    assert main(["--make-test-cert", PUBLISHER, "--cert-out", str(stem)]) == 0

    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    assert main(["--package", str(pkg), "--pfx", str(stem.with_suffix(".pfx"))]) == 0


def test_publisher_mismatch_fails_with_both_names(tmp_path: Path, capsys):
    stem = tmp_path / "other"
    main(["--make-test-cert", "CN=Not-The-Publisher", "--cert-out", str(stem)])
    capsys.readouterr()

    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    code = main(["--package", str(pkg), "--pfx", str(stem.with_suffix(".pfx"))])
    err = capsys.readouterr().err
    assert code == 1
    assert PUBLISHER in err and "CN=Not-The-Publisher" in err


def test_publisher_check_can_be_overridden(tmp_path: Path):
    stem = tmp_path / "other"
    main(["--make-test-cert", "CN=Not-The-Publisher", "--cert-out", str(stem)])
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    code = main(
        [
            "--package",
            str(pkg),
            "--pfx",
            str(stem.with_suffix(".pfx")),
            "--no-publisher-check",
        ]
    )
    assert code == 0


def test_missing_arguments_are_rejected(capsys):
    with pytest.raises(SystemExit) as exit_info:
        main(["--package", "x.msix"])  # no --pfx
    assert exit_info.value.code == 2
    assert "required" in capsys.readouterr().err


def test_missing_package_is_reported(tmp_path: Path, cert: Path, capsys):
    code = main(
        [
            "--package",
            str(tmp_path / "absent.msix"),
            "--pfx",
            str(cert.with_suffix(".pfx")),
        ]
    )
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_signing_twice_is_refused(tmp_path: Path, cert: Path, capsys):
    pkg = pack_python(EXAMPLE, tmp_path / "x.msix")
    pfx = str(cert.with_suffix(".pfx"))
    assert main(["--package", str(pkg), "--pfx", pfx]) == 0
    assert main(["--package", str(pkg), "--pfx", pfx]) == 1
    assert "already carries a signature" in capsys.readouterr().err
