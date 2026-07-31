"""The makemsix backend, exercised against a stub binary.

The real `makemsix` needs a C++ build that upstream's own bootstrap script warns
may fail, so it is almost never present. A stub proves the parts we control:
which arguments we pass, and how failures surface.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from openappx.pack import default_makemsix
from openappx.pack import main as pack_main
from openappx.pack_core import pack_makemsix

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"


def make_stub(path: Path, *, exit_code: int = 0, produce_output: bool = True) -> Path:
    """A fake makemsix that records its argv and optionally writes the package."""
    log = path.with_suffix(".log")
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, pathlib\n"
        f"pathlib.Path({str(log)!r}).write_text(' '.join(sys.argv[1:]))\n"
        + (
            "args = sys.argv[1:]\n"
            "out = args[args.index('-p') + 1]\n"
            "pathlib.Path(out).write_bytes(b'PK\\x03\\x04stub')\n"
            if produce_output
            else ""
        )
        + f"sys.exit({exit_code})\n",
        encoding="utf-8",
    )
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return log


@pytest.fixture
def stub(tmp_path: Path):
    binary = tmp_path / "makemsix"

    def build(**kwargs) -> tuple[Path, Path]:
        return binary, make_stub(binary, **kwargs)

    return build


def test_passes_only_the_directory_and_package_arguments(tmp_path: Path, stub):
    binary, log = stub()
    out = pack_makemsix(EXAMPLE, tmp_path / "out.msix", binary)
    recorded = log.read_text().split()

    assert recorded[0] == "pack"
    assert "-d" in recorded and "-p" in recorded
    # upstream accepts nothing else: no certificate flags may creep back in
    assert not {"-c", "-b"} & set(recorded)
    assert out.is_file()


def test_failure_surfaces_the_tool_output(tmp_path: Path, stub):
    binary, _log = stub(exit_code=3, produce_output=False)
    with pytest.raises(RuntimeError, match="makemsix failed \\(3\\)"):
        pack_makemsix(EXAMPLE, tmp_path / "out.msix", binary)


def test_silent_success_without_a_package_is_an_error(tmp_path: Path, stub):
    """Exit code 0 is not proof: check the file actually appeared."""
    binary, _log = stub(exit_code=0, produce_output=False)
    with pytest.raises(RuntimeError, match="reported success but"):
        pack_makemsix(EXAMPLE, tmp_path / "out.msix", binary)


def test_existing_output_is_replaced(tmp_path: Path, stub):
    binary, _log = stub()
    out = tmp_path / "out.msix"
    out.write_bytes(b"stale")
    pack_makemsix(EXAMPLE, out, binary)
    assert out.read_bytes() != b"stale"


def test_cli_reports_a_missing_binary(tmp_path: Path, capsys):
    code = pack_main(
        [
            "--root",
            str(EXAMPLE),
            "--out",
            str(tmp_path / "out.msix"),
            "--backend",
            "makemsix",
            "--makemsix",
            str(tmp_path / "absent"),
        ]
    )
    assert code == 2
    assert "makemsix not found" in capsys.readouterr().err


def test_cli_uses_the_backend_when_present(tmp_path: Path, stub, capsys):
    binary, log = stub()
    code = pack_main(
        [
            "--root",
            str(EXAMPLE),
            "--out",
            str(tmp_path / "out.msix"),
            "--backend",
            "makemsix",
            "--makemsix",
            str(binary),
        ]
    )
    assert code == 0
    assert "backend=makemsix" in capsys.readouterr().out
    assert log.read_text().startswith("pack")


def test_signing_flags_are_refused_outright(tmp_path: Path, capsys):
    """No backend can sign during pack; `openappx sign` does it afterwards."""
    code = pack_main(
        [
            "--root",
            str(EXAMPLE),
            "--out",
            str(tmp_path / "out.msix"),
            "--cert",
            "whatever.pfx",
        ]
    )
    assert code == 2
    assert "signing is not implemented" in capsys.readouterr().err


def test_default_binary_location_is_searched(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert default_makemsix().name == "makemsix"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_stub_is_executable(tmp_path: Path, stub):
    binary, _log = stub()
    assert os.access(binary, os.X_OK)
