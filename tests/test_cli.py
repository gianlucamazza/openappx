"""The command-line entry points.

These were the only modules with no tests at all, which is backwards: they are
the surface every user touches, and the dispatcher's lazy imports mean a typo in
one subcommand stays invisible until someone runs it.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from openappx.cli import main as cli_main
from openappx.pack import main as pack_main
from openappx.validate import main as validate_main

REPO = Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "examples" / "minimal-layout"
RESOURCE_ONLY = REPO / "examples" / "resource-only"

SUBCOMMANDS = ("pack", "bundle", "unpack", "sign", "validate", "inspect", "deploy")


def test_bare_invocation_prints_usage_and_fails(capsys):
    assert cli_main([]) == 2
    assert "usage: openappx" in capsys.readouterr().out


def test_help_succeeds(capsys):
    assert cli_main(["--help"]) == 0
    out = capsys.readouterr().out
    for command in SUBCOMMANDS:
        assert command in out, command


def test_unknown_command_is_rejected(capsys):
    assert cli_main(["frobnicate"]) == 2
    assert "unknown command" in capsys.readouterr().err


@pytest.mark.parametrize("command", SUBCOMMANDS)
def test_every_advertised_subcommand_is_importable(command):
    """The dispatcher imports lazily, so a broken module hides until invoked."""
    with pytest.raises(SystemExit) as exit_info:
        cli_main([command, "--help"])
    assert exit_info.value.code == 0


def test_dispatcher_routes_to_pack(tmp_path: Path, capsys):
    out = tmp_path / "x.msix"
    assert cli_main(["pack", "--root", str(EXAMPLE), "--out", str(out)]) == 0
    assert zipfile.is_zipfile(out)


def test_dispatcher_routes_to_validate(capsys):
    assert cli_main(["validate", "--root", str(RESOURCE_ONLY)]) == 0
    assert "OK" in capsys.readouterr().out


# --- validate CLI ---------------------------------------------------------


def test_validate_reports_problems_and_fails(tmp_path: Path, capsys):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a"/></Package>', encoding="utf-8"
    )
    assert validate_main(["--root", str(layout)]) == 1
    assert "FAIL" in capsys.readouterr().err


def test_validate_rejects_a_non_directory(tmp_path: Path, capsys):
    assert validate_main(["--root", str(tmp_path / "absent")]) == 2
    assert "not a directory" in capsys.readouterr().err


# --- pack CLI -------------------------------------------------------------


def test_pack_refuses_a_bad_layout_unless_allowed(tmp_path: Path, capsys):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/>'
        '<Applications><Application Id="x" Executable="missing.exe"/></Applications>'
        "</Package>",
        encoding="utf-8",
    )
    out = tmp_path / "x.msix"

    assert pack_main(["--root", str(layout), "--out", str(out)]) == 2
    assert "Layout validation failed" in capsys.readouterr().err
    assert not out.exists()

    assert pack_main(["--root", str(layout), "--out", str(out), "--allow-missing"]) == 0
    assert "warning:" in capsys.readouterr().err
    assert out.is_file()


def test_pack_rejects_a_root_that_is_not_a_directory(tmp_path: Path, capsys):
    code = pack_main(
        ["--root", str(tmp_path / "absent"), "--out", str(tmp_path / "x.msix")]
    )
    assert code == 2
    assert "not a directory" in capsys.readouterr().err


def test_pack_reports_an_empty_layout(tmp_path: Path, capsys):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "AppxManifest.xml").write_text(
        '<Package><Identity Name="a" Publisher="CN=b" Version="1.0.0.0"/></Package>',
        encoding="utf-8",
    )
    (layout / "AppxManifest.xml").unlink()
    assert pack_main(["--root", str(layout), "--out", str(tmp_path / "x.msix")]) == 2


def test_pack_reports_runtime_failures_as_exit_1(tmp_path: Path, capsys):
    """A layout that validates but cannot be packed: the output path is a directory."""
    out = tmp_path / "blocked"
    out.mkdir()
    code = pack_main(["--root", str(RESOURCE_ONLY), "--out", str(out)])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_bundle_reports_a_corrupt_input_without_traceback(tmp_path: Path, capsys):
    broken = tmp_path / "broken.msix"
    broken.write_bytes(b"not a zip")
    from openappx.bundle import main as bundle_main

    code = bundle_main(
        ["--package", str(broken), "--out", str(tmp_path / "out.msixbundle")]
    )
    assert code == 2
    assert "error:" in capsys.readouterr().err
