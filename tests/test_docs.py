"""Documentation claims that can rot silently.

Docs here make specific, checkable promises — command names, file paths, error
codes. Each one that drifts sends someone down a wrong path, so the cheap ones
are asserted rather than trusted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
# CLAUDE.md is deliberately absent from the sdist — it addresses an agent
# working in the checkout, not someone installing the package — so the list is
# filtered rather than fixed. Everything else here must exist: MANIFEST.in ships
# it precisely so this suite can run from an unpacked sdist.
DOCS = [
    doc
    for doc in sorted(REPO.glob("docs/*.md"))
    + [
        REPO / "README.md",
        REPO / "CHANGELOG.md",
        REPO / "CONTRIBUTING.md",
        REPO / "SECURITY.md",
        REPO / "CLAUDE.md",
    ]
    if doc.is_file()
]

SUBCOMMANDS = {
    "pack",
    "bundle",
    "unpack",
    "sign",
    "validate",
    "inspect",
    "deploy",
}


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_relative_links_resolve(doc: Path):
    """A dead link in a README is a small lie that compounds."""
    for target in re.findall(r"\]\((?!https?://|#)([^)]+)\)", doc.read_text()):
        path = (doc.parent / target.split("#")[0]).resolve()
        assert path.exists(), f"{doc.name} links to missing {target}"


def invocations(text: str) -> set[str]:
    """Commands actually invoked: inside a fenced block, or in backticks.

    Prose mentions ("openappx builds, signs and inspects packages") start a line
    the same way, so only fenced content and inline code count.
    """
    found: set[str] = set()
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            found.update(re.findall(r"\bopenappx ([a-z][a-z-]*)", line))
    found.update(re.findall(r"`openappx ([a-z][a-z-]*)", text))
    return found


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_documented_subcommands_exist(doc: Path):
    """Nothing may advertise a command the CLI does not dispatch."""
    for command in invocations(doc.read_text()):
        assert command in SUBCOMMANDS, f"{doc.name} invokes `openappx {command}`"


def test_every_subcommand_is_documented_in_the_readme():
    readme = (REPO / "README.md").read_text()
    for command in SUBCOMMANDS:
        assert f"openappx {command}" in readme, command


def test_version_is_consistent():
    from openappx import __version__

    pyproject = (REPO / "pyproject.toml").read_text()
    assert f'version = "{__version__}"' in pyproject
    assert f"## {__version__}" in (REPO / "CHANGELOG.md").read_text()


def test_examples_referenced_by_docs_exist():
    for name in ("minimal-layout", "resource-only"):
        assert (REPO / "examples" / name / "AppxManifest.xml").is_file()


def test_error_codes_in_format_doc_match_the_signing_doc():
    """Both files quote install failures; they must not disagree."""
    format_doc = (REPO / "docs" / "format.md").read_text()
    signing_doc = (REPO / "docs" / "signing.md").read_text()

    codes = lambda text: set(re.findall(r"0x[0-9A-F]{8}", text))  # noqa: E731
    shared = codes(format_doc) & codes(signing_doc)
    assert {"0x8007000B", "0x800B0100", "0x80096010"} <= shared


def test_environment_variables_documented_are_the_ones_used():
    from openappx.deploy import PASSWORD_ENV as DEVICE_ENV
    from openappx.sign.cli import PASSWORD_ENV as PFX_ENV

    security = (REPO / "SECURITY.md").read_text()
    for name in (DEVICE_ENV, PFX_ENV, "OPENAPPX_NO_NETWORK"):
        assert name in security or name in (REPO / "CONTRIBUTING.md").read_text(), name


def test_agent_guidance_matches_ci_and_exit_code_contract():
    """Checkout-only guidance must not send maintainers down stale paths."""
    guidance_path = REPO / "CLAUDE.md"
    workflow_path = REPO / ".github" / "workflows" / "ci.yml"
    if not guidance_path.is_file() or not workflow_path.is_file():
        pytest.skip("checkout-only guidance and CI workflow are absent from sdist")
    guidance = guidance_path.read_text()
    workflow = workflow_path.read_text()
    assert "Python 3.10–3.14" in guidance
    assert "Python 3.10–3.13" not in guidance
    assert 'python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]' in workflow
    assert "`validate` returns `1`" in guidance


def test_project_classifiers_cover_the_ci_python_matrix():
    pyproject = (REPO / "pyproject.toml").read_text()
    workflow_path = REPO / ".github" / "workflows" / "ci.yml"
    if not workflow_path.is_file():
        pytest.skip("checkout-only CI workflow is absent from sdist")
    workflow = workflow_path.read_text()
    versions = re.findall(r'python-version: \["([^"]+)', workflow)
    for version in versions:
        assert f'Programming Language :: Python :: {version}' in pyproject
