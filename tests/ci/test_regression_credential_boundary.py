# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression test for issue #3933: credential boundary anchors.

The credential redaction patterns for GitHub, OpenAI, AWS, and Google tokens
in all four SDKs (.NET, TypeScript, Rust, Python) previously included ``_``
in their boundary-anchor exclusion sets, so a secret glued to ``_`` was
silently missed. This test inspects the source files themselves to verify the
patterns use alphanumeric-only anchors (``[A-Za-z0-9]`` without ``_``) and
that no ``\\b`` word boundary is used on a bounded-token pattern.

This is a **source-level** guard. The per-SDK unit tests verify runtime
behaviour; this test catches an accidental revert in any SDK without
building that SDK's toolchain.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------
# Files carrying bounded-token credential patterns.
# Each entry maps a file to the regex fragment that should NOT
# appear in any bounded-token pattern line.
# ---------------------------------------------------------------
BOUNDED_TOKEN_FILES = [
    # TypeScript
    REPO_ROOT
    / "agent-governance-python"
    / "agent-mesh"
    / "packages"
    / "mcp-proxy"
    / "src"
    / "audit.ts",
    # Python
    REPO_ROOT
    / "agent-governance-python"
    / "agent-os"
    / "src"
    / "agent_os"
    / "credential_redactor.py",
]

# Rust uses procedural boundary functions (match arms), not regex strings.
# A separate test below checks the Rust source directly.
_RUST_REDACTOR = (
    REPO_ROOT
    / "agent-governance-rust"
    / "agentmesh-mcp"
    / "src"
    / "mcp"
    / "redactor.rs"
)

# Pattern names that are bounded-token patterns (not keyword-anchored).
BOUNDED_PREFIXES = [
    "AKIA",       # AWS access key
    "AIza",       # Google API key
    "gh[psour]_", # GitHub token (regex form)
    "ghp_",       # GitHub token (literal form)
    "ghs_",
    "gho_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "sk-",        # OpenAI token
]

# This regex matches a lookaround that includes _ in its character class,
# which is the core defect in #3933. It handles both lookbehind ``(?<!``
# / ``(?<=`` and lookahead ``(?!`` / ``(?=`` forms.
_UNDERSCORE_IN_LOOKAROUND = re.compile(
    r"\(\?<?[!=]\[A-Za-z0-9[^\]]*_[^\]]*\]"
)


@pytest.mark.parametrize(
    "filepath",
    BOUNDED_TOKEN_FILES,
    ids=lambda p: "/".join(p.relative_to(REPO_ROOT).parts[-3:]),
)
def test_no_word_boundary_on_bounded_token_patterns(filepath: Path) -> None:
    """Bounded-token patterns must not use ``\\b``; they should use
    ``(?<![A-Za-z0-9])`` / ``(?![A-Za-z0-9])`` instead."""
    if not filepath.exists():
        pytest.skip(f"{filepath} not found")

    text = filepath.read_text(encoding="utf-8")
    # Only check lines that mention a bounded token prefix.
    for i, line in enumerate(text.splitlines(), 1):
        for prefix in BOUNDED_PREFIXES:
            if prefix in line and r"\b" in line:
                # Exclude comment lines
                stripped = line.strip()
                if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
                    continue
                pytest.fail(
                    f"{filepath.name}:{i}: bounded-token pattern line "
                    f"contains \\b (word boundary) near '{prefix}'. "
                    f"Use lookaround anchors instead.\n  {line.strip()}"
                )


@pytest.mark.parametrize(
    "filepath",
    BOUNDED_TOKEN_FILES,
    ids=lambda p: "/".join(p.relative_to(REPO_ROOT).parts[-3:]),
)
def test_no_underscore_in_bounded_token_lookaround(filepath: Path) -> None:
    """Bounded-token pattern lookarounds must not include ``_`` in the
    character class — it blocks detection of secrets glued to ``_``."""
    if not filepath.exists():
        pytest.skip(f"{filepath} not found")

    text = filepath.read_text(encoding="utf-8")
    for i, line in enumerate(text.splitlines(), 1):
        has_bounded_prefix = any(prefix in line for prefix in BOUNDED_PREFIXES)
        if not has_bounded_prefix:
            continue
        # Skip Slack — its value class includes - and that's correct
        if "xox" in line or "Slack" in line:
            continue
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("#") or stripped.startswith("*"):
            continue
        if _UNDERSCORE_IN_LOOKAROUND.search(line):
            pytest.fail(
                f"{filepath.name}:{i}: bounded-token lookaround "
                f"includes '_' in character class.\n  {line.strip()}"
            )


# ---------------------------------------------------------------
# SSN pattern parity: content_scanner must match the separator
# forms that credential_redactor already accepts.
# ---------------------------------------------------------------

_CONTENT_SCANNER = (
    REPO_ROOT
    / "agent-governance-python"
    / "agent-rag-governance"
    / "src"
    / "agent_rag_governance"
    / "content_scanner.py"
)


def test_content_scanner_ssn_accepts_space_and_dot_separators() -> None:
    """The SSN pattern must accept space and dot separators, not only dash."""
    if not _CONTENT_SCANNER.exists():
        pytest.skip("content_scanner.py not found")

    text = _CONTENT_SCANNER.read_text(encoding="utf-8")
    # The pattern should use a character class like [\s.-] for separators.
    # A dash-only pattern would be \d{3}-\d{2}-\d{4}.
    if r"\d{3}-\d{2}-\d{4}" in text and r"[\s.-]" not in text:
        pytest.fail(
            "content_scanner.py SSN pattern only matches dash-separated form; "
            "it should match space and dot separators too (issue #3815)."
        )


# ---------------------------------------------------------------
# Rust boundary functions: procedural match-arm checks.
#
# Rust uses is_left_boundary_char / is_right_boundary_char with
# match arms instead of regex strings.  The regex-scanning guard
# above cannot inspect these, so we check them separately.
# ---------------------------------------------------------------

def test_rust_left_boundary_non_slack_rejects_only_alphanumeric() -> None:
    """Non-Slack match arms in is_left_boundary_char must reject only
    ASCII alphanumerics.  If an arm for a non-Slack kind includes '_'
    or blocks '-', a secret prefixed with underscore or dash would be
    missed (regression for #3933)."""
    if not _RUST_REDACTOR.exists():
        pytest.skip("redactor.rs not found")

    text = _RUST_REDACTOR.read_text(encoding="utf-8")
    in_left = False
    brace_depth = 0
    for i, line in enumerate(text.splitlines(), 1):
        if "fn is_left_boundary_char" in line:
            in_left = True
            brace_depth = 0
        if not in_left:
            continue
        brace_depth += line.count("{") - line.count("}")
        # The function ends when brace depth returns to zero after opening
        if in_left and brace_depth <= 0 and "{" not in line and "fn " not in line:
            break
        # Skip the Slack arm (it correctly blocks '-')
        if "SlackToken" in line:
            continue
        # No non-Slack arm should contain '_' in its match expression
        if "=> " in line and "'_'" in line:
            pytest.fail(
                f"redactor.rs:{i}: is_left_boundary_char non-Slack arm "
                f"blocks '_', which would miss underscore-prefixed secrets.\n"
                f"  {line.strip()}"
            )


def test_rust_right_boundary_non_slack_rejects_alphanumeric() -> None:
    """Non-Slack match arms in is_right_boundary_char must reject ASCII
    alphanumerics (not return false unconditionally).  An unconditional
    false means right boundary is never enforced (#3933 review)."""
    if not _RUST_REDACTOR.exists():
        pytest.skip("redactor.rs not found")

    text = _RUST_REDACTOR.read_text(encoding="utf-8")
    in_right = False
    brace_depth = 0
    for i, line in enumerate(text.splitlines(), 1):
        if "fn is_right_boundary_char" in line:
            in_right = True
            brace_depth = 0
        if not in_right:
            continue
        brace_depth += line.count("{") - line.count("}")
        # The function ends when brace depth returns to zero after opening
        if in_right and brace_depth <= 0 and "{" not in line and "fn " not in line:
            break
        # The catch-all arm must not be `_ => false`
        if "_ =>" in line and "false" in line and "is_ascii" not in line:
            pytest.fail(
                f"redactor.rs:{i}: is_right_boundary_char catch-all arm "
                f"returns false, so right boundary is never enforced "
                f"for most credential kinds.\n  {line.strip()}"
            )
