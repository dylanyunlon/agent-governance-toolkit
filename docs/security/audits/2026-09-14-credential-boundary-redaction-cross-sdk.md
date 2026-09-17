---
title: "2026-09-14 — Credential Boundary Redaction (Cross-SDK)"
last_reviewed: 2026-09-14
owner: agt-maintainers
---

# 2026-09-14 — Credential Boundary Redaction (Cross-SDK)

Issue: [microsoft/agent-governance-toolkit#3933](https://github.com/microsoft/agent-governance-toolkit/issues/3933)

## What changed and why

`McpCredentialRedactor` (C#), `AuditLogger` (TypeScript), `CredentialRedactor`
(Python), and the Rust `CredentialRedactor` all contained credential-detection
patterns for GitHub, OpenAI, AWS, and Google API tokens with incorrect boundary
anchors. The anchors treated `_` (and, for some patterns, `-`) as a
boundary-blocking character, so a valid secret glued to a preceding or following
word character via `_` — the way rotation notes, environment prefixes, and
config-file annotations actually annotate secrets — passed through completely
unredacted.

Concrete shapes that were missed:

- Right-edge: `AKIAIOSFODNN7EXAMPLE_old`, `ghp_XXXX_deprecated`,
  `AIzaXXXX_rotated`
- Left-edge: `session_AKIAIOSFODNN7EXAMPLE`, `env_ghp_XXXX`,
  `svc_AIzaXXXX`
- Both: `old_AKIAIOSFODNN7EXAMPLE_new`

### Per-SDK root cause and fix

| SDK | Left anchor defect | Right anchor defect | Fix applied |
|-----|-------------------|-------------------|-------------|
| C# | `_` in lookaround exclusion set for GitHub/OpenAI | `\b` for AWS/Google (treats `_` as word char) | Alphanumeric-only `(?<![A-Za-z0-9])` / `(?![A-Za-z0-9])` lookaround. Google tail uses strict superset `(?:(?![A-Za-z0-9])|(?<=-))` to preserve the old `\b` shape for keys ending in `-`. |
| TypeScript | Same as C# (copy-pasted patterns) | Same as C# | Same fix as C#. |
| Python | Left anchor was already correct (`(?<![A-Za-z0-9])`) | `\b` for AWS, Google, Stripe; GitHub lookahead included `_` | Right anchor migrated to `(?![A-Za-z0-9])`. Google tail already had strict superset anchor. |
| Rust | `is_left_boundary_char` included `_` for GitHub | `is_right_boundary_char` returned `false` for all non-Slack kinds, so right boundary was never enforced | `is_left_boundary_char` now rejects only ASCII alphanumerics. `is_right_boundary_char` now rejects ASCII alphanumerics for all kinds (plus `-` for Slack). |

### OpenAI left-edge widening (C# and TypeScript only)

The C# and TypeScript OpenAI patterns previously used `(?<![A-Za-z0-9_-])`
which excluded both `_` and `-` from the left boundary. The fix removed both,
aligning with the Python SDK which has always used `(?<![A-Za-z0-9])`. This
means kebab identifiers like `my-sk-aaaa…` are now matched in C# and TypeScript
where they were previously skipped. This is intentional: a real secret preceded
by a `-` separator (e.g. `env-sk-…`) must be detected, and the Python SDK has
accepted this trade-off since its initial implementation.

Additionally, the `content_scanner.py` SSN pattern in `agent-rag-governance`
was updated from `\b\d{3}-\d{2}-\d{4}\b` (dash-only, `\b`-anchored) to
`(?<![A-Za-z0-9])\d{3}[\s.-]\d{2}[\s.-]\d{4}(?![A-Za-z0-9])` to match the
separator forms (`credential_redactor.py` already accepted) and use the
consistent lookaround anchor (issue #3815).

## Threat model impact

This change strengthens credential detection across all language SDKs and does
not introduce a new external attack surface. It touches only boundary-anchor
logic in detection patterns.

| Dimension | Direction |
|---|---|
| Right-edge detection | **Strengthened** in C#, TypeScript, and Python. Rust right boundary was previously unenforced for non-Slack kinds; now enforced. |
| Left-edge detection | **Strengthened** in C#, TypeScript, and Rust. Python left anchor was already correct. |
| False-positive surface | **Widened slightly** for OpenAI in C# and TypeScript: kebab identifiers like `my-sk-…` are now matched (aligned with Python). Unchanged for all other patterns. |
| Cross-SDK consistency | **Improved.** All four SDKs now use alphanumeric-only left boundary. Right boundary is now enforced in Rust (previously absent for non-Slack). |
| SSN detector parity | **Strengthened.** `content_scanner.py` now matches the same separator forms as `credential_redactor.py`, closing the detection-disagreement gap described in #3815. |
| Log and audit exposure | **Unchanged.** No raw secret values are exposed in any new code path. |

### Known limitations

- The Bearer token and JWT patterns in `credential_redactor.py` still use
  a trailing `\b`. Their value classes do not include `_`, so the practical
  impact is minimal, but they are inconsistent with the other patterns.
  A follow-up can align them.

## Test coverage

- **C# `McpCredentialRedactorTests.cs`**: right-edge, left-edge, both-edges,
  multi-credential, still-rejects-alphanumeric, SlackToken-unchanged, and
  Google-key-ending-in-hyphen tests for all four affected patterns.
- **C# `McpResponseSanitizerTests.cs`**: end-to-end pipeline tests verifying
  glued credentials are caught by `ScanText`.
- **TypeScript `policy-audit.test.ts`**: boundary tests for GitHub, AWS,
  Google, and OpenAI tokens through the `AuditLogger.sanitizeValue` pipeline.
- **Rust `redactor.rs` (inline tests)**: left-edge, right-edge, both-edges,
  multi-credential, and still-rejects-alphanumeric tests; updated
  `prefix_ghp_` test to assert detection (behaviour change from bug fix).
- **Python `test_credential_redactor.py`**: right-edge `_old` tests for
  GitHub, AWS, Google, OpenAI, and Stripe; multi-credential single-pass;
  false-positive guard; trailing-bare-underscore for GitHub.
- **Python `test_content_scanner.py`**: SSN dash, space, dot separator tests;
  underscore-glued SSN; bare-nine-digit rejection.
- **Source-level regression guard** (`test_regression_credential_boundary.py`):
  scans all four SDK source files for `\b` near bounded-token patterns and
  for `_` inside lookaround character classes. The guard regex covers both
  lookbehind (`(?<!`) and lookahead (`(?!`) forms.
