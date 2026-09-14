# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MCP auth method enforcement."""

import pytest
from agent_os.mcp_auth_enforcement import (
    McpAuthPolicy,
    McpServerEntry,
    AuthCheckResult,
    VALID_AUTH_METHODS,
)


class TestMcpServerEntry:
    def test_valid_entry(self):
        e = McpServerEntry(name="test", allowed_auth_methods=["oauth2", "mtls"])
        assert e.name == "test"
        assert e.require_tls is True

    def test_invalid_auth_method(self):
        with pytest.raises(ValueError, match="Invalid auth method"):
            McpServerEntry(name="test", allowed_auth_methods=["magic"])


class TestMcpAuthPolicy:
    def test_deny_none_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="none")
        assert not result.allowed
        assert "none" in result.reason.lower()

    def test_allow_oauth2_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="oauth2")
        assert result.allowed

    def test_allow_mtls_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="mtls")
        assert result.allowed

    def test_allow_bearer_by_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="bearer")
        assert result.allowed

    def test_deny_api_key_not_in_default(self):
        policy = McpAuthPolicy()
        result = policy.check("any-server", auth_method="api_key")
        assert not result.allowed

    def test_custom_default_methods(self):
        policy = McpAuthPolicy(default_allowed_methods=["api_key", "bearer"])
        assert policy.check("s", auth_method="api_key").allowed
        assert not policy.check("s", auth_method="oauth2").allowed

    def test_per_server_allowlist(self):
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="finance", allowed_auth_methods=["mtls"]),
        ])
        # mtls allowed for finance
        assert policy.check("finance", auth_method="mtls").allowed
        # oauth2 NOT allowed for finance (even though it's in default)
        assert not policy.check("finance", auth_method="oauth2").allowed

    def test_unknown_server_uses_default(self):
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="finance", allowed_auth_methods=["mtls"]),
        ])
        # Unknown server falls back to default (oauth2 allowed)
        assert policy.check("unknown", auth_method="oauth2").allowed

    def test_deny_none_can_be_disabled(self):
        policy = McpAuthPolicy(deny_none=False, default_allowed_methods=["none"])
        result = policy.check("s", auth_method="none")
        assert result.allowed

    def test_invalid_auth_method_rejected(self):
        policy = McpAuthPolicy()
        result = policy.check("s", auth_method="magic")
        assert not result.allowed
        assert "Unknown" in result.reason

    def test_tls_required(self):
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="secure", allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        # HTTPS OK
        assert policy.check("secure", auth_method="oauth2", url="https://api.example.com").allowed
        # HTTP rejected
        assert not policy.check("secure", auth_method="oauth2", url="http://api.example.com").allowed

    @pytest.mark.parametrize("require_tls", [True, False], ids=["tls-required", "tls-not-required"])
    @pytest.mark.parametrize(
        ("caller_url", "configured_url", "allowed_when_tls_required"),
        [
            pytest.param("", "", True, id="empty-caller-empty-config"),
            pytest.param("", "https://configured.example", True, id="empty-caller-https-config"),
            pytest.param("", "http://configured.example", False, id="empty-caller-http-config"),
            pytest.param("https://caller.example", "", True, id="https-caller-empty-config"),
            pytest.param(
                "https://caller.example",
                "https://configured.example",
                True,
                id="https-caller-https-config",
            ),
            pytest.param(
                "https://caller.example",
                "http://configured.example",
                True,
                id="https-caller-http-config",
            ),
            pytest.param("http://caller.example", "", False, id="http-caller-empty-config"),
            pytest.param(
                "http://caller.example",
                "https://configured.example",
                False,
                id="http-caller-https-config",
            ),
            pytest.param(
                "http://caller.example",
                "http://configured.example",
                False,
                id="http-caller-http-config",
            ),
        ],
    )
    def test_tls_enforcement_uses_caller_url_or_configured_fallback(
        self,
        require_tls,
        caller_url,
        configured_url,
        allowed_when_tls_required,
    ):
        policy = McpAuthPolicy(
            servers=[
                McpServerEntry(
                    name="secure",
                    url=configured_url,
                    allowed_auth_methods=["oauth2"],
                    require_tls=require_tls,
                ),
            ]
        )

        result = policy.check("secure", auth_method="oauth2", url=caller_url)

        expected_allowed = allowed_when_tls_required if require_tls else True
        assert result.allowed is expected_allowed

    def test_add_remove_server(self):
        policy = McpAuthPolicy()
        policy.add_server(McpServerEntry(name="new", allowed_auth_methods=["api_key"]))
        assert policy.check("new", auth_method="api_key").allowed
        policy.remove_server("new")
        # Falls back to default
        assert not policy.check("new", auth_method="api_key").allowed

    def test_result_fields(self):
        policy = McpAuthPolicy()
        result = policy.check("my-server", auth_method="oauth2")
        assert result.server_name == "my-server"
        assert result.auth_method == "oauth2"
        assert result.allowed
        assert len(result.reason) > 0

    def test_unregistered_server_with_url_still_requires_tls(self):
        # Regression for #3814: a server name absent from the allowlist used
        # to skip the TLS gate entirely, even with a plain-http URL.
        policy = McpAuthPolicy()
        result = policy.check("typo-d-server", auth_method="oauth2", url="http://mcp.internal/tools")
        assert not result.allowed
        assert "tls" in result.reason.lower()

    def test_unregistered_server_with_https_url_is_allowed(self):
        policy = McpAuthPolicy()
        result = policy.check("new-server", auth_method="oauth2", url="https://mcp.internal/tools")
        assert result.allowed

    def test_unregistered_server_default_tls_floor_can_be_disabled(self):
        policy = McpAuthPolicy(default_require_tls=False)
        result = policy.check("legacy-server", auth_method="oauth2", url="http://mcp.internal/tools")
        assert result.allowed


class TestFromYaml:
    def test_parse_yaml(self):
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  deny_none: true
  default_allowed_methods: [oauth2, mtls]
  servers:
    - name: finance-tools
      url: https://mcp.internal/finance
      allowed_auth_methods: [mtls]
      require_tls: true
    - name: public-search
      allowed_auth_methods: [oauth2, api_key]
""")
        assert policy.check("finance-tools", auth_method="mtls").allowed
        assert not policy.check("finance-tools", auth_method="oauth2").allowed
        assert policy.check("public-search", auth_method="api_key").allowed
        assert policy.check("unknown", auth_method="oauth2").allowed
        assert not policy.check("unknown", auth_method="bearer").allowed

    def test_empty_yaml(self):
        policy = McpAuthPolicy.from_yaml("")
        assert policy.check("s", auth_method="oauth2").allowed

    def test_yaml_default_require_tls_defaults_true(self):
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  default_allowed_methods: [oauth2]
""")
        result = policy.check("unregistered", auth_method="oauth2", url="http://mcp.internal/tools")
        assert not result.allowed

    def test_yaml_default_require_tls_false_disables_the_floor(self):
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  default_allowed_methods: [oauth2]
  default_require_tls: false
""")
        result = policy.check("legacy-server", auth_method="oauth2", url="http://mcp.internal/tools")
        assert result.allowed


# ---------------------------------------------------------------
# Parametrized TLS gate matrix
# Sweep all combinations of caller-URL scheme × entry-URL scheme ×
# require_tls. This is the "200-case matrix" carloshvp ran manually;
# pinning it in CI prevents regressions.
# ---------------------------------------------------------------

_TLS_SCHEMES = ("https", "wss")
_NON_TLS_SCHEMES = ("http", "ws", "ftp")


def _url(scheme: str) -> str:
    """Build a minimal valid URL for a scheme."""
    if not scheme:
        return ""
    return f"{scheme}://mcp.internal/api"


class TestTlsGateMatrix:
    """Full caller-URL × entry-URL × require_tls sweep."""

    @pytest.mark.parametrize("entry_scheme", _TLS_SCHEMES)
    def test_tls_entry_no_caller_url_allowed(self, entry_scheme):
        """TLS entry.url + no caller url → allowed."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url=_url(entry_scheme),
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2")
        assert result.allowed, f"entry={entry_scheme} should be allowed"

    @pytest.mark.parametrize("entry_scheme", _NON_TLS_SCHEMES)
    def test_non_tls_entry_no_caller_url_denied(self, entry_scheme):
        """Non-TLS entry.url + no caller url → denied."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url=_url(entry_scheme),
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2")
        assert not result.allowed, f"entry={entry_scheme} should be denied"
        assert "TLS" in result.reason

    @pytest.mark.parametrize("caller_scheme", _TLS_SCHEMES)
    @pytest.mark.parametrize("entry_scheme", _NON_TLS_SCHEMES)
    def test_tls_caller_overrides_non_tls_entry(self, caller_scheme, entry_scheme):
        """TLS caller url wins over non-TLS entry.url → allowed."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url=_url(entry_scheme),
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2", url=_url(caller_scheme))
        assert result.allowed

    @pytest.mark.parametrize("caller_scheme", _NON_TLS_SCHEMES)
    @pytest.mark.parametrize("entry_scheme", _TLS_SCHEMES)
    def test_non_tls_caller_overrides_tls_entry(self, caller_scheme, entry_scheme):
        """Non-TLS caller url wins over TLS entry.url → denied."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url=_url(entry_scheme),
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2", url=_url(caller_scheme))
        assert not result.allowed

    @pytest.mark.parametrize("entry_scheme", list(_TLS_SCHEMES) + list(_NON_TLS_SCHEMES) + [""])
    def test_require_tls_false_always_allows(self, entry_scheme):
        """require_tls=False + any scheme → allowed."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url=_url(entry_scheme) if entry_scheme else "",
                           allowed_auth_methods=["oauth2"], require_tls=False),
        ])
        result = policy.check("s", "oauth2")
        assert result.allowed

    def test_both_empty_urls_allowed_s10_12(self):
        """S10.12: both caller and entry url empty → allowed (no URL to check)."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url="",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2", url="")
        assert result.allowed


class TestTlsGateEdgeCases:
    """Edge cases not covered by the scheme matrix."""

    def test_entry_url_bare_hostname_no_scheme_denied(self):
        """A bare hostname (no scheme) is denied under require_tls."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url="mcp.internal:8443",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2")
        assert not result.allowed

    def test_entry_url_uppercase_scheme_normalized(self):
        """Scheme comparison is case-insensitive."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url="HTTPS://mcp.internal/api",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2")
        assert result.allowed

    def test_caller_url_whitespace_treated_as_present(self):
        """A caller URL containing only whitespace still has an empty scheme → denied."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url="https://mcp.internal",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2", url="  ")
        assert not result.allowed

    def test_reason_message_includes_scheme(self):
        """Denial reason must include the offending scheme for debugging."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="s", url="http://mcp.internal",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("s", "oauth2")
        assert "http" in result.reason.lower()
        assert "TLS" in result.reason

    def test_reason_message_includes_server_name(self):
        """Denial reason must include the server name."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="finance-db", url="http://mcp.internal",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        result = policy.check("finance-db", "oauth2")
        assert "finance-db" in result.reason

    def test_add_then_check_entry_url_fallback(self):
        """Dynamic add_server also benefits from entry.url fallback."""
        policy = McpAuthPolicy()
        policy.add_server(McpServerEntry(
            name="dynamic", url="http://mcp.internal",
            allowed_auth_methods=["oauth2"], require_tls=True,
        ))
        assert not policy.check("dynamic", "oauth2").allowed

    def test_remove_server_clears_entry(self):
        """After remove_server, server falls back to default policy."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="tmp", url="http://bad",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        assert not policy.check("tmp", "oauth2").allowed
        policy.remove_server("tmp")
        # Falls back to default (oauth2 is in default allowed)
        assert policy.check("tmp", "oauth2").allowed

    def test_multiple_servers_independent(self):
        """TLS decision for one server does not affect another."""
        policy = McpAuthPolicy(servers=[
            McpServerEntry(name="secure", url="https://a.internal",
                           allowed_auth_methods=["oauth2"], require_tls=True),
            McpServerEntry(name="insecure", url="http://b.internal",
                           allowed_auth_methods=["oauth2"], require_tls=True),
        ])
        assert policy.check("secure", "oauth2").allowed
        assert not policy.check("insecure", "oauth2").allowed


class TestTlsGateYamlIntegration:
    """YAML round-trip tests for the TLS gate."""

    def test_yaml_mixed_tls_servers(self):
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  servers:
    - name: prod-api
      url: https://api.prod.internal
      allowed_auth_methods: [mtls]
      require_tls: true
    - name: staging-api
      url: http://api.staging.internal
      allowed_auth_methods: [oauth2]
      require_tls: true
    - name: dev-local
      url: ""
      allowed_auth_methods: [oauth2]
      require_tls: true
    - name: monitoring
      url: http://metrics.internal
      allowed_auth_methods: [api_key]
      require_tls: false
""")
        assert policy.check("prod-api", "mtls").allowed
        assert not policy.check("staging-api", "oauth2").allowed
        assert policy.check("dev-local", "oauth2").allowed  # S10.12
        assert policy.check("monitoring", "api_key").allowed  # require_tls=false

    def test_yaml_caller_url_overrides_configured(self):
        policy = McpAuthPolicy.from_yaml("""
mcp_auth_policy:
  servers:
    - name: flexible
      url: http://mcp.internal
      allowed_auth_methods: [oauth2]
      require_tls: true
""")
        # Entry is http → denied without caller url
        assert not policy.check("flexible", "oauth2").allowed
        # Caller overrides with https → allowed
        assert policy.check("flexible", "oauth2", url="https://mcp.secure.com").allowed
