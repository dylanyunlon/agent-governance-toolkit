# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""End-to-end tests: govern() + BackendRegistry wiring (issue #3911).

These tests verify that BackendRegistry.register() actually affects
what govern() does — the exact gap described in #3911.
"""

import pytest

from agentmesh.governance.backend import BackendRegistry, PolicyDecisionResult
from agentmesh.governance.govern import govern, GovernanceDenied
from agentmesh.governance.policy import PolicyEngine


# ── Helpers ──────────────────────────────────────────────────

class StubBackend:
    """A test backend that allows/denies based on action name."""

    def __init__(self, name: str = "stub", allow_actions: set | None = None):
        self._name = name
        self._allow_actions = allow_actions or {"read"}
        self._calls: list[tuple[str, dict]] = []

    @property
    def name(self) -> str:
        return self._name

    def evaluate(self, action: str, context: dict) -> PolicyDecisionResult:
        self._calls.append((action, context))
        allowed = action in self._allow_actions
        return PolicyDecisionResult(
            allowed=allowed,
            reason=f"{'allowed' if allowed else 'denied'} by {self._name}",
            backend=self._name,
            latency_ms=0.1,
        )

    def healthy(self) -> bool:
        return True

    @property
    def calls(self):
        return self._calls


class UnhealthyBackend(StubBackend):
    def healthy(self) -> bool:
        return False


class CrashingBackend(StubBackend):
    def evaluate(self, action: str, context: dict) -> PolicyDecisionResult:
        raise RuntimeError("backend crashed")


def dummy_tool(**kwargs):
    return {"status": "executed", **kwargs}


BACKEND_ROUTING_POLICY = """
apiVersion: governance.toolkit/v1
name: route-to-backend
agents: ["*"]
default_action: deny
rules:
  - name: delegate-export
    condition: "action.type == 'export'"
    action: deny
    backend: stub
  - name: allow-read
    condition: "action.type == 'read'"
    action: allow
"""

DENY_ALL_POLICY = """
apiVersion: governance.toolkit/v1
name: deny-all
default_action: deny
rules: []
"""

ALLOW_ALL_POLICY = """
apiVersion: governance.toolkit/v1
name: allow-all
agents: ["*"]
default_action: allow
rules:
  - name: allow-everything
    condition: "action.type == 'read'"
    action: allow
"""


# ── Tests ────────────────────────────────────────────────────

class TestBackendDelegationViaRule:
    """A YAML rule with backend: stub delegates to the stub backend."""

    def setup_method(self):
        BackendRegistry.clear()

    def teardown_method(self):
        BackendRegistry.clear()

    def test_backend_allows_when_registered(self):
        backend = StubBackend(allow_actions={"export"})
        BackendRegistry.register(backend)

        safe = govern(dummy_tool, policy=BACKEND_ROUTING_POLICY)
        result = safe(action="export")
        assert result["status"] == "executed"
        assert len(backend.calls) == 1

    def test_backend_denies_when_registered(self):
        backend = StubBackend(allow_actions=set())  # denies everything
        BackendRegistry.register(backend)

        safe = govern(dummy_tool, policy=BACKEND_ROUTING_POLICY, on_deny=lambda d: d)
        decision = safe(action="export")
        assert decision.allowed is False
        assert "stub" in decision.reason

    def test_rule_without_backend_unaffected(self):
        """Rules without a backend field work exactly as before."""
        BackendRegistry.register(StubBackend())

        safe = govern(dummy_tool, policy=BACKEND_ROUTING_POLICY)
        result = safe(action="read")
        assert result["status"] == "executed"

    def test_unregistered_backend_falls_through_to_rule_action(self):
        """If the named backend isn't registered, the rule's own action applies."""
        # Don't register anything
        safe = govern(dummy_tool, policy=BACKEND_ROUTING_POLICY, on_deny=lambda d: d)
        decision = safe(action="export")
        assert decision.allowed is False  # rule action is deny

    def test_unhealthy_backend_denies_fail_closed(self):
        BackendRegistry.register(UnhealthyBackend())

        safe = govern(dummy_tool, policy=BACKEND_ROUTING_POLICY, on_deny=lambda d: d)
        decision = safe(action="export")
        assert decision.allowed is False
        assert "unhealthy" in decision.reason

    def test_crashing_backend_denies_fail_closed(self):
        BackendRegistry.register(CrashingBackend())

        safe = govern(dummy_tool, policy=BACKEND_ROUTING_POLICY, on_deny=lambda d: d)
        decision = safe(action="export")
        assert decision.allowed is False
        assert "errored" in decision.reason


class TestBackendFallback:
    """When no YAML rule matches, registered backends are consulted."""

    def setup_method(self):
        BackendRegistry.clear()

    def teardown_method(self):
        BackendRegistry.clear()

    def test_fallback_allows_via_backend(self):
        backend = StubBackend(allow_actions={"anything"})
        BackendRegistry.register(backend)

        safe = govern(dummy_tool, policy=DENY_ALL_POLICY)
        result = safe(action="anything")
        assert result["status"] == "executed"
        assert len(backend.calls) == 1

    def test_fallback_denies_via_backend(self):
        backend = StubBackend(allow_actions=set())
        BackendRegistry.register(backend)

        safe = govern(dummy_tool, policy=DENY_ALL_POLICY, on_deny=lambda d: d)
        decision = safe(action="anything")
        assert decision.allowed is False
        assert "stub" in decision.reason

    def test_no_backend_registered_uses_default(self):
        """Without any backend, deny-all policy just denies."""
        safe = govern(dummy_tool, policy=DENY_ALL_POLICY, on_deny=lambda d: d)
        decision = safe(action="anything")
        assert decision.allowed is False

    def test_yaml_match_takes_precedence_over_backend(self):
        """A matching YAML rule should win — backends are fallback only."""
        backend = StubBackend(allow_actions={"read"})
        BackendRegistry.register(backend)

        safe = govern(dummy_tool, policy=ALLOW_ALL_POLICY)
        result = safe(action="read")
        assert result["status"] == "executed"
        # Backend should NOT have been called — YAML matched first
        assert len(backend.calls) == 0


class TestPolicyEngineBackendDirect:
    """PolicyEngine.evaluate() backend integration without govern()."""

    def setup_method(self):
        BackendRegistry.clear()

    def teardown_method(self):
        BackendRegistry.clear()

    def test_evaluate_consults_backend_on_fallback(self):
        backend = StubBackend(allow_actions={"query"})
        BackendRegistry.register(backend)

        engine = PolicyEngine()
        engine.load_yaml(DENY_ALL_POLICY)
        decision = engine.evaluate("agent-1", {"action": {"type": "query"}})
        assert decision.allowed is True
        assert decision.metadata["backend"] == "stub"

    def test_evaluate_backend_delegation_via_rule(self):
        backend = StubBackend(allow_actions={"export"})
        BackendRegistry.register(backend)

        engine = PolicyEngine()
        engine.load_yaml(BACKEND_ROUTING_POLICY)
        decision = engine.evaluate("agent-1", {"action": {"type": "export"}})
        assert decision.allowed is True
        assert decision.matched_rule == "delegate-export"
        assert decision.metadata["backend"] == "stub"

    def test_evaluate_metadata_includes_backend_latency(self):
        backend = StubBackend(allow_actions={"export"})
        BackendRegistry.register(backend)

        engine = PolicyEngine()
        engine.load_yaml(BACKEND_ROUTING_POLICY)
        decision = engine.evaluate("agent-1", {"action": {"type": "export"}})
        assert "backend_latency_ms" in decision.metadata
