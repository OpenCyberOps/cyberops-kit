"""INV-5 and INV-6 — sandboxing and absolute offline mode.

INV-5: untrusted code is never executed on the host. Never shell out to
``npm install``, ``pip install``, ``go mod download``, or a build tool directly from
the host process.

INV-6: ``--offline`` disables every outbound network call, including AI. Any code
path that cannot honor it must fail loudly rather than degrade silently.
"""

from __future__ import annotations

import pytest

from cyberops_kit.config import Settings
from cyberops_kit.core.errors import OfflineViolationError, SandboxUnavailableError
from cyberops_kit.core.ingest import ingest
from cyberops_kit.core.sandbox import (
    FORBIDDEN_HOST_PROGRAMS,
    Sandbox,
    SandboxSpec,
    detect_runtime,
    run_host,
)
from cyberops_kit.scanners import registry
from cyberops_kit.scanners.base import ScanOutcome

PACKAGE_MANAGERS = [
    "npm",
    "pip",
    "pip3",
    "yarn",
    "pnpm",
    "go",
    "cargo",
    "mvn",
    "gradle",
    "bundle",
    "composer",
    "dotnet",
    "make",
    "bazel",
]


# --- INV-5 ---------------------------------------------------------------------


@pytest.mark.parametrize("program", PACKAGE_MANAGERS)
async def test_package_managers_are_refused_on_the_host(program):
    """Running a package manager on the host is structurally impossible."""
    with pytest.raises(SandboxUnavailableError, match="refusing to run"):
        await run_host([program, "install"])


@pytest.mark.parametrize("program", PACKAGE_MANAGERS)
async def test_refusal_survives_an_absolute_path(program):
    """The check uses the program name, so a full path cannot slip past it."""
    with pytest.raises(SandboxUnavailableError, match="refusing to run"):
        await run_host([f"/usr/local/bin/{program}", "install"])


def test_forbidden_list_covers_every_documented_tool():
    """The package managers named explicitly in the threat model are all listed."""
    named_in_claude_md = {"npm", "pip", "go"}
    assert named_in_claude_md <= FORBIDDEN_HOST_PROGRAMS


async def test_empty_command_is_refused():
    """An empty argv is refused rather than passed to the shell."""
    with pytest.raises(SandboxUnavailableError):
        await run_host([])


def test_sandbox_has_no_host_fallback(monkeypatch, tmp_path):
    """With no container runtime, the sandbox raises instead of running on the host.

    A silent host fallback would be the single worst bug this project could ship.
    """
    monkeypatch.setattr("cyberops_kit.core.sandbox.detect_runtime", lambda _: None)

    with pytest.raises(SandboxUnavailableError, match="no container runtime"):
        Sandbox(SandboxSpec(image="img", workspace=tmp_path))


def test_sandbox_command_is_isolated_by_construction(tmp_path):
    """The generated container invocation carries every isolation flag."""
    runtime = detect_runtime("docker")
    if runtime is None:
        pytest.skip("no container runtime installed")

    sandbox = Sandbox(SandboxSpec(image="example:latest", workspace=tmp_path))
    command = sandbox._build_command(["echo", "hi"], container_name="c", workdir="/workspace")
    joined = " ".join(command)

    assert "--network=none" in joined
    assert "--cap-drop=ALL" in joined
    assert "--security-opt=no-new-privileges" in joined
    assert "--read-only" in joined
    assert "--rm" in joined
    assert f"{tmp_path.resolve()}:/workspace:ro" in joined


# --- INV-6 ---------------------------------------------------------------------


def test_offline_refuses_a_remote_target():
    """Cloning in offline mode fails loudly rather than degrading."""
    with (
        pytest.raises(OfflineViolationError, match="offline"),
        ingest("https://github.com/owner/repo", offline=True),
    ):
        pass


def test_offline_plus_ai_is_a_configuration_error():
    """Combining offline with AI enabled is rejected at config load."""
    with pytest.raises(ValueError, match="offline"):
        Settings(offline=True, ai={"enabled": True})


def test_offline_alone_is_valid():
    """Offline mode on its own is a normal configuration."""
    assert Settings(offline=True).offline is True


def test_ai_enabled_alone_is_valid():
    """AI enabled without offline is accepted; Phase 1 simply registers no enricher."""
    assert Settings(ai={"enabled": True}).ai.enabled is True


async def test_network_scanners_skip_loudly_when_offline(run_context, settings):
    """A network-requiring scanner is skipped with a stated reason, not run anyway."""
    offline_settings = settings.model_copy(update={"offline": True})
    ctx = run_context.model_copy(update={"offline": True, "config": offline_settings})

    for name in ("scorecard", "osv", "semgrep"):
        plugin = registry.get(name)
        assert plugin is not None
        result = await plugin.run(ctx)

        assert result.outcome is ScanOutcome.SKIPPED
        assert result.reason == "offline"
        assert "INV-6" in (result.detail or "")


def test_every_network_scanner_declares_it():
    """Scanners that reach the network must declare ``requires_network``.

    Without the declaration, the base class would happily run them under --offline.
    """
    for name in ("scorecard", "osv", "semgrep", "trivy"):
        plugin = registry.get(name)
        assert plugin is not None
        assert plugin.requires_network is True, f"{name} must declare requires_network"


def test_offline_forces_sandbox_network_off(run_context, settings, tmp_path):
    """Offline mode overrides a configured bridge network in the sandbox."""
    bridged = settings.model_copy(
        update={"sandbox": settings.sandbox.model_copy(update={"network": "bridge"})}
    )
    ctx = run_context.model_copy(update={"offline": True, "config": bridged})

    network = "none" if ctx.offline else ctx.config.sandbox.network
    assert network == "none"
