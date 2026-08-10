"""Scanner plugin registry.

Registration is explicit rather than magic: plugins are imported and registered at
the bottom of this module. A security tool should not discover and execute code
based on what happens to be installed.
"""

from __future__ import annotations

from cyberops_kit.config import Settings
from cyberops_kit.core.models import ProjectProfile
from cyberops_kit.scanners.base import ScannerPlugin

_REGISTRY: dict[str, ScannerPlugin] = {}


def register(plugin: ScannerPlugin) -> ScannerPlugin:
    """Add a plugin to the registry.

    Args:
        plugin: The plugin instance to register.

    Returns:
        The same plugin, so this can be used inline at module scope.

    Raises:
        ValueError: A plugin with the same name is already registered.
    """
    if plugin.name in _REGISTRY:
        msg = f"scanner {plugin.name!r} is already registered"
        raise ValueError(msg)
    _REGISTRY[plugin.name] = plugin
    return plugin


def get(name: str) -> ScannerPlugin | None:
    """Look up a plugin by name.

    Args:
        name: Plugin name.

    Returns:
        The plugin, or ``None`` when it is not registered.
    """
    return _REGISTRY.get(name.lower())


def all_plugins() -> list[ScannerPlugin]:
    """Return every registered plugin in deterministic name order.

    Returns:
        All registered plugins, sorted by name.
    """
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]


def select(settings: Settings, profile: ProjectProfile) -> list[ScannerPlugin]:
    """Choose the plugins to run for a given project.

    A plugin runs when it is enabled in config *and* relevant to the detected
    profile. Ordering is by name so that two runs schedule the same work in the same
    order (INV-3).

    Args:
        settings: Resolved configuration.
        profile: The detected project profile.

    Returns:
        The plugins to execute.
    """
    return [
        plugin
        for plugin in all_plugins()
        if settings.scanner_enabled(plugin.name) and plugin.applies_to(profile)
    ]


def unregister_all() -> None:
    """Empty the registry. Used by tests that register fakes."""
    _REGISTRY.clear()


def _install_builtin_plugins() -> None:
    """Import and register the built-in plugins.

    Imported inside a function to keep module import order explicit and to avoid a
    circular import at package load time.
    """
    from cyberops_kit.scanners import (
        gitleaks,
        osv,
        scorecard,
        semgrep,
        slsa,
        syft,
        trivy,
    )

    for module in (scorecard, osv, semgrep, gitleaks, trivy, syft, slsa):
        register(module.PLUGIN)


_install_builtin_plugins()
