"""AI Security Engine — detection plugin framework.

Provides the abstract base class, plugin registry, and orchestrator
for running AI security scans across all OWASP LLM modules.

Usage:
    from apps.security_engine import get_engine, get_registry

    engine = get_engine()
    registry = get_registry()
    plugin = registry.get_plugin('prompt_injection')
"""

# Lazy imports to avoid AppRegistryNotReady during Django startup.
# Django model imports happen inside the functions, not at module level.
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from apps.security_engine.engine import SecurityEngine
    from apps.security_engine.registry import PluginRegistry


def get_engine() -> 'SecurityEngine':
    """Get the global SecurityEngine singleton (lazy import)."""
    from apps.security_engine.engine import security_engine
    return security_engine


def get_registry() -> 'PluginRegistry':
    """Get the global PluginRegistry singleton (lazy import)."""
    from apps.security_engine.registry import plugin_registry
    return plugin_registry


__all__ = ['get_engine', 'get_registry']
