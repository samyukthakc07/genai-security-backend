"""Plugin registry for discovering and managing detection plugins."""
import logging
import threading
from typing import Optional

from apps.security_engine.base import DetectionPlugin
from apps.security_engine.exceptions import PluginNotFoundError, PluginRegistrationError

logger = logging.getLogger('security_engine.registry')


class PluginRegistry:
    """Registry that manages all detection plugins.

    Plugins are discovered automatically on startup via the AppConfig.ready() method.
    Plugins can also be registered manually for testing.
    """

    def __init__(self):
        self._plugins: dict[str, DetectionPlugin] = {}
        self._initialized = False
        self._lock = threading.RLock()

    def register(self, plugin_class: type[DetectionPlugin]) -> None:
        """Register a detection plugin.

        Thread-safe: uses a lock to prevent concurrent registration.

        Args:
            plugin_class: The plugin class to register (not an instance)

        Raises:
            PluginRegistrationError: If a plugin with the same module_type already exists
        """
        # Instantiate to validate metadata
        try:
            instance = plugin_class()
        except Exception as e:
            raise PluginRegistrationError(
                f'Failed to instantiate plugin {plugin_class.__name__}: {e}'
            ) from e

        with self._lock:
            module_type = instance.module_type
            if module_type in self._plugins:
                raise PluginRegistrationError(
                    f'Duplicate plugin for module_type: {module_type} '
                    f'(existing: {self._plugins[module_type].__class__.__name__}, '
                    f'new: {plugin_class.__name__})'
                )

            self._plugins[module_type] = instance

        logger.info(
            'Registered plugin: %s (module_type=%s, version=%s)',
            instance.name, module_type, instance.version
        )

    def get_plugin(self, module_type: str) -> DetectionPlugin:
        """Get a plugin by module type.

        Args:
            module_type: The OWASP module type (e.g., 'prompt_injection')

        Returns:
            The registered plugin instance

        Raises:
            PluginNotFoundError: If no plugin is registered for module_type
        """
        plugin = self._plugins.get(module_type)
        if plugin is None:
            raise PluginNotFoundError(module_type)
        return plugin

    def get_all_plugins(self) -> dict[str, DetectionPlugin]:
        """Get all registered plugins (thread-safe copy)."""
        with self._lock:
            return dict(self._plugins)

    def get_available_modules(self) -> list[str]:
        """Get list of all registered module types."""
        with self._lock:
            return list(self._plugins.keys())

    def unregister(self, module_type: str) -> None:
        """Unregister a plugin (useful for testing)."""
        with self._lock:
            self._plugins.pop(module_type, None)

    def discover_plugins(self) -> None:
        """Auto-discover and register all DetectionPlugin subclasses.

        Thread-safe: uses a lock to prevent concurrent initialization.
        Scans all modules under apps.security_engine.plugins for
        DetectionPlugin subclasses and registers them.
        """
        with self._lock:
            if self._initialized:
                return

            import importlib
            import pkgutil

            import apps.security_engine.plugins as plugins_package

            for importer, modname, is_pkg in pkgutil.iter_modules(plugins_package.__path__):
                if modname.startswith('_'):
                    continue
                try:
                    module = importlib.import_module(f'apps.security_engine.plugins.{modname}')
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if (isinstance(attr, type)
                                and issubclass(attr, DetectionPlugin)
                                and attr is not DetectionPlugin
                                and not getattr(attr, '_is_stub', False)):
                            self.register(attr)
                except Exception as e:
                    logger.warning('Failed to load plugin module %s: %s', modname, e)

            self._initialized = True

        logger.info(
            'Plugin discovery complete. Registered %d plugins: %s',
            len(self._plugins),
            ', '.join(self._plugins.keys())
        )

    def clear(self) -> None:
        """Clear all registered plugins and reset initialization."""
        with self._lock:
            old_plugins = list(self._plugins.keys())
            self._plugins.clear()
            self._initialized = False
        logger.info('Cleared %d plugins from registry', len(old_plugins))


# Global singleton instance
plugin_registry = PluginRegistry()
