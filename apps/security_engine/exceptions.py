"""Custom exceptions for the AI Security Engine."""


class SecurityEngineError(Exception):
    """Base exception for all security engine errors."""
    pass


class PluginError(SecurityEngineError):
    """Base exception for plugin-related errors."""
    pass


class PluginNotFoundError(PluginError):
    """Raised when a requested plugin is not registered."""

    def __init__(self, module_type: str):
        self.module_type = module_type
        super().__init__(f'No plugin found for module type: {module_type}')


class PluginRegistrationError(PluginError):
    """Raised when a plugin fails to register."""
    pass


class PluginExecutionError(PluginError):
    """Raised when a plugin fails during scan execution."""

    def __init__(self, module_type: str, detail: str = ''):
        self.module_type = module_type
        self.detail = detail
        super().__init__(f'Plugin execution failed for {module_type}: {detail}')


class ScanError(SecurityEngineError):
    """Raised when a scan operation fails."""

    def __init__(self, message: str, scan_id: str = None):
        self.scan_id = scan_id
        super().__init__(message)


class InvalidTargetError(SecurityEngineError):
    """Raised when the scan target is invalid or unsupported."""
    pass


class ConfigurationError(SecurityEngineError):
    """Raised when the engine or plugin configuration is invalid."""
    pass


class ResourceLimitExceededError(SecurityEngineError):
    """Raised when a scan exceeds resource limits (time, size, etc.)."""
    pass
