"""Exception hierarchy shared by the CLI and web layers."""


class SherlogError(Exception):
    """Base class for user-facing errors (reported without a traceback)."""


class CaseError(SherlogError):
    """A case does not exist, already exists, or is invalid."""


class EvidenceError(SherlogError):
    """Evidence could not be read or recorded."""


class ConfigError(SherlogError):
    """Configuration is missing or invalid."""
