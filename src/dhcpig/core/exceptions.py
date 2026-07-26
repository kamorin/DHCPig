"""Exception hierarchy for dhcpig."""


class DhcpigError(Exception):
    """Base class for all dhcpig errors."""


class Unauthorized(DhcpigError):
    """A destructive action was attempted without authorization/scope."""


class ConfigError(DhcpigError):
    """Invalid session configuration."""


class OutOfScope(DhcpigError):
    """A target address is outside the permitted scope."""


class SessionConflict(DhcpigError):
    """A session is already active (single-session guard)."""
