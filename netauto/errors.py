"""Exception hierarchy.

Every failure that crosses the MCP boundary is one of these, so the server can
turn it into a useful message instead of leaking a vendor traceback.
"""


class NetautoError(Exception):
    """Base for every error this package raises."""


class DriverError(NetautoError):
    """A driver failed to talk to a device."""


class AuthError(DriverError):
    """Credentials were missing, rejected, or incomplete."""


class UnsupportedPlatform(NetautoError):
    """No driver is registered for the requested platform."""


class UnsafeCommand(NetautoError):
    """A command was rejected because it is not on the read-only allowlist."""


class WriteDisabled(NetautoError):
    """A write was attempted while allow_writes is false."""
