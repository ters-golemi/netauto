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


class UnsupportedOperation(NetautoError):
    """The driver has no path to what was asked, on this platform.

    Distinct from DriverError: nothing went wrong on the wire. A Meraki
    organisation has no CLI and a cloud tenant has no LLDP table, and callers
    should report that as a gap rather than as a failure.
    """


class UnsafeCommand(NetautoError):
    """A command was rejected because it is not on the read-only allowlist."""


class WriteDisabled(NetautoError):
    """A write was attempted while allow_writes is false."""
