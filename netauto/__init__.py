"""Multi-vendor network automation toolkit.

Read-first by design: every driver exposes facts, configuration retrieval and
read-only command execution. Configuration changes are computed as diffs and
never committed unless writes are explicitly enabled, which no driver here
implements yet.
"""

__version__ = "0.1.0"

from netauto.errors import (
    AuthError,
    DriverError,
    NetautoError,
    UnsafeCommand,
    UnsupportedPlatform,
    WriteDisabled,
)

__all__ = [
    "__version__",
    "NetautoError",
    "DriverError",
    "AuthError",
    "UnsupportedPlatform",
    "UnsafeCommand",
    "WriteDisabled",
]
