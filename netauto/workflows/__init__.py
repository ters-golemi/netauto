"""Workflows: multi-step, read-only pipelines over a platform's devices.

Two per supported platform. The configuration check pulls a device's
configuration and show output, compares both against the vendor-guide ruleset
and reports what to improve; the documentation maker does all of that and then
writes an editable Word document with a topology diagram in it.

Nothing here can change a device. Workflows use the same drivers and the same
read-only command guard as everything else, and the command sets live in
spec.py as reviewable data.
"""

from netauto.workflows.runner import (
    DONE,
    FAILED,
    PENDING,
    RUNNING,
    SKIPPED,
    DeviceResult,
    Run,
    RunStore,
    StepState,
    WorkflowService,
)
from netauto.workflows.spec import (
    CONFIG_CHECK,
    DOCUMENTATION,
    KIND_NAMES,
    REGISTRY,
    WorkflowSpec,
    for_platform,
    get,
)

__all__ = [
    "CONFIG_CHECK", "DOCUMENTATION", "KIND_NAMES", "REGISTRY", "WorkflowSpec",
    "for_platform", "get",
    "DeviceResult", "Run", "RunStore", "StepState", "WorkflowService",
    "PENDING", "RUNNING", "DONE", "SKIPPED", "FAILED",
]
