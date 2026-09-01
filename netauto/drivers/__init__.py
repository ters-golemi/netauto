"""Driver registry.

Platform strings in the inventory resolve to driver classes here. Vendor SDKs
are imported lazily inside each driver module so that a missing optional
dependency only breaks the platform that needs it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable

from netauto.errors import UnsupportedPlatform

if TYPE_CHECKING:
    from netauto.drivers.base import Driver


def _napalm(name: str) -> Callable[[], type["Driver"]]:
    def loader() -> type["Driver"]:
        from netauto.drivers.napalm_driver import make_napalm_driver

        return make_napalm_driver(name)

    return loader


def _module(path: str, attr: str) -> Callable[[], type["Driver"]]:
    def loader() -> type["Driver"]:
        import importlib

        return getattr(importlib.import_module(path), attr)

    return loader


#: platform string -> lazy loader returning a Driver subclass
REGISTRY: dict[str, Callable[[], type["Driver"]]] = {
    # Cisco -- CLI/NETCONF via napalm
    "cisco_ios": _napalm("ios"),
    "cisco_xe": _napalm("ios"),
    "cisco_nxos": _napalm("nxos_ssh"),
    "cisco_xr": _napalm("iosxr"),
    "arista_eos": _napalm("eos"),
    # Juniper -- NETCONF via napalm/PyEZ
    "juniper_junos": _napalm("junos"),
    # HPE Aruba
    "aruba_aoscx": _module("netauto.drivers.aoscx_driver", "AosCxDriver"),
    "aruba_osswitch": _module("netauto.drivers.netmiko_driver", "ArubaOsSwitchDriver"),
    "aruba_central": _module("netauto.drivers.central_driver", "ArubaCentralDriver"),
    # Cloud-managed
    "meraki": _module("netauto.drivers.meraki_driver", "MerakiDriver"),
    # Fortinet
    "fortinet_fortios": _module("netauto.drivers.fortios_driver", "FortiOsDriver"),
    "fortinet_cli": _module("netauto.drivers.netmiko_driver", "FortinetCliDriver"),
}


def get_driver_class(platform: str) -> type["Driver"]:
    """Resolve a platform string to a driver class."""
    try:
        loader = REGISTRY[platform]
    except KeyError:
        raise UnsupportedPlatform(
            f"No driver for platform {platform!r}. Supported: {', '.join(sorted(REGISTRY))}."
        ) from None
    return loader()


def supported_platforms() -> list[str]:
    return sorted(REGISTRY)
