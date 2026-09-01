"""Opening drivers for inventory devices."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from netauto.config import Settings
from netauto.drivers import get_driver_class
from netauto.drivers.base import Driver
from netauto.inventory import Device, Inventory


@contextmanager
def connect(device: Device, settings: Settings) -> Iterator[Driver]:
    """Open a driver for one device, closing it on the way out."""
    driver_cls = get_driver_class(device.platform)
    driver = driver_cls(device, settings)
    driver.open()
    try:
        yield driver
    finally:
        driver.close()


def load_context(settings: Settings | None = None) -> tuple[Settings, Inventory]:
    """Load settings and inventory together, the usual entry point."""
    settings = settings or Settings.load()
    return settings, Inventory.load(settings.inventory_path)
