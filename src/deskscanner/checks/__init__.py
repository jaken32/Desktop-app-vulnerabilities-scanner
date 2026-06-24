"""Check registry. The order here defines the deterministic order in which
checks run and findings are produced (before final stable sort)."""

from __future__ import annotations

from .app_meta import AppMetaCheck
from .base import Check, CheckContext
from .dependencies import DependenciesCheck
from .electron_config import ElectronConfigCheck
from .local_api import LocalApiCheck
from .secrets import SecretsCheck
from .storage import StorageCheck

# Fixed, deterministic registration order.
ALL_CHECKS: list[type[Check]] = [
    AppMetaCheck,
    ElectronConfigCheck,
    SecretsCheck,
    DependenciesCheck,
    LocalApiCheck,
    StorageCheck,
]


def build_checks() -> list[Check]:
    return [cls() for cls in ALL_CHECKS]


__all__ = ["ALL_CHECKS", "build_checks", "Check", "CheckContext"]
