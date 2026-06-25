"""Native-engine package: scan macOS desktop apps that ship no readable bundle.

The Electron engine (``deskscanner.engine`` + ``deskscanner.checks``) is
unchanged. This package adds a platform router (:mod:`detect`) and a native /
Flutter engine that produces the *same* :class:`~deskscanner.models.Finding`
schema, severity rubric, confidence model, and report renderer.
"""

from __future__ import annotations

from .detect import EngineDetection, detect_engine

__all__ = ["EngineDetection", "detect_engine"]
