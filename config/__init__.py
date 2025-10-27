"""Package-level configuration for the project.

This module re-exports the names from ``config.config`` so code can do either:

- ``from config.config import CA_PASSWORD`` (existing imports keep working)
- ``from config import CA_PASSWORD`` or ``import config`` (package-style)

Keep the surface area minimal and explicit.
"""
from .config import TGS_SECRET_KEY, CA_PASSWORD

__all__ = ["TGS_SECRET_KEY", "CA_PASSWORD"]
