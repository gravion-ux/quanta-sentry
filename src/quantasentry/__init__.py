"""QuantaSentry: cryptographic inventory and post-quantum migration readiness.

Public API
----------
``inventory``         algorithm references found under a path
``inventory_report``  inventory with scan counts and a per-algorithm summary
"""
from .inventory import EXTENSIONS, IGNORED_DIRS, PATTERNS, inventory, inventory_report

__all__ = [
    "EXTENSIONS",
    "IGNORED_DIRS",
    "PATTERNS",
    "__version__",
    "inventory",
    "inventory_report",
]

__version__ = "0.2.0"
