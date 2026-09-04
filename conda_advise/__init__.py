"""Advisory awareness for conda environments."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import AdvisoryReport

try:
    from ._version import __version__
except ImportError:  # pragma: no cover
    __version__ = "0.0.0.dev0"

__all__ = ["AdvisoryReport", "__version__"]


def __getattr__(name: str) -> object:
    if name == "AdvisoryReport":
        from .models import AdvisoryReport

        return AdvisoryReport
    raise AttributeError(name)
