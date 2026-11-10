"""Files shipped inside the package (copies of spec/ that the code reads at run time)."""
from __future__ import annotations

import os

_HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")


def path(*parts: str) -> str:
    return os.path.join(_HERE, *parts)
