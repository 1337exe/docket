from __future__ import annotations

from pathlib import Path


def safe_join(base, rel):
    """Resolve rel inside base; None if it escapes (path traversal) or is absolute."""
    if not rel or Path(rel).is_absolute():
        return None
    base = Path(base).resolve()
    p = (base / rel).resolve()
    try:
        p.relative_to(base)
    except ValueError:
        return None
    return p
