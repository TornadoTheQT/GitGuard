"""GitGuard — a secret-scanning CLI for folders, ZIPs, and GitHub repos."""

__version__ = "0.1.0"

#: Minimum supported Python version. Single source of truth used by the CLI's
#: ``doctor`` command and the ``install.sh`` bootstrap script. Keep this in sync
#: with ``requires-python`` in ``pyproject.toml``.
REQUIRES_PYTHON = (3, 9)

#: Human-readable form, e.g. ``"3.9"`` — for help text and error messages.
REQUIRES_PYTHON_STR = ".".join(str(p) for p in REQUIRES_PYTHON)

__all__ = ["__version__", "REQUIRES_PYTHON", "REQUIRES_PYTHON_STR"]
