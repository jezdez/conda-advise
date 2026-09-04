"""Validate the release conda package path."""

from __future__ import annotations

import os
import sys
from pathlib import Path


def main() -> None:
    output_dir = Path(sys.argv[1]).resolve()
    version = os.environ.get("CONDA_ADVISE_VERSION")
    if not version:
        raise SystemExit("CONDA_ADVISE_VERSION is required")
    candidates = tuple(output_dir.rglob("conda-advise-*.conda")) + tuple(
        output_dir.rglob("conda-advise-*.tar.bz2")
    )
    expected = tuple(
        path for path in candidates if path.name.startswith(f"conda-advise-{version}-")
    )
    if len(expected) != 1:
        names = ", ".join(path.name for path in expected) or "none"
        raise SystemExit(f"expected one conda-advise {version} package, found {names}")
    package = expected[0]
    if package.parent.name != "noarch":
        raise SystemExit(f"expected a noarch package, found {package}")
    print(package)


if __name__ == "__main__":
    main()
