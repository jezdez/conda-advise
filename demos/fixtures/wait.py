"""Read startup confirmation from the fixture process's private directory."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path


def wait_for_server(root: Path, pid: int) -> str:
    for _attempt in range(100):
        try:
            payload = json.loads((root / "ready.json").read_text(encoding="utf-8"))
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if payload["pid"] != pid:
            raise RuntimeError("fixture startup confirmation has the wrong process ID")
        return str(payload["url"])
    raise RuntimeError("fixture advisory server did not start")


if __name__ == "__main__":
    print(wait_for_server(Path(sys.argv[1]), int(sys.argv[2])))
