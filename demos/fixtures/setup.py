"""Create deterministic prefix, conda configuration, and cache fixtures."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
from pathlib import Path

from conda.base.context import context

from conda_advise.cache import AdvisoryCache
from conda_advise.kev import DEFAULT_KEV_URL

ARTIFACT_SHA256 = "1" * 64
ARTIFACT_MD5 = "2" * 32
PACKAGE_FILENAME = "demo-package-1.0.0-py_0.tar.bz2"


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    prefix = root / "prefix"
    metadata = prefix / "conda-meta"
    metadata.mkdir(parents=True, exist_ok=True)
    (metadata / "history").write_text("", encoding="utf-8")
    record = {
        "name": "demo-package",
        "version": "1.0.0",
        "build": "py_0",
        "build_number": 0,
        "channel": "conda-forge",
        "subdir": "noarch",
        "url": (
            "https://conda.anaconda.org/conda-forge/noarch/"
            "demo-package-1.0.0-py_0.conda"
        ),
        "fn": "demo-package-1.0.0-py_0.conda",
        "sha256": ARTIFACT_SHA256,
        "md5": ARTIFACT_MD5,
        "depends": [],
    }
    record_path = metadata / "demo-package-1.0.0-py_0.json"
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    package_bytes = _package_bytes()
    package_sha256 = hashlib.sha256(package_bytes).hexdigest()
    package_md5 = hashlib.md5(package_bytes, usedforsecurity=False).hexdigest()
    channel = root / "channel"
    noarch = channel / "noarch"
    noarch.mkdir(parents=True, exist_ok=True)
    (noarch / PACKAGE_FILENAME).write_bytes(package_bytes)
    package_record: dict[str, object] = {
        "build": "py_0",
        "build_number": 0,
        "depends": [],
        "md5": package_md5,
        "name": "demo-package",
        "noarch": "generic",
        "sha256": package_sha256,
        "size": len(package_bytes),
        "subdir": "noarch",
        "timestamp": 1788264000000,
        "version": "1.0.0",
    }
    _write_repodata(
        noarch,
        subdir="noarch",
        packages={PACKAGE_FILENAME: package_record},
    )
    _write_repodata(channel / context.subdir, subdir=context.subdir, packages={})
    (root / "fixture.json").write_text(
        json.dumps(
            {
                "channel_package": PACKAGE_FILENAME,
                "channel_sha256": package_sha256,
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    condarc = root / "condarc"
    condarc.write_text(
        "\n".join(
            (
                "plugins:",
                "  conda_advise_provider: osv",
                "  conda_advise_post_solve: warn",
                "  conda_advise_minimum_severity: high",
                "  conda_advise_timeout_seconds: 5",
                "  conda_advise_conda_forge_origins:",
                "    - https://conda.anaconda.org/conda-forge",
                "    - https://prefix.dev/conda-forge",
                "    - http://127.0.0.1:8765/channel",
                "  conda_advise_osv_url: http://127.0.0.1:8765",
                "  conda_advise_parselmouth_url: http://127.0.0.1:8765",
                "  conda_advise_basilisk_url: http://127.0.0.1:8765",
                "",
            )
        ),
        encoding="utf-8",
    )

    with AdvisoryCache() as cache:
        cache.put(
            f"kev:{DEFAULT_KEV_URL}",
            "catalog",
            {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
            positive=True,
        )

    print(prefix)


def _package_bytes() -> bytes:
    index = json.dumps(
        {
            "build": "py_0",
            "build_number": 0,
            "depends": [],
            "name": "demo-package",
            "noarch": "generic",
            "subdir": "noarch",
            "version": "1.0.0",
        },
        sort_keys=True,
    ).encode()
    files = b"share/conda-advise-demo.txt\n"
    content = b"deterministic conda-advise demonstration\n"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:bz2") as archive:
        for name, data in (
            ("info/index.json", index),
            ("info/files", files),
            ("share/conda-advise-demo.txt", content),
        ):
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            member.mtime = 0
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def _write_repodata(
    directory: Path,
    *,
    subdir: str,
    packages: dict[str, dict[str, object]],
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    payload = {
        "info": {"subdir": subdir},
        "packages": packages,
        "packages.conda": {},
        "removed": [],
        "repodata_version": 1,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    (directory / "repodata.json").write_text(encoded, encoding="utf-8")
    (directory / "current_repodata.json").write_text(encoded, encoding="utf-8")


if __name__ == "__main__":
    main()
