"""Exercise the installed plugin against a deterministic offline cache."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ARTIFACT_SHA256 = "1" * 64
ADVISORY_ID = "GHSA-demo-0001-0001"
MODIFIED = "2026-08-01T12:00:00Z"
COMPONENT_PURL = "pkg:pypi/demo-package@1.0.0"


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="conda-advise-package-test-"))
    os.environ["XDG_CACHE_HOME"] = str(root / "cache")
    os.environ["CONDARC"] = str(root / "condarc")
    (root / "condarc").write_text("channels:\n  - conda-forge\n", encoding="utf-8")
    prefix = root / "prefix"
    metadata = prefix / "conda-meta"
    metadata.mkdir(parents=True)
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
        "depends": [],
    }
    (metadata / "demo-package-1.0.0-py_0.json").write_text(
        json.dumps(record), encoding="utf-8"
    )

    from conda_advise.cache import AdvisoryCache
    from conda_advise.components.parselmouth import DEFAULT_PARSELMOUTH_URL
    from conda_advise.kev import DEFAULT_KEV_URL
    from conda_advise.providers.osv import DEFAULT_OSV_URL

    advisory = {
        "schema_version": "1.7.0",
        "id": ADVISORY_ID,
        "modified": MODIFIED,
        "published": "2026-07-31T12:00:00Z",
        "aliases": ["CVE-2026-0001"],
        "summary": "Deterministic package test advisory",
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        ],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo-package"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                    }
                ],
            }
        ],
        "references": [
            {
                "type": "ADVISORY",
                "url": "https://example.invalid/GHSA-demo-0001-0001",
            }
        ],
    }
    with AdvisoryCache() as cache:
        cache.put(
            f"parselmouth:{DEFAULT_PARSELMOUTH_URL}",
            ARTIFACT_SHA256,
            {
                "pypi_normalized_names": ["demo-package"],
                "versions": {"demo-package": "1.0.0"},
            },
            positive=True,
        )
        cache.put(
            f"osv.query:{DEFAULT_OSV_URL}",
            COMPONENT_PURL,
            {"vulns": [{"id": ADVISORY_ID, "modified": MODIFIED}]},
            positive=True,
        )
        cache.put(
            f"osv.detail:{DEFAULT_OSV_URL}",
            f"{ADVISORY_ID}\x1f{MODIFIED}",
            advisory,
            positive=True,
        )
        cache.put(
            f"kev:{DEFAULT_KEV_URL}",
            "catalog",
            {"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
            positive=True,
        )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "conda",
            "advise",
            "--prefix",
            str(prefix),
            "--offline",
            "--json",
        ],
        check=False,
        capture_output=True,
        env=os.environ.copy(),
        text=True,
    )
    if completed.returncode != 1:
        raise SystemExit(
            f"expected advisory exit status 1, got {completed.returncode}: "
            f"{completed.stderr}"
        )
    report = json.loads(completed.stdout)
    if report["provider"] != "osv":
        raise SystemExit("offline report did not use OSV")
    if report["summary"]["qualifying_matches"] != 1:
        raise SystemExit("offline report did not contain the cached advisory")
    if report["summary"]["incomplete"] != 0:
        raise SystemExit("offline report coverage was incomplete")


if __name__ == "__main__":
    main()
