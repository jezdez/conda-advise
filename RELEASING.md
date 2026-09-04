# Releasing

Releases are built from bare version tags by the `Release` GitHub Actions workflow.
The workflow builds the wheel and source distribution once, checks their metadata and contents, installs the wheel into a clean conda-owning environment, records GitHub build provenance, and attaches those files to a draft GitHub release.
It publishes the same files to PyPI through Trusted Publishing, builds a noarch conda package from the exact published source distribution, uploads that package to the `jezdez` Anaconda.org channel, and makes the GitHub release public only after a clean channel installation succeeds.

## Repository configuration

Configure the PyPI Trusted Publisher with:

- Owner: `jezdez`
- Repository: `conda-advise`
- Workflow: `release.yml`
- Environment: `pypi`

Configure the GitHub Actions `pypi` environment to permit deployments only from version tags and require maintainer approval.
Configure the GitHub Actions `anaconda` environment with an `ANACONDA_API_KEY` secret that can upload packages to the `jezdez` Anaconda.org namespace.
Permit `anaconda` deployments only from version tags and require maintainer approval.
The workflow exposes that secret as `ANACONDA_API_TOKEN` only to the Anaconda Client upload step because that is the environment variable read by Anaconda Client.
Enable immutable GitHub releases before publishing the first version.

## Prepare a release

1. Replace the `[Unreleased]` changelog entries with a version heading and release date, then add a new empty `[Unreleased]` section.
2. Add the version and release date to `CITATION.cff`.
3. Update installation documentation only for package indexes and conda channels where the release will actually be available.
4. Merge the release preparation through review into `main`.
5. Update the local branch and record the exact commit.

```console
git switch main
git pull --ff-only
git rev-parse HEAD
```

Confirm that tests, static checks, strict documentation, link checking, examples, and distribution checks passed for that commit.

Create and push an annotated bare version tag:

```console
git tag -a 0.1.0 -m "conda-advise 0.1.0"
git push origin 0.1.0
```

The tag starts this sequence:

1. Build one wheel and one source distribution from the locked release environment.
2. Check metadata, filenames, archive contents, and the version derived from the tag.
3. Install the wheel into a clean environment containing conda and run an offline smoke scan.
4. Record GitHub build provenance for the two distributions.
5. Create a verified-tag draft GitHub release and attach the exact distributions.
6. Wait for approval of the `pypi` environment.
7. Publish the distributions and PyPI attestations through Trusted Publishing.
8. Wait for approval of the `anaconda` environment.
9. Build and test one noarch conda package from the PyPI source distribution whose SHA256 matches the source distribution built by the workflow.
10. Upload the package to the `main` label in the `jezdez` Anaconda.org namespace without a replacement flag.
11. Wait for public repodata, install the package into a clean conda environment, and repeat plugin discovery and the offline fixture scan.
12. Make the GitHub release public.

## Verify published artifacts

Download both formats from GitHub and PyPI, compare their bytes, then verify GitHub's build provenance and PyPI's publish attestations.
Replace `0.1.0` before running the commands.

```console
set -euo pipefail
release_version="0.1.0"
release_check="$(mktemp -d)"
mkdir "$release_check/github" "$release_check/pypi"
gh release download "$release_version" --repo jezdez/conda-advise \
  --dir "$release_check/github"
curl --fail --location --silent --show-error \
  "https://pypi.org/pypi/conda-advise/$release_version/json" \
  --output "$release_check/pypi.json"
wheel_url="$(jq -er \
  --arg name "conda_advise-${release_version}-py3-none-any.whl" \
  '.urls[] | select(.filename == $name) | .url' \
  "$release_check/pypi.json")"
sdist_url="$(jq -er \
  --arg name "conda_advise-${release_version}.tar.gz" \
  '.urls[] | select(.filename == $name) | .url' \
  "$release_check/pypi.json")"
case "$wheel_url" in
  https://files.pythonhosted.org/*) ;;
  *) echo "Unexpected PyPI wheel URL." >&2 && exit 1 ;;
esac
case "$sdist_url" in
  https://files.pythonhosted.org/*) ;;
  *) echo "Unexpected PyPI source archive URL." >&2 && exit 1 ;;
esac
curl --fail --location --silent --show-error "$wheel_url" \
  --output "$release_check/pypi/conda_advise-${release_version}-py3-none-any.whl"
curl --fail --location --silent --show-error "$sdist_url" \
  --output "$release_check/pypi/conda_advise-${release_version}.tar.gz"
cmp "$release_check/github/conda_advise-${release_version}-py3-none-any.whl" \
  "$release_check/pypi/conda_advise-${release_version}-py3-none-any.whl"
cmp "$release_check/github/conda_advise-${release_version}.tar.gz" \
  "$release_check/pypi/conda_advise-${release_version}.tar.gz"
gh attestation verify "$release_check"/github/* --repo jezdez/conda-advise
pipx run --spec "pypi-attestations==0.0.30" pypi-attestations verify pypi \
  --repository https://github.com/jezdez/conda-advise \
  "$wheel_url"
pipx run --spec "pypi-attestations==0.0.30" pypi-attestations verify pypi \
  --repository https://github.com/jezdez/conda-advise \
  "$sdist_url"
```

Install the published wheel into a clean conda environment and verify plugin discovery and offline JSON output:

```console
set -euo pipefail
release_root="$(mktemp -d)"
release_prefix="$release_root/environment"
consumer_root="$release_root/fixture"
conda create --yes --prefix "$release_prefix" --override-channels \
  --channel conda-forge "conda>=24.3" cvss jsonschema packageurl-python pip
conda run --prefix "$release_prefix" python -m pip install --no-cache-dir \
  "$release_check/pypi/conda_advise-${release_version}-py3-none-any.whl"
conda run --prefix "$release_prefix" conda advise --help
export XDG_CACHE_HOME="$consumer_root/cache"
export CONDARC="$consumer_root/condarc"
"$release_prefix/bin/python" demos/fixtures/setup.py "$consumer_root" >/dev/null
"$release_prefix/bin/python" demos/fixtures/server.py "$consumer_root" \
  >"$consumer_root/server.log" 2>&1 &
consumer_server_pid=$!
cleanup_consumer_server() {
  kill "$consumer_server_pid" >/dev/null 2>&1 || true
}
trap cleanup_consumer_server EXIT
until curl --silent --fail http://127.0.0.1:8765/health >/dev/null; do
  sleep 0.05
done
if conda run --prefix "$release_prefix" conda advise \
  --prefix "$consumer_root/prefix" --json >"$release_check/online.json"; then
  online_status=0
else
  online_status=$?
fi
test "$online_status" -eq 1
kill "$consumer_server_pid"
wait "$consumer_server_pid" || true
trap - EXIT
if conda run --prefix "$release_prefix" conda advise \
  --prefix "$consumer_root/prefix" --offline --json \
  >"$release_check/report.json"; then
  offline_status=0
else
  offline_status=$?
fi
test "$offline_status" -eq 1
"$release_prefix/bin/python" -m jsonschema \
  -i "$release_check/report.json" schema/conda-advise-report-v1.schema.json
```

Verify the personal-channel package separately from the future conda-forge package:

```console
set -euo pipefail
anaconda_prefix="$release_root/anaconda-environment"
conda create --yes --prefix "$anaconda_prefix" \
  --strict-channel-priority \
  --override-channels \
  --channel https://conda.anaconda.org/jezdez/label/main \
  --channel conda-forge \
  "conda-advise=${release_version}" \
  "conda>=24.3"
conda run --prefix "$anaconda_prefix" python -c \
  "import conda_advise; assert conda_advise.__version__ == '$release_version'"
conda run --prefix "$anaconda_prefix" conda advise --help
conda run --prefix "$anaconda_prefix" python recipe/offline_smoke.py
```

## Failure recovery

If PyPI publishing fails, inspect the live PyPI files before rerunning anything.
Rerun failed jobs only when neither distribution was published.

If PyPI contains one distribution, a missing attestation, an unexpected filename, or bytes different from the draft release, leave the draft private and prepare a new version.
Do not replace an uploaded file.

If both exact distributions and their attestations reached PyPI, compare them with the draft assets before retrying downstream jobs.

If the Anaconda.org upload fails, inspect `jezdez/conda-advise` and the `main` label before rerunning it.
If the exact conda package is already present, do not upload with `--force` and do not replace it.
When the upload job succeeded but public installation verification failed, rerun only the verification job after repodata has propagated.
Publish the verified draft only after both PyPI and Anaconda.org verification have succeeded.

```console
gh release edit 0.1.0 --repo jezdez/conda-advise --draft=false
```

If only the final GitHub publication job fails after PyPI and Anaconda.org verification succeed, rerun only that job.

Never move a release tag, replace published assets, or reuse a released version.

## Publish on conda-forge

Start the conda-forge submission only after version `0.1.0` is available on PyPI and the clean consumer smoke test above passes.

1. Submit a noarch Python recipe to `conda-forge/staged-recipes` using the source distribution published on PyPI.
2. Require Python 3.10 or newer, conda 24.3 or newer, `cvss`, and `packageurl-python` in the recipe.
3. Test `import conda_advise`, conda plugin discovery, `conda advise --help`, and a deterministic offline fixture scan in the recipe.
4. Build and test the recipe locally with `rattler-build` before opening the staged-recipes pull request.
5. After feedstock creation, use the normal conda-forge bot update pull requests for subsequent releases.
6. Verify feedstock CI and the package on `conda-forge/label/main`.
7. Verify aggregate repodata and CDN propagation.
8. Install `conda-advise` from the ordinary conda-forge channel into a clean conda environment and repeat plugin discovery and the offline fixture scan.

Document `conda install -c conda-forge conda-advise` only after the final clean installation succeeds without a staging label or direct package URL.
