# Use conda-advise in CI

Use versioned JSON output and decide explicitly which exit statuses should fail a job.

::::{tab-set}

:::{tab-item} POSIX

```console
conda advise --prefix "$CONDA_PREFIX" --json > conda-advise.json
```

:::

:::{tab-item} PowerShell

```powershell
conda advise --prefix $env:CONDA_PREFIX --json | Set-Content -Encoding utf8 conda-advise.json
```

:::

::::

The exit statuses are:

| Status | Meaning |
| --- | --- |
| `0` | The provider completed and no finding met the threshold |
| `1` | At least one finding met the threshold |
| `2` | The target was invalid or attempted provider work was incomplete |

An unmapped artifact is `not_checked` and does not by itself produce status 2.
Your policy must decide whether the unmapped count is acceptable.

To archive a report even when findings produce status 1, preserve the command status explicitly:

::::{tab-set}

:::{tab-item} POSIX

```console
set +e
conda advise --prefix "$CONDA_PREFIX" --json > conda-advise.json
advise_status=$?
set -e
case "$advise_status" in
  0) echo "No advisory matched the configured threshold" ;;
  1) echo "Review qualifying advisory matches" >&2 ;;
  2) echo "Advisory scan was incomplete" >&2 ;;
  *) echo "Unexpected exit status: $advise_status" >&2; exit "$advise_status" ;;
esac
```

:::

:::{tab-item} PowerShell

```powershell
conda advise --prefix $env:CONDA_PREFIX --json | Set-Content -Encoding utf8 conda-advise.json
$adviseStatus = $LASTEXITCODE
switch ($adviseStatus) {
  0 { Write-Output "No advisory matched the configured threshold" }
  1 { Write-Warning "Review qualifying advisory matches" }
  2 { Write-Error "Advisory scan was incomplete" }
  default { throw "Unexpected exit status: $adviseStatus" }
}
```

:::

::::

:::{note}
The shell example uses semicolon syntax because each `case` arm is a shell statement list.
The result wording deliberately does not call a zero-match report safe.
:::

Validate the document against the shipped schema before consuming its fields:

::::{tab-set}

:::{tab-item} POSIX

```console
python -m jsonschema \
  -i conda-advise.json \
  schema/conda-advise-report-v1.schema.json
```

:::

:::{tab-item} PowerShell

```powershell
python -m jsonschema `
  -i conda-advise.json `
  schema/conda-advise-report-v1.schema.json
```

:::

::::

Pin the `conda-advise` version in production automation and reject unknown `schema_version` values.
Do not make decisions from human output or undocumented fields.
