# Configuration reference

conda stores plugin settings under the `plugins` key.
`conda-advise` uses flat names prefixed with `conda_advise_`.
conda 25.5 and newer can write these values with `conda config --set plugins.SETTING VALUE`.
conda 24.3 through 25.3 require direct `.condarc` editing, although they read the same structure.

```yaml
plugins:
  conda_advise_provider: osv
  conda_advise_post_solve: warn
  conda_advise_minimum_severity: high
  conda_advise_timeout_seconds: 5
  conda_advise_conda_forge_origins:
    - https://conda.anaconda.org/conda-forge
    - https://prefix.dev/conda-forge
```

## User settings

| Setting | Type | Default | Meaning |
| --- | --- | --- | --- |
| `conda_advise_provider` | `osv` or `basilisk` | `osv` | Provider used when the CLI does not override it. `basilisk` is experimental |
| `conda_advise_post_solve` | `off` or `warn` | `warn` | Whether to check packages selected for linking |
| `conda_advise_minimum_severity` | severity name | `high` | Minimum warning and exit-status severity |
| `conda_advise_timeout_seconds` | integer from 1 through 30 | `5` | Advisory scan deadline for manual scans and post-solve checks |
| `conda_advise_conda_forge_origins` | URL list | canonical conda-forge and Prefix mirror | URL prefixes whose recognized records are eligible for provider lookup |

KEV matches always qualify regardless of the minimum severity.
The deadline starts when package-record scanning begins and includes subject normalization, cache access, provider requests, and optional KEV enrichment.
The deadline stops the scan from waiting for unfinished requests but does not terminate an HTTP worker that is already running.
Such a worker may finish after the report but cannot change it.

## Endpoint settings

The following advanced settings permit a controlled deployment to use a compatible mirror:

| Setting | Default |
| --- | --- |
| `conda_advise_osv_url` | `https://api.osv.dev` |
| `conda_advise_parselmouth_url` | `https://conda-mapping.prefix.dev` |
| `conda_advise_basilisk_url` | `https://api.basilisk.prefix.dev` |

The replacement service must implement the same request and response behavior documented for the selected provider.
Validation accepts HTTPS endpoints and plain HTTP only for `localhost`, `127.0.0.1`, and `::1`.
Loopback HTTP is unencrypted and should be used only for local tests and deterministic demonstrations.

Changing a service URL does not make a record with a nonmatching artifact URL or an unrecognized package record eligible for lookup.
Adding an origin does make recognized records below that URL path eligible, including private records if the configured path contains them.
Recognition does not cross-check the record's channel field, filename, or digest against conda-forge metadata.
