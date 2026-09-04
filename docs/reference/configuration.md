# Configuration reference

Conda stores plugin settings under the `plugins` key.
`conda-advise` uses flat names prefixed with `conda_advise_`.
Conda 25.5 and newer can write these values with `conda config --set plugins.SETTING VALUE`.
Conda 24.3 through 25.3 require direct `.condarc` editing, although they read the same structure.

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
| `conda_advise_timeout_seconds` | integer from 1 through 30 | `5` | Total hook network budget |
| `conda_advise_conda_forge_origins` | URL list | canonical conda-forge and Prefix mirror | Origins eligible for public lookup |

KEV matches always qualify regardless of the minimum severity.

## Endpoint settings

The following advanced settings permit a controlled deployment to use a compatible mirror:

| Setting | Default |
| --- | --- |
| `conda_advise_osv_url` | `https://api.osv.dev` |
| `conda_advise_parselmouth_url` | `https://conda-mapping.prefix.dev` |
| `conda_advise_basilisk_url` | `https://api.basilisk.prefix.dev` |

The replacement service must implement the same request and response behavior documented for the selected provider.
HTTPS is required outside loopback tests.

Changing a service URL does not make an otherwise private or unrecognized package record eligible for lookup.
