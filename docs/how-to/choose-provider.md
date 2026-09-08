# Choose an advisory provider

The default `osv` provider uses [Parselmouth](https://github.com/prefix-dev/parselmouth) and [OSV](https://osv.dev/).
The experimental alternative uses Prefix's [Basilisk](https://basilisk.prefix.dev/status).
One provider runs per scan.

Select a provider for one invocation:

```console
conda advise --provider=osv
conda advise --provider=basilisk
```

The command-line option replaces the configured provider for that invocation.
Comparing providers requires two separate scans.

Set the persistent provider used by manual scans and post-solve checks:

```console
conda config --set plugins.conda_advise_provider osv
```

To opt into the experimental Basilisk provider persistently:

```console
conda config --set plugins.conda_advise_provider basilisk
```

Writing plugin settings through `conda config` requires conda 25.5 or newer.
conda 24.3 through 25.3 can read these settings but cannot write them through `conda config`.
For those versions, edit the active `.condarc` and add:

```yaml
plugins:
  conda_advise_provider: basilisk
```

The providers transmit different inputs and return different [matching evidence](../explanation/matching-and-evidence.md):

| Provider | Requests | Evidence |
| --- | --- | --- |
| `osv` | Artifact hash to Parselmouth, then PyPI component names and versions to OSV | `artifact_component` |
| `basilisk` | Eligible conda package names and versions to Prefix | `upstream_version` |

Both use the same allowed origins, which exclude ordinary private-channel records by default.
Adding an origin permits lookup of recognized records beneath it, including private records.
Read [provider behavior](../reference/providers.md) and [privacy](../explanation/privacy.md) before choosing a provider for unattended use.
