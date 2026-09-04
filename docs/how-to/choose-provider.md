# Choose an advisory provider

`conda-advise` uses one provider per scan.
The default is `osv`.

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

The `osv` provider sends an artifact SHA-256 to Prefix's Parselmouth service.
It sends returned PyPI component names and exact versions to OSV.

The `basilisk` provider sends names and versions from records whose sanitized artifact URLs match the configured allowed-origin list to Prefix.
With the default list, ordinary private-channel records have other URLs and are not eligible.
Adding an origin authorizes recognized records below that URL path, including private records if the configured path contains them.
Eligibility also requires syntactically valid package names, versions, and conda subdirectories, but the client does not cross-check the record's channel field, filename, or digest against conda-forge metadata.
It does not call Parselmouth or OSV directly from your machine.

Read [provider behavior](../reference/providers.md), [privacy](../explanation/privacy.md), and [matching evidence](../explanation/matching-and-evidence.md) before choosing a provider for unattended use.
