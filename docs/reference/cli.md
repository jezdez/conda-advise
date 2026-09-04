# Command-line reference

The following help is generated from the parser used by the plugin:

```{eval-rst}
.. argparse::
   :module: conda_advise.cli
   :func: build_parser
   :prog: conda advise
```

## Synopsis

```text
conda advise [-n ENVIRONMENT | -p PATH] [--provider {osv,basilisk}]
             [--minimum-severity {low,medium,high,critical}]
             [--offline] [--refresh] [--json]
```

`conda advise` scans installed conda package records in one prefix.
It does not scan unmanaged pip installations or files outside conda's package records.
The common `conda advice` spelling is accepted as an alias.

## Target selection

| Option | Meaning |
| --- | --- |
| `-n`, `--name` | Select a named conda environment |
| `-p`, `--prefix` | Select a prefix by path |

The two options are mutually exclusive.
Without either option, conda's active or default prefix is used.

## Advisory options

| Option | Meaning |
| --- | --- |
| `--provider {osv,basilisk}` | Replace the configured provider for this run |
| `--minimum-severity LEVEL` | Replace the configured finding threshold |
| `--offline` | Prevent network work and use eligible cached data only |
| `--refresh` | Bypass fresh query entries and request current data |

`--offline` and `--refresh` cannot be combined.
`basilisk` is experimental and transmits eligible conda-forge package names and versions to Prefix.

## Output

| Option | Meaning |
| --- | --- |
| `--json` | Write one `conda-advise-report-v1` document to stdout |

Conda's standard networking and console options are also accepted through its parser helpers.
The human report groups findings by artifact.
The JSON report is the supported automation interface.

## Exit statuses

| Status | Meaning |
| --- | --- |
| `0` | The selected provider completed and no match met the threshold |
| `1` | One or more matches met the threshold |
| `2` | The target was invalid or attempted provider work was incomplete |

Unmapped artifacts use `not_checked` coverage and do not alone force status 2.
