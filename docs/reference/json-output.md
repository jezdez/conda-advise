# JSON output

`conda advise --json` writes one JSON document to standard output.
Human diagnostics do not precede or follow it.

The version 1 schema is available in the source distribution, installed package, and documentation site:

- [`schema/conda-advise-report-v1.schema.json`](../../schema/conda-advise-report-v1.schema.json)
- `conda_advise/schema/conda-advise-report-v1.schema.json` as installed package data in the wheel

## Top-level fields

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer output schema version, currently `1` |
| `generated_at` | UTC report-generation time |
| `target` | Prefix selected for the scan |
| `provider` | `osv` or `basilisk` |
| `provider_experimental` | `true` when the selected provider is experimental |
| `minimum_severity` | Threshold used to count qualifying matches |
| `subjects` | Sanitized artifact identities reported by conda package records |
| `coverage` | Provider status for each subject |
| `findings` | Advisory matches and retained evidence |
| `failures` | Provider, cache, and deadline failures |
| `summary` | Checked, mapped, unmapped, not-checked, incomplete, and finding counters |

A target-selection, usage, scan, or JSON-rendering error returns a smaller versioned error document with `schema_version`, optional `target`, and `error.message`.
It exits with status 2.

## Subjects

Each subject contains `id`, `name`, `version`, `build`, `build_number`, `subdir`, `channel`, sanitized `url`, `filename`, `sha256`, and `md5`.
The ID is `sha256:<digest>` when SHA-256 is known.

Credentials, token path segments, query strings, and fragments are removed from serialized URLs.
The local report can include the sanitized artifact URL for a private or unrecognized `not_checked` subject so the user can identify what was excluded.
Records whose sanitized artifact URLs fall outside the configured allowed-origin list are not transmitted to a provider or cached as provider inputs.

## Coverage

Each coverage item refers to a subject ID and records the `provider`, `status`, optional stable `reason`, optional `checked_at` time, and `stale` state.
See [coverage and reason codes](coverage-and-reason-codes.md).

## Findings

Each finding contains:

- the subject ID
- preferred display `id` and complete `aliases`
- advisory `summary`
- normalized `severity` and optional numeric `score`
- upstream `fixes`
- one or more evidence objects
- complete retained `source_records`
- `kev` and `stale` flags

Evidence records include their `type`, `provider`, exact artifact SHA-256 when known, and component PURL for `artifact_component` evidence.

Advisory details with a nonempty `withdrawn` value are excluded before findings are built.
Retained source records preserve the provider-native ID, publication and modification fields, null withdrawn state, source URL, CVSS vectors and calculated base scores, upstream fixes, and the complete validated provider response in `data`.
Treat summaries, aliases, fixes, URLs, and every value under `data` as provider-controlled input.

## Compatibility

Fields required by schema version 1 keep their meaning for the v1 release line.
Reason-code and advisory-source vocabularies may grow, so consumers must tolerate unknown values where the schema allows strings.

`summary.unmapped` counts `component_not_mapped` and `no_components` subjects.
Those subjects retain `not_checked` coverage but are excluded from `summary.not_checked` so callers can distinguish absent component mappings from provenance exclusions.

A future incompatible document will use another `schema_version` and schema file.
Consumers should reject versions they do not understand.
