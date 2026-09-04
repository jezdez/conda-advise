# Coverage and reason codes

Every subject has provider coverage independent of its findings.
Callers must inspect both.

## Coverage statuses

| Status | Meaning |
| --- | --- |
| `complete` | All provider work scheduled for the subject completed |
| `not_checked` | The subject was intentionally not sent or could not be mapped to provider input |
| `incomplete` | Provider work was attempted but did not finish successfully |

`complete` with no findings means only that the selected provider returned no matches for its inputs at that time.
It is not a universal vulnerability assessment.

The summary counts `component_not_mapped` and `no_components` subjects under `unmapped`.
Other `not_checked` subjects are counted separately.

## Stable reason codes

| Code | Status | Meaning |
| --- | --- | --- |
| no reason | `complete` | Provider work completed |
| `unsupported_origin` | `not_checked` | The artifact origin was not an allowed public conda-forge origin |
| `unrecognized_record` | `not_checked` | The package name, version, or conda platform directory was not recognized |
| `missing_sha256` | `not_checked` | The `osv` provider requires an artifact SHA-256 |
| `component_not_mapped` | `not_checked` | Parselmouth returned no mapping for the artifact hash |
| `no_components` | `not_checked` | A mapping response contained no usable component name and version |
| `offline_cache_miss` | `incomplete` | Offline mode had no eligible cached result or used an incomplete stale fallback |
| `deadline_exceeded` | `incomplete` | The total scan budget expired |
| `request_failed` | `incomplete` | A provider request failed |
| `invalid_response` | `incomplete` | A provider response could not be validated |

## Diagnostic reason codes

Provider failures are reported separately from per-subject coverage.

| Code | Completeness | Meaning |
| --- | --- | --- |
| `cache_failed` | unchanged | The persistent cache was unavailable, so the current scan continued with an in-memory cache |

Reason-code additions within schema version 1 are permitted.
Consumers must tolerate unknown strings while preserving the status value.
