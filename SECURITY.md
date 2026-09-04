# Security policy

## Supported versions

No package release has been published yet, so report findings against the current `main` branch.
After the first release and before 1.0, only the latest published version receives security fixes.

| Version | Supported |
| --- | --- |
| Current `main` branch | Yes, before the first release |
| Latest release | Yes, after publication |
| Older releases | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use a [private GitHub security advisory](https://github.com/jezdez/conda-advise/security/advisories/new).

Include the affected version, package provenance, selected provider, expected behavior, observed behavior, and a minimal reproducer when it is safe to share. Treat disclosure of private package identities, credential leakage, incorrect provider routing, cache poisoning, JSON injection, provider-controlled resource exhaustion, and transaction blocking as security-sensitive.

We will acknowledge a report as soon as practical, coordinate a fix and release with the reporter, and credit the reporter unless they request otherwise.
