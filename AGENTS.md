# AGENTS.md — conda-advise coding guidelines

## Project structure

- The distribution is `conda-advise`, the Python namespace is `conda_advise`, and the conda subcommand is `conda advise`.
- Keep plugin registration in `conda_advise/plugin.py`. Registration imports must stay light because conda discovers plugins on every invocation.
- Put CLI parsing and dispatch in `conda_advise/cli/main.py`. Keep `__init__.py` files as thin re-export modules.
- Put advisory implementations under `providers/` and component discovery under `components/`. Providers are internal in v1.
- Tests mirror source paths and test module names match their source modules.

## Imports and dependencies

- Use relative imports inside `conda_advise`. Absolute package imports belong in tests and entry points.
- Use lazy imports only for startup-sensitive plugin hooks, optional dependencies, or real import cycles. Put other imports at module scope.
- Prefer the standard library and existing conda APIs before adding dependencies.
- Use Pixi as the canonical development environment and run project commands through committed Pixi tasks.
- Use `conda.gateways.connection.session.get_session()` for every HTTP request. Do not construct a separate requests session or add another HTTP client.
- Pin minimum dependency versions in `pyproject.toml`, not exact runtime versions.
- After changing Pixi dependencies, features, tasks, environments, or workspace settings, run `pixi lock` and commit `pixi.lock` with the change.

## Typing and code structure

- Add `from __future__ import annotations` to every Python module.
- Use modern annotations such as `str | None` and `list[str]`.
- Use `ty` for type checking and Ruff for linting and formatting.
- Put behavior on the class that owns its data. Before creating a private module helper, check for an existing conda API, an appropriate class method, or a reusable public function. Inline one-use logic.
- Do not use section-divider comments. Split a module when its responsibilities need headings.
- Comments and docstrings explain non-obvious reasons, limitations, or tradeoffs. Do not narrate the code.

## Conda integration

- Reuse conda APIs for prefix discovery, configuration, network sessions, reporting, and plugin registration.
- Reuse conda parser helpers for standard options. Do not register duplicate `--json`, `--offline`, prefix, verbosity, debug, trace, or console arguments.
- Register through `[project.entry-points.conda]` and the `conda_subcommands`, `conda_settings`, and `conda_post_solves` hooks.
- Treat `--json` only as an output format. Emit one complete JSON document on stdout and keep human diagnostics off stdout.
- Render human reports with Rich using text labels that remain meaningful without color. Keep JSON output independent of terminal rendering.
- Keep `artifact_component` and `upstream_version` evidence distinct. Component presence is not proof that vulnerable code is reachable or unpatched.
- Do not send private, defaults, Anaconda commercial, local, or unrecognized package records to public providers.
- Never describe missing coverage, an unmapped package, provider failure, stale data, or an empty match set as safe or unaffected.
- Preserve compatibility of `conda-advise-report-v1` for the full v1 release line.

## Testing

- Write module-level pytest functions. Do not group tests in classes.
- Never use `unittest.mock`, `Mock`, `MagicMock`, or `patch`.
- Use pytest fixtures, `monkeypatch`, recording closures, small real fakes, and local HTTP servers.
- Prefer parameterized tests with readable IDs. Add cases to an existing parameterized test before adding another function for the same behavior.
- Put shared fixtures in the nearest useful `conftest.py`.
- Run the full test suite, Ruff lint, Ruff format check, and ty before considering code complete.
- Measure branch coverage with pytest-cov.

## Documentation and demos

- Use Sphinx with MyST, `conda-sphinx-theme`, and `sphinx-design`.
- Follow Diataxis with tutorials, how-to guides, reference, and explanation sections.
- Keep tab labels short and avoid excessive bold or italic emphasis.
- Document provider privacy, evidence strength, incomplete coverage, caching, and result wording prominently.
- Keep VHS sources and deterministic fixtures under `demos/`. Generate both GIF and MP4 output from each public tape.
- Never make a demo depend on current live advisory results.

## Releases and GitHub prose

- Maintain `CHANGELOG.md` with an `Unreleased` section and prepare releases through reviewed changes on `main`.
- Release from annotated bare version tags such as `0.1.0`.
- Build the wheel and source distribution once, attest those files, attach them to a draft GitHub release, and publish the same files through PyPI Trusted Publishing.
- Build the Anaconda.org package from that exact PyPI source distribution, upload it without replacement flags, verify a clean installation, then publish the GitHub release.
- Pin every third-party GitHub Action to a complete commit SHA with the release version in a comment.
- Never replace published assets or reuse a released tag.
- Keep release workflows focused on orchestration. Put reusable checks in Pixi tasks and normal CI.
- Write GitHub issue and pull request prose as one physical line per paragraph or bullet. Let GitHub wrap it.
- Pull request descriptions explain what changed and why. Do not include validation commands or verification output.
- Never prefix pull request titles with `[codex]`.
