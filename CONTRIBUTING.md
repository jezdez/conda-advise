# Contributing

Contributions are welcome. Participation follows the [conda Code of Conduct](https://github.com/conda/governance/blob/main/CODE_OF_CONDUCT.md).

## Development

Install [Pixi](https://pixi.sh), clone the repository, and run:

```console
pixi run --locked -e dev check
pixi run --locked -e test test
pixi run --locked -e docs docs
```

Create focused changes from `main`, add tests for behavior changes, update documentation when users are affected, and keep `pixi.lock` synchronized with `pyproject.toml`.

AI-assisted contributors remain responsible for understanding their changes, discussing them during review, keeping them focused, and fixing behavior instead of weakening tests.

