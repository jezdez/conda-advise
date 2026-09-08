# Install conda-advise

Install `conda-advise` in the Python environment that owns the `conda` executable.
That is where [conda discovers plugins](https://docs.conda.io/projects/conda/en/stable/dev-guide/plugins/index.html).

:::{warning}
There is no published release yet.
Use the source installation below.
:::

## Run the source preview

Clone the repository and install its locked development environment.

::::{tab-set}

:::{tab-item} POSIX

```console
git clone https://github.com/jezdez/conda-advise.git
cd conda-advise
pixi install --locked -e dev
pixi run --locked -e dev conda advise --help
```

:::

:::{tab-item} PowerShell

```powershell
git clone https://github.com/jezdez/conda-advise.git
Set-Location conda-advise
pixi install --locked -e dev
pixi run --locked -e dev conda advise --help
```

:::

::::

Run all preview commands through that environment:

```console
pixi run --locked -e dev conda advise --prefix /path/to/environment
```

PyPI and conda-forge installation commands will be added after release.
The Python distribution omits conda as a dependency because supported conda releases are not distributed through PyPI.

## Windows on ARM64

CI checks native wheel installation and model imports with the locked `win-arm64-native` Pixi environment.
The complete plugin suite uses the `win-64` environment through Windows Prism because conda is unavailable from the ordinary conda-forge `win-arm64` subdir.
Native conda plugin discovery and transactions on Windows ARM64 are not covered.
