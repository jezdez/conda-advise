# Install conda-advise

`conda-advise` must be installed in the Python environment that owns the `conda` executable.
conda discovers plugins from that environment.
A plugin installed in an unrelated named environment is not visible to another conda installation.

:::{warning}
There is no supported end-user package release yet.
Do not install an unpublished package name into a working base environment.
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

## Wait for a supported installation

PyPI and conda-forge commands will be added only after each package is publicly available and verified from a clean environment.
The PyPI distribution intentionally omits conda as a dependency.
The old, yanked `conda` project on PyPI is unsupported, and supported conda releases are not distributed through PyPI.
Future installation instructions will still require a conda-owning environment.

## Windows on ARM64

GitHub provides a native Windows 11 ARM64 runner, and `conda-advise` runs a native wheel-install and model-import canary there from the locked `win-arm64-native` Pixi environment.
conda itself is not currently available from the ordinary conda-forge `win-arm64` subdir, so the complete plugin suite on that runner uses the locked `win-64` environment through Windows Prism emulation.
This does not claim native conda plugin integration on Windows ARM64.
