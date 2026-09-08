# Demo recordings

The recordings use [VHS](https://github.com/charmbracelet/vhs) with local fixtures for [Parselmouth](https://github.com/prefix-dev/parselmouth), [OSV](https://osv.dev/), [Basilisk](https://basilisk.prefix.dev/status), and CISA KEV.
No live advisory or package service is needed.

| Demo | Description |
| --- | --- |
| `quickstart` | Scan a fixture prefix and read one artifact-component match |
| `post-solve-warning` | Create an environment through conda and show the post-solve warning |
| `providers` | Compare the `osv` and experimental `basilisk` providers in separate runs |

Each tape writes a GIF and an MP4, with pauses to read the report.

## Regenerate

Render all recordings:

```console
pixi run --locked -e demo demos
```

Pass one or more names to render selected tapes:

```console
pixi run --locked -e demo demos quickstart
pixi run --locked -e demo demos quickstart providers
```

`_settings.tape` sets the terminal appearance and timing.
Each tape creates a private temporary directory and starts `fixtures/server.py`, which reserves an available loopback port before creating the prefix, channel, configuration, and KEV cache.
`fixtures/wait.py` checks the server's startup file and process ID.
The directory and port vary between recordings, while advisory and package data stay fixed.

`CONDA_ADVISE_CACHE_PATH` and `CONDA_PKGS_DIRS` keep caches inside that directory, which is removed when recording ends.
The post-solve recording runs a real `conda create` transaction against the local channel.
