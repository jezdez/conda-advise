# Demo recordings

The terminal demonstrations use [VHS](https://github.com/charmbracelet/vhs) and deterministic local responses.
They do not contact Parselmouth, OSV, Basilisk, CISA, or conda-forge.

| Demo | Description |
| --- | --- |
| `quickstart` | Scan a fixture prefix and read one artifact-component match |
| `post-solve-warning` | Create an environment through conda and show the post-solve warning |
| `providers` | Compare the `osv` and experimental `basilisk` providers in separate runs |

Each tape writes a GIF for documentation and an MP4 for higher-quality playback.

## Regenerate

Install the locked demo environment, then render all recordings:

```console
pixi run --locked demos
```

Pass one or more names to render selected tapes:

```console
pixi run --locked demos quickstart
pixi run --locked demos quickstart providers
```

`_settings.tape` owns the shared terminal dimensions, color theme, font, typing speed, and timeout.
`fixtures/server.py` serves fixed Parselmouth, OSV, Basilisk, and conda-channel responses on loopback.
`fixtures/setup.py` creates an installed-prefix record, a deterministic local conda package and channel, conda configuration, and fresh KEV cache under a temporary demo directory.

The post-solve recording runs a real `conda create` solve and transaction against the temporary channel.
It does not add a production fixture mode or special command-line option.
