Source demos/_settings.tape

Output demos/providers.gif
Output demos/providers.mp4

Hide
Type `eval "$(pixi shell-hook -s bash -e demo)"`
Enter
Wait /\)/
Type `export PS1="$DEMO_PS1"`
Enter
Wait /demo>/
Type `unset NO_COLOR`
Enter
Wait /demo>/
Type `demo_root="/tmp/conda-advise-demo-$PPID" && rm -rf "$demo_root" && mkdir -p "$demo_root" && export XDG_CACHE_HOME="$demo_root/cache" && python demos/fixtures/setup.py "$demo_root" >/dev/null`
Enter
Wait /demo>/
Type `export CONDARC="$demo_root/condarc"`
Enter
Wait /demo>/
Type `python demos/fixtures/server.py "$demo_root" >"$demo_root/server.log" 2>&1 & demo_server_pid=$!`
Enter
Wait /demo>/
Type `until curl --silent --fail http://127.0.0.1:8765/health >/dev/null; do sleep 0.05; done`
Enter
Wait /demo>/
Type "clear"
Enter
Wait /demo>/
Show

Type "# Default: exact artifact component mapped through Parselmouth and OSV"
Enter
Sleep 1s
Type@100ms `conda advise --prefix "$demo_root/prefix" --provider=osv`
Enter
Wait /demo>/
Sleep 12s

Type "clear"
Enter
Wait /demo>/

Type "# Experimental: upstream package version matched by Prefix Basilisk"
Enter
Sleep 1s
Type@100ms `conda advise --prefix "$demo_root/prefix" --provider=basilisk`
Enter
Wait /demo>/
Sleep 12s

Hide
Type `kill "$demo_server_pid"`
Enter
Type `rm -rf "$demo_root"`
Enter
