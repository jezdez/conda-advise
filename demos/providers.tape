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
Type `demo_root="$(mktemp -d)" && export CONDA_ADVISE_CACHE_PATH="$demo_root/cache/cache.sqlite3" CONDA_PKGS_DIRS="$demo_root/pkgs" || exit 1`
Enter
Wait /demo>/
Type `export CONDARC="$demo_root/condarc"`
Enter
Wait /demo>/
Type `python demos/fixtures/server.py "$demo_root" >"$demo_root/server.log" 2>&1 & demo_server_pid=$!`
Enter
Wait /demo>/
Type `trap 'kill "$demo_server_pid" 2>/dev/null || true; wait "$demo_server_pid" 2>/dev/null || true; rm -rf "$demo_root"' EXIT; demo_service_url="$(python demos/fixtures/wait.py "$demo_root" "$demo_server_pid")" && kill -0 "$demo_server_pid" || exit 1`
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
Type `kill "$demo_server_pid" 2>/dev/null || true; wait "$demo_server_pid" 2>/dev/null || true; rm -rf "$demo_root"; trap - EXIT`
Enter
