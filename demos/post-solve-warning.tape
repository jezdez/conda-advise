Source demos/_settings.tape

Output demos/post-solve-warning.gif
Output demos/post-solve-warning.mp4

Hide
Type `eval "$(pixi shell-hook -s bash -e demo)"`
Enter
Wait /\)/
Type `export PS1="$DEMO_PS1"`
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

Type "# Create an environment from a deterministic local conda channel"
Enter
Sleep 500ms
Type@80ms `conda create --yes --prefix "$demo_root/transaction-prefix" --override-channels --channel http://127.0.0.1:8765/channel --solver libmamba demo-package`
Enter
Wait /demo>/
Sleep 4s

Hide
Type `kill "$demo_server_pid"`
Enter
Type `rm -rf "$demo_root"`
Enter
