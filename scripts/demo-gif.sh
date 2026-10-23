#!/bin/sh
# Record `keyleak demo` (fake home, fake keys) and render docs/demo.gif.
# Needs asciinema 2.x (`uv tool install asciinema`) and agg
# (`cargo install --git https://github.com/asciinema/agg`).
# Runs in an empty environment with HOME=/home/me and a `$ ` prompt, so no
# real user name or path can end up in the GIF.
set -eu
cd "$(dirname "$0")/.."
work=target/gif
rm -rf "$work"
mkdir -p "$work/bin" "$work/asciinema"
cp target/release/keyleak "$work/bin/"
cat > "$work/type.sh" <<'EOF'
#!/bin/sh
printf '$ '
sleep 0.6
for c in k e y l e a k ' ' d e m o; do printf '%s' "$c"; sleep 0.07; done
sleep 0.5
printf '\n'
keyleak demo || true
printf '$ '
EOF
chmod +x "$work/type.sh"
env -i HOME=/home/me USER=me SHELL=/bin/sh TERM=xterm-256color LANG=C.UTF-8 TMPDIR=/tmp \
    PATH="$PWD/$work/bin:/usr/bin:/bin" ASCIINEMA_CONFIG_HOME="$PWD/$work/asciinema" \
    "$(command -v asciinema)" rec -q --cols 110 --rows 40 -c "$work/type.sh" "$work/raw.cast" </dev/null
python3 -I scripts/demo-gif-retime.py "$work/raw.cast" "$work/demo.cast" 40
agg --theme dracula --font-family "${GIF_FONT:-JetBrains Mono,JetBrainsMono Nerd Font Mono,DejaVu Sans Mono}" --font-size 16 --line-height 1.3 \
    --fps-cap 15 --idle-time-limit 5 --last-frame-duration 4 "$work/demo.cast" docs/demo.gif
for s in "${USER:-}" "${HOME:-}"; do
    if [ -n "$s" ] && grep -qF "$s" "$work/demo.cast"; then
        echo "'$s' is in the recording, not publishing it" >&2
        rm -f docs/demo.gif
        exit 1
    fi
done
ls -l docs/demo.gif
