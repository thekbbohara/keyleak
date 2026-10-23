# Keyleak

![keyleak demo: 20 keys exposed in 61 places on a fake home folder, each with a fix](docs/demo.gif)

You pasted your OpenAI key into the terminal. 37 times. Keyleak finds every
API key sitting in plain text in your home folder (shell history, `.env`
files, dotfiles, AI agent chat logs) and tells you, in plain English, how bad
each one is and how to fix it.

- **Offline and read-only.** No network code at all. It opens files, never changes them.
- **Never prints a key.** Every key is masked (`sk-proj-…8rPs`) before it leaves the scanner, in the terminal, JSON and HTML.
- **Fast.** One binary, all cores. About 5 GB / 50,000 files of a real home folder in under 10 seconds.

Questions (false positives, fixing a key, exit codes, gitleaks vs trufflehog): see the [FAQ](docs/FAQ.md).

## Install

Linux x86_64, one static binary with no dependencies:

```sh
curl -LO https://github.com/thekbbohara/keyleak/releases/download/v0.1.0/keyleak-v0.1.0-x86_64-linux.tar.gz
curl -LO https://github.com/thekbbohara/keyleak/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf keyleak-v0.1.0-x86_64-linux.tar.gz
install -m 755 keyleak-v0.1.0-x86_64-linux/keyleak ~/.local/bin/
```

macOS or anything else with Rust 1.80+:

```sh
cargo install --git https://github.com/thekbbohara/keyleak --tag v0.1.0
```

## Run it

```sh
keyleak demo               # try it first on a fake home full of fake keys
keyleak                    # scan ~
keyleak --html report.html # also write an HTML report
```

| Option | |
|---|---|
| `-p, --path DIR` | scan this folder or file instead of `~` (repeatable) |
| `-a, --all` | scan every text file, not only the usual leak spots |
| `--json` | machine-readable report |
| `--html [FILE]` | also write a single-file HTML report (saved with mode 600) |
| `--ignore-file FILE` | extra ignore file |
| `--max-size MB` | skip bigger files (default 10; history and agent logs 64) |

Exit code: `0` no keys, `1` keys found, `2` error.

## What it never does

- **No network.** There is no network code: no telemetry, no update checks, no calls to verify a key.
- **No full keys.** Keys are masked in the terminal, JSON and HTML. The HTML report is saved readable by you only.
- **No changes.** It never edits, moves or deletes a file. Fixing is up to you, with the steps it prints.

## What it finds

OpenAI, Anthropic, Google / Gemini, AWS (key ID and secret), GitHub (classic
and fine-grained), GitLab, Slack (tokens, app tokens, webhooks), Stripe (live,
test, webhook), Telegram bots, Hugging Face, Deepgram, OpenRouter, Groq, xAI,
Replicate, npm, PyPI, SendGrid, private keys, passwords in URLs and `.netrc`,
bearer tokens, and generic `SOMETHING_API_KEY=` / `TOKEN=` / `SECRET=`
assignments with random-looking values.

Placeholders (`your_api_key_here`, `sk-xxxx`, `<paste>`), `$VARIABLES`, paths,
IDs and low-entropy values are skipped. In app data and agent logs, generic
hits need a secret-looking name (`DISCORD_BOT_TOKEN`, `apiKey`), so cache keys
and tracking tokens stay out.

## Where it looks, and how risky that is

| Place | Risk | Why |
|---|---|---|
| `.env` inside a git repo, not git-ignored | critical | one `git add .` from being public |
| shell history (zsh, bash, fish, python, psql …) | high | plain text, kept forever, often synced |
| AI agent logs (Claude Code, Codex, Gemini, opencode, aider …) | high | the key was also sent to the AI provider |
| shell startup files (`.zshrc`, `.bashrc`, `config.fish`) | high | dotfile repos end up on GitHub |
| token in a git remote URL (`.git/config`) | high | shown by `git remote -v`, copied with the folder |
| git-ignored `.env`, app configs | medium | fine for local dev, still plain text |
| credential files (`~/.aws/credentials`, `.npmrc`, `.netrc`, `gh` …) | low | where the tool expects it; medium if others can read the file |

Every finding comes with a fix: the provider page to rotate the key, which
history lines to delete, how to move it to the system keyring
(`secret-tool` on Linux, `security` on macOS), or how to git-ignore it.

The same key in 38 places is one key: findings are grouped per key, so you
rotate once and clean up every copy.

Not scanned: `~/.ssh`, `~/.gnupg` and keyrings (keys belong there), caches,
`node_modules`, build folders, browser profiles, other disks and network
mounts, binary files, and symlinks that point outside the scanned folder.

## Ignore things

`~/.keyleakignore` and `<scanned folder>/.keyleakignore`:

```
id:3fa9c2d1          # one key, everywhere (the id is in the report)
*.example            # a file or folder name, at any depth
projects/old/**      # a path relative to the scanned folder
~/notes/keys.md      # an absolute path
```

Or put `keyleak:allow` on the line itself.

## vs gitleaks and trufflehog

They are great at scanning git repos and CI. Keyleak is for your laptop: it
starts from the places people actually leak keys (history, dotfiles, agent
logs), groups repeats into one key, ranks by where the key sits, and explains
the fix. No verification calls, so nothing leaves your machine.

## Why Rust

A single static binary with no runtime, fast enough to read gigabytes of
history and agent logs on every core, and only three dependencies (`regex`,
`serde`, `serde_json`) so the whole tool is easy to audit. That matters for a
program you run over your secrets.

## Develop

```sh
make check       # fmt, clippy, tests
make demo        # coloured scan of a fake home, for screen recordings
make demo-html   # the HTML report of the same
make shots       # screenshots of the HTML report (needs Chrome)
make gif         # docs/demo.gif from `keyleak demo` (needs asciinema and agg)
make release     # static x86_64 Linux tarball + SHA256SUMS in target/dist
```

The fake keys are generated at run time from a fixed seed, so the repo holds
no key-shaped strings and every demo looks the same.

## License

MIT
