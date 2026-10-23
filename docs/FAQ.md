# Keyleak FAQ

Short answers. The [README](../README.md) has the full tables.

- [What does it scan?](#what-does-it-scan)
- [What does it never do?](#what-does-it-never-do)
- [Does it ever print my full key?](#does-it-ever-print-my-full-key)
- [It found something that is not a key. How do I ignore it?](#it-found-something-that-is-not-a-key-how-do-i-ignore-it)
- [It found a real key. What now?](#it-found-a-real-key-what-now)
- [Which systems does it run on?](#which-systems-does-it-run-on)
- [How do I install it?](#how-do-i-install-it)
- [What do the exit codes mean?](#what-do-the-exit-codes-mean)
- [How is it different from gitleaks or trufflehog?](#how-is-it-different-from-gitleaks-or-trufflehog)
- [Can I try it without scanning my own files?](#can-i-try-it-without-scanning-my-own-files)

## What does it scan?

Your home folder (`~`), or the folders and files you pass with `--path`.

By default it reads only the places where keys usually leak:

- shell history (`.zsh_history`, `.bash_history`, fish, python, psql and any other `*_history`)
- `.env`, `.env.*`, `*.env` and `.envrc` files
- shell startup files (`.zshrc`, `.bashrc`, `.profile`, `config.fish` …)
- dotfiles, and config-like files inside dot folders (`~/.config`, `~/.aws`, `~/.claude` …)
- AI agent logs (Claude Code, Codex, Gemini, opencode, aider, Cursor and others)
- `.git/config` of every repo it walks through
- files named like secrets: `credentials*`, `secrets.*`, `*.pem`, `*.key`, `*.tfvars`, `docker-compose*`, `service-account*`

`--all` scans every text file instead.

It skips caches, `node_modules`, build folders, browser profiles, `~/.ssh`,
`~/.gnupg`, keyrings, binary files, other disks and network mounts, and
symlinks that point outside the scanned folder. Files over 10 MB are skipped
(history and agent logs: 64 MB). Change that with `--max-size`.

## What does it never do?

- **No network.** There is no network code. Its only dependencies are
  `regex`, `serde` and `serde_json`. It never calls a provider to check
  whether a key works. The HTML report loads nothing from the internet either
  (its Content-Security-Policy is `default-src 'none'`).
- **No changes to your files.** It opens files to read them, nothing else.
  It never edits, moves or deletes anything. The only files it writes are the
  ones you ask for: the HTML report (`--html`) and the fake home of
  `keyleak demo`.
- **No full keys.** See the next question.

## Does it ever print my full key?

No. Every key it finds is masked before it leaves the scanner, in the
terminal, `--json` and `--html`: a short public prefix, `…`, and the last 4
characters (`sk-proj-…8rPs`). Secrets under 16 characters show only 2 trailing
characters, and private keys show only their header. A test checks that no
output ever contains a full key.

The report still shows file paths and the masked line around each key, and
other long random-looking strings on that line are blanked. Treat the report
as private: the HTML report is saved readable by you only (mode 600).

## It found something that is not a key. How do I ignore it?

Pick one:

- Add `keyleak:allow` on the same line (for example in a comment).
- Add the key's id to `~/.keyleakignore` to ignore that one key everywhere.
  The id is in the report: `id:3fa9c2d1`.
- Add a file or folder to `~/.keyleakignore`:

```
id:3fa9c2d1          # one key, everywhere
*.example            # a file or folder name, at any depth
projects/old/**      # a path relative to the scanned folder
~/notes/keys.md      # an absolute path
```

Keyleak also reads `.keyleakignore` at the top of each scanned folder, and
any file you pass with `--ignore-file`.

Many false positives are skipped already: placeholders (`your_api_key_here`,
`sk-xxxx`, `<paste>`), `$VARIABLES`, paths, IDs and low-entropy values. In app
data and agent logs, a generic `NAME=value` only counts when the name looks
like a secret (`DISCORD_BOT_TOKEN`, `apiKey`).

## It found a real key. What now?

Each finding prints its own fix. In general:

1. **Rotate it first.** Make a new key on the provider's page (the link is in
   the report) and revoke the old one. A key that sat in plain text, shell
   history, an AI chat or a git remote should be treated as leaked. Deleting
   the file does not undo that.
2. **Clean up every copy.** Repeats are grouped per key, so you see all the
   places at once. Delete the history lines it names (with other terminals
   closed), delete the agent session log, take the token out of the git remote
   URL.
3. **Store the new key properly.** Keep it in your system keyring or a secret
   manager and load it when needed. On Linux:

   ```sh
   secret-tool store --label=OPENAI_API_KEY keyleak OPENAI_API_KEY
   export OPENAI_API_KEY="$(secret-tool lookup keyleak OPENAI_API_KEY)"   # in .zshrc
   ```

   On macOS use `security add-generic-password` and
   `security find-generic-password -w`. For a project, a `.env` file is fine
   for local work if it is git-ignored. Keyleak marks a `.env` inside a git
   repo that is not git-ignored as critical.
4. Next time, start commands that hold a secret with a space and turn on
   `setopt HIST_IGNORE_SPACE` (zsh) or `HISTCONTROL=ignorespace` (bash), so
   they never reach your history.

## Which systems does it run on?

- **Linux x86_64:** a prebuilt static binary with no dependencies.
- **macOS:** build from source with `cargo install`. Fix tips use the macOS
  keychain (`security`) there.
- **Windows:** not supported or tested.

## How do I install it?

Linux x86_64, from the release:

```sh
curl -LO https://github.com/thekbbohara/keyleak/releases/download/v0.1.0/keyleak-v0.1.0-x86_64-linux.tar.gz
curl -LO https://github.com/thekbbohara/keyleak/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS
tar xzf keyleak-v0.1.0-x86_64-linux.tar.gz
install -m 755 keyleak-v0.1.0-x86_64-linux/keyleak ~/.local/bin/
```

Anywhere with Rust 1.80+:

```sh
cargo install --git https://github.com/thekbbohara/keyleak --tag v0.1.0
```

## What do the exit codes mean?

| Code | Meaning |
|---|---|
| `0` | no keys found |
| `1` | keys found |
| `2` | error (bad argument, missing path, file it could not write) |

So `keyleak && echo clean` works in scripts.

## How is it different from gitleaks or trufflehog?

They are built for code: git history, repos and CI pipelines. Keyleak is
built for your machine. It starts from where people leak keys day to day
(shell history, dotfiles, `.env` files, AI agent logs), groups every copy of a
key into one finding, ranks it by where it sits, and tells you how to fix it.

It also never makes network calls. trufflehog checks found keys against the
provider by default, which sends them over the network. Use the right tool
for each job: gitleaks or trufflehog in your repos and CI, Keyleak on your
laptop.

## Can I try it without scanning my own files?

Yes:

```sh
keyleak demo          # writes a fake home with fake keys to a temp folder and scans only that
keyleak demo ./x      # same, in ./x
```

The fake keys are generated from a fixed seed, so every run looks the same.
The GIF in the README is a recording of `keyleak demo`.
