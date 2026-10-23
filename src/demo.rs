//! A fake home folder full of fake keys, for tests and screen recordings.
//!
//! Keys are generated at run time from a fixed seed, so the repository itself
//! contains no key-shaped strings (secret scanners and push protection stay
//! quiet) while every run produces the same, reproducible demo.

use std::fs;
use std::io;
use std::path::Path;

pub const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
pub const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub const HEX: &[u8] = b"0123456789abcdef";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `prefix` followed by `n` pseudo-random characters from `charset`.
pub fn fake_charset(prefix: &str, n: usize, seed: u64, charset: &[u8]) -> String {
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xD1B54A32D192ED03;
    let mut s = String::from(prefix);
    for _ in 0..n {
        // splitmix64
        x = x.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        s.push(charset[(z % charset.len() as u64) as usize] as char);
    }
    s
}

/// An alphanumeric fake key.
pub fn fake(prefix: &str, n: usize, seed: u64) -> String {
    fake_charset(prefix, n, seed, ALNUM)
}

/// Write the fake home into `root` (created if missing).
pub fn write_fake_home(root: &Path) -> io::Result<()> {
    let openai = fake("sk-proj-", 120, 101);
    let anthropic = format!("{}AA", fake("sk-ant-api03-", 93, 102));
    let gemini = fake("AIza", 35, 103);
    let aws_id = fake_charset("AKIA", 16, 104, UPPER);
    let aws_secret = fake_charset("", 40, 105, B64);
    let github = fake("ghp_", 36, 106);
    let gho = fake("gho_", 36, 107);
    let gitlab = fake("glpat-", 20, 108);
    let slack_hook = format!(
        "https://hooks.slack.com/services/{}/{}/{}",
        fake_charset("T", 10, 109, UPPER),
        fake_charset("B", 10, 110, UPPER),
        fake("", 24, 111)
    );
    let stripe = fake(&["sk", "_live_"].concat(), 99, 112);
    let telegram = fake_charset("7412589630:AA", 33, 113, ALNUM);
    let hf = fake("hf_", 34, 114);
    let deepgram = fake_charset("", 40, 115, HEX);
    let npm = fake("npm_", 36, 116);
    let groq = fake("gsk_", 52, 117);
    let xai = fake("xai-", 80, 118);
    let openrouter = fake_charset("sk-or-v1-", 64, 119, HEX);
    let replicate = fake("r8_", 37, 120);
    let netrc_pw = fake("", 32, 121);
    let db_pw = fake("", 14, 122);

    let fillers = [
        "ls -la",
        "cd ~/projects/telegram-bot",
        "git status",
        "git pull",
        "npm run dev",
        "clear",
        "python3 main.py",
        "code .",
        "docker ps",
        "htop",
        "cargo build --release",
        "git commit -m wip",
        "cd ..",
        "make",
        "pnpm install",
    ];
    let mut zsh = String::new();
    let mut t = 1_726_000_000u64;
    let mut push = |zsh: &mut String, cmd: &str| {
        t += 97;
        zsh.push_str(&format!(": {t}:0;{cmd}\n"));
    };
    for i in 0..37 {
        for f in 0..(3 + i % 5) {
            push(&mut zsh, fillers[(i * 7 + f) % fillers.len()]);
        }
        let cmd = match i % 4 {
            0 => format!("export OPENAI_API_KEY={openai}"),
            1 => format!("curl https://api.openai.com/v1/models -H \"Authorization: Bearer {openai}\""),
            2 => format!("OPENAI_API_KEY={openai} python3 agent.py"),
            _ => format!("echo {openai} | wl-copy"),
        };
        push(&mut zsh, &cmd);
        match i {
            5 => push(&mut zsh, &format!("git clone https://{github}@github.com/me/secret-project.git")),
            11 => push(&mut zsh, &format!(
                "curl -X POST https://api.deepgram.com/v1/listen -H \"Authorization: Token {deepgram}\" --data-binary @memo.wav"
            )),
            17 => push(&mut zsh, &format!("huggingface-cli login --token {hf}")),
            23 => push(&mut zsh, &format!("export ANTHROPIC_API_KEY={anthropic}")),
            29 => push(&mut zsh, &format!("psql postgres://app:{db_pw}@localhost:5432/app")),
            _ => {}
        }
    }

    let files: Vec<(&str, String)> = vec![
        (".zsh_history", zsh),
        (".bash_history", format!(
            "ls\naws configure set aws_access_key_id {aws_id}\naws configure set aws_secret_access_key {aws_secret}\naws s3 ls\nstripe login --api-key {stripe}\n"
        )),
        (".local/share/fish/fish_history", format!(
            "- cmd: set -x GROQ_API_KEY {groq}\n  when: 1726001234\n- cmd: ls\n  when: 1726001240\n"
        )),
        (".zshrc", format!(
            "export PATH=$HOME/.local/bin:$PATH\nexport EDITOR=nvim\nexport ANTHROPIC_API_KEY={anthropic}\nexport GEMINI_API_KEY={gemini}\nalias ll='ls -la'\n"
        )),
        (".npmrc", format!("//registry.npmjs.org/:_authToken={npm}\n")),
        (".netrc", format!("machine api.heroku.com\n  login me@example.com\n  password {netrc_pw}\n")),
        (".aws/credentials", format!(
            "[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n"
        )),
        (".config/gh/hosts.yml", format!("github.com:\n    oauth_token: {gho}\n    user: me\n")),
        (".claude/projects/-home-me-telegram-bot/session.jsonl", format!(
            "{{\"type\":\"user\",\"message\":{{\"content\":\"my key is {openai} why does it say 401\"}}}}\n{{\"type\":\"user\",\"message\":{{\"content\":\"use this one instead: {xai}\"}}}}\n"
        )),
        (".config/replicate/config.toml", format!("[auth]\ntoken = \"{replicate}\"\n")),
        ("projects/telegram-bot/.env", format!(
            "TELEGRAM_BOT_TOKEN={telegram}\nOPENROUTER_API_KEY={openrouter}\nDEBUG=true\n"
        )),
        ("projects/telegram-bot/.env.example", "TELEGRAM_BOT_TOKEN=your_token_here\nOPENROUTER_API_KEY=<paste-your-key>\n".into()),
        ("projects/telegram-bot/.git/HEAD", "ref: refs/heads/main\n".into()),
        ("projects/shop/.env.local", format!(
            "STRIPE_SECRET_KEY={stripe}\nSLACK_WEBHOOK_URL={slack_hook}\nNEXT_PUBLIC_SITE=https://shop.example.com\n"
        )),
        ("projects/shop/.gitignore", "node_modules/\n.env*.local\n".into()),
        ("projects/shop/.git/config", format!(
            "[remote \"origin\"]\n\turl = https://oauth2:{gitlab}@gitlab.com/me/shop.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        )),
        ("projects/shop/README.md", "Set STRIPE_SECRET_KEY in .env.local\n".into()),
    ];
    for (rel, body) in files {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(&path, body)?;
        #[cfg(unix)]
        if rel.contains("history") || rel.starts_with(".aws") || rel == ".netrc" {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}
