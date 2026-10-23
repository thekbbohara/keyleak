//! Walk the folders, pick the files where keys usually leak, run the detectors
//! and group every hit by secret.

use crate::detect::{self, Detector, DETECTORS};
use crate::ignore::{git_ignored, Ignore};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

pub const DEFAULT_MAX_SIZE: u64 = 10 * 1024 * 1024;
/// History files and agent logs grow large and are the most valuable to scan.
const LOG_MAX_SIZE: u64 = 64 * 1024 * 1024;
const APP_MAX_SIZE: u64 = 1024 * 1024;

pub struct Options {
    pub roots: Vec<PathBuf>,
    /// Scan every text file, not only the usual leak spots.
    pub all: bool,
    pub max_size: u64,
    pub ignore: Ignore,
    /// Shown as `~` in paths, and used for `~/` ignore patterns.
    pub home: Option<PathBuf>,
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    fn shift(self, by: i8) -> Risk {
        let i = (self as i8 + by).clamp(0, 3);
        [Risk::Low, Risk::Medium, Risk::High, Risk::Critical][i as usize]
    }
    pub fn label(self) -> &'static str {
        match self {
            Risk::Low => "LOW",
            Risk::Medium => "MEDIUM",
            Risk::High => "HIGH",
            Risk::Critical => "CRITICAL",
        }
    }
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Where {
    History,
    AgentLog,
    EnvFile,
    ShellConfig,
    GitConfig,
    CredentialFile,
    AppConfig,
    File,
}

impl Where {
    pub fn label(self) -> &'static str {
        match self {
            Where::History => "shell history",
            Where::AgentLog => "AI agent log",
            Where::EnvFile => ".env file",
            Where::ShellConfig => "shell startup file",
            Where::GitConfig => "git config",
            Where::CredentialFile => "credential file",
            Where::AppConfig => "app config",
            Where::File => "other file",
        }
    }
}

#[derive(Serialize, Debug, Clone)]
pub struct Place {
    pub path: String,
    pub line: usize,
    pub column: usize,
    #[serde(rename = "where")]
    pub kind: Where,
    pub risk: Risk,
    /// The line with every secret masked, trimmed around the hit.
    pub context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Secret {
    pub id: String,
    pub detector: &'static str,
    pub name: &'static str,
    pub provider: &'static str,
    pub masked: String,
    pub risk: Risk,
    pub rotate: &'static str,
    pub fix: Vec<String>,
    pub places: Vec<Place>,
}

#[derive(Serialize, Debug, Default)]
pub struct Stats {
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub skipped_large: usize,
    pub skipped_binary: usize,
    pub skipped_unreadable: usize,
    pub skipped_symlinks: usize,
    pub skipped_ignored: usize,
}

#[derive(Serialize, Debug)]
pub struct Report {
    pub tool: &'static str,
    pub version: &'static str,
    pub roots: Vec<String>,
    pub mode: &'static str,
    pub duration_ms: u128,
    pub stats: Stats,
    pub secrets_exposed: usize,
    pub places: usize,
    pub secrets: Vec<Secret>,
}

impl Report {
    pub fn count_by<K: Ord + Copy>(&self, key: impl Fn(&Secret) -> K) -> Vec<(K, usize)> {
        let mut m: std::collections::BTreeMap<K, usize> = Default::default();
        for s in &self.secrets {
            *m.entry(key(s)).or_default() += 1;
        }
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by_key(|a| std::cmp::Reverse(a.1));
        v
    }

    pub fn places_by_where(&self) -> Vec<(Where, usize)> {
        let mut m: HashMap<Where, usize> = HashMap::new();
        for p in self.secrets.iter().flat_map(|s| &s.places) {
            *m.entry(p.kind).or_default() += 1;
        }
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }
}

struct Candidate {
    path: PathBuf,
    kind: Where,
}

pub fn scan(opts: &Options) -> Report {
    let started = Instant::now();
    let mut stats = Stats::default();
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    for root in &opts.roots {
        walk(root, opts, &mut files, &mut seen, &mut stats);
    }

    let next = AtomicUsize::new(0);
    let found: Mutex<Vec<(usize, Vec<RawPlace>)>> = Mutex::new(Vec::new());
    let shared = Mutex::new(Stats::default());
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).min(8);
    std::thread::scope(|s| {
        for _ in 0..workers {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(c) = files.get(i) else { break };
                let limit = match c.kind {
                    Where::History | Where::AgentLog => opts.max_size.max(LOG_MAX_SIZE),
                    // Big files in app folders are data (caches, dumps), not config.
                    Where::AppConfig if !opts.all => opts.max_size.min(APP_MAX_SIZE),
                    _ => opts.max_size,
                };
                let strict = matches!(c.kind, Where::AgentLog | Where::AppConfig | Where::File);
                match scan_file(&c.path, limit, strict) {
                    FileResult::Hits(hits, bytes) => {
                        {
                            let mut st = shared.lock().unwrap();
                            st.files_scanned += 1;
                            st.bytes_scanned += bytes;
                        }
                        if !hits.is_empty() {
                            found.lock().unwrap().push((i, hits));
                        }
                    }
                    FileResult::Large => shared.lock().unwrap().skipped_large += 1,
                    FileResult::Binary => shared.lock().unwrap().skipped_binary += 1,
                    FileResult::Unreadable => shared.lock().unwrap().skipped_unreadable += 1,
                }
            });
        }
    });
    let st = shared.into_inner().unwrap();
    stats.files_scanned = st.files_scanned;
    stats.bytes_scanned = st.bytes_scanned;
    stats.skipped_large = st.skipped_large;
    stats.skipped_binary = st.skipped_binary;
    stats.skipped_unreadable = st.skipped_unreadable;

    let mut secrets: HashMap<String, Secret> = HashMap::new();
    let mut found = found.into_inner().unwrap();
    found.sort_by_key(|(i, _)| *i);
    for (i, hits) in found {
        let c = &files[i];
        let base = base_risk(c, opts.home.as_deref());
        for h in hits {
            if opts.ignore.ignores_id(&h.id) {
                continue;
            }
            let det = &DETECTORS[h.detector];
            let mut risk = base.0.shift(det.risk_adjust);
            if det.id == "private-key" && h.encrypted {
                risk = risk.shift(-1);
            }
            if c.kind == Where::CredentialFile && h.shared_readable {
                risk = risk.shift(1);
            }
            let place = Place {
                path: display(&c.path, opts.home.as_deref()),
                line: h.line,
                column: h.column,
                kind: c.kind,
                risk,
                context: h.context,
                note: base.1.clone(),
            };
            let s = secrets.entry(h.id.clone()).or_insert_with(|| Secret {
                id: h.id.clone(),
                detector: det.id,
                name: det.name,
                provider: det.provider,
                masked: h.masked.clone(),
                risk,
                rotate: det.rotate,
                fix: Vec::new(),
                places: Vec::new(),
            });
            s.risk = s.risk.max(risk);
            if !s.places.iter().any(|p| p.path == place.path && p.line == place.line) {
                s.places.push(place);
            }
        }
    }
    let mut secrets: Vec<Secret> = secrets.into_values().collect();
    for s in &mut secrets {
        s.places.sort_by(|a, b| {
            b.risk.cmp(&a.risk).then(a.kind.cmp(&b.kind)).then(a.path.cmp(&b.path)).then(a.line.cmp(&b.line))
        });
        s.fix = advice(s, DETECTORS.iter().find(|d| d.id == s.detector).unwrap());
    }
    secrets.sort_by(|a, b| {
        b.risk.cmp(&a.risk).then(b.places.len().cmp(&a.places.len())).then(a.name.cmp(b.name))
    });
    let places = secrets.iter().map(|s| s.places.len()).sum();
    Report {
        tool: "keyleak",
        version: env!("CARGO_PKG_VERSION"),
        roots: opts.roots.iter().map(|r| display(r, opts.home.as_deref())).collect(),
        mode: if opts.all { "all text files" } else { "usual leak spots" },
        duration_ms: started.elapsed().as_millis(),
        stats,
        secrets_exposed: secrets.len(),
        places,
        secrets,
    }
}

pub fn display(p: &Path, home: Option<&Path>) -> String {
    match home.and_then(|h| p.strip_prefix(h).ok()) {
        Some(r) if r.as_os_str().is_empty() => "~".into(),
        Some(r) => format!("~/{}", r.display()),
        None => p.display().to_string(),
    }
}

/// A path for CLI messages: relative when inside `cwd`, else `~`-shortened,
/// so screen recordings never show the user's folder names.
pub fn short(p: &Path, home: Option<&Path>, cwd: Option<&Path>) -> String {
    match cwd.filter(|c| c.parent().is_some()).and_then(|c| p.strip_prefix(c).ok()) {
        Some(r) if r.as_os_str().is_empty() => ".".into(),
        Some(r) => r.display().to_string(),
        None => display(p, home),
    }
}

// ---------------------------------------------------------------- walking

/// Folders that are huge, rebuildable or hold keys where they belong.
const SKIP_NAMES: &[&str] = &[
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "site-packages",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".parcel-cache",
    "bower_components",
    ".gradle",
    ".terraform",
    ".direnv",
    ".pnpm-store",
    "target",
    "Cache",
    "Code Cache",
    "GPUCache",
    "CachedData",
    "Service Worker",
    "IndexedDB",
    "blob_storage",
    "Crashpad",
    "DawnCache",
    "DawnGraphiteCache",
    "DawnWebGPUCache",
    "ShaderCache",
    "GrShaderCache",
    "Session Storage",
    "Local Storage",
    "WebStorage",
];

/// Paths relative to the scan root that are skipped.
const SKIP_PATHS: &[&str] = &[
    ".cache",
    ".npm",
    ".cargo/registry",
    ".cargo/git",
    ".rustup",
    ".local/share/Trash",
    ".local/share/Steam",
    ".steam",
    ".mozilla",
    ".thunderbird",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/microsoft-edge",
    ".vscode/extensions",
    ".vscode-server",
    ".cursor/extensions",
    ".m2",
    "go/pkg",
    ".local/lib",
    ".local/share/uv",
    ".local/share/pnpm",
    ".bun/install",
    ".android",
    ".wine",
    ".local/share/containers",
    ".local/share/flatpak",
    ".var/app",
    "snap",
    ".ollama",
    ".nvm/versions",
    ".pyenv/versions",
    ".conda/pkgs",
    "anaconda3/pkgs",
    "miniconda3/pkgs",
    ".local/share/docker",
    ".local/share/keyrings",
    ".ssh",
    ".gnupg",
    ".pki",
    ".password-store",
];

fn walk(
    root: &Path,
    opts: &Options,
    out: &mut Vec<Candidate>,
    seen: &mut HashSet<(u64, u64)>,
    stats: &mut Stats,
) {
    let Ok(root_canon) = fs::canonicalize(root) else { return };
    let root_dev = dev_of(&root_canon);
    if root_canon.is_file() {
        let name = root_canon.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        push(out, seen, &root_canon, root_canon.clone(), classify(&name, &name));
        return;
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            stats.skipped_unreadable += 1;
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            let Ok(ft) = e.file_type() else { continue };
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            let name = e.file_name().to_string_lossy().into_owned();
            if opts.ignore.ignores_path(&path, &rel) {
                stats.skipped_ignored += 1;
                continue;
            }
            if ft.is_dir() {
                if name == ".git" {
                    let cfg = path.join("config");
                    if cfg.is_file() {
                        push(out, seen, &cfg, cfg.clone(), Where::GitConfig);
                    }
                    continue;
                }
                if SKIP_NAMES.contains(&name.as_str()) || SKIP_PATHS.contains(&rel.as_str()) {
                    continue;
                }
                if root_dev.is_some() && dev_of(&path) != root_dev {
                    continue; // another filesystem (network mount, FUSE, USB disk)
                }
                stack.push(path);
            } else if ft.is_file() {
                if opts.all || wanted(&rel, &name) {
                    push(out, seen, &path, path.clone(), classify(&rel, &name));
                }
            } else if ft.is_symlink() {
                // Follow links to files that stay inside the root (dotfile
                // managers like stow); never leave the root, never follow dirs.
                match fs::canonicalize(&path) {
                    Ok(t) if t.starts_with(&root_canon) && t.is_file() => {
                        if opts.all || wanted(&rel, &name) {
                            push(out, seen, &t, path.clone(), classify(&rel, &name));
                        }
                    }
                    _ => stats.skipped_symlinks += 1,
                }
            }
        }
    }
}

fn push(out: &mut Vec<Candidate>, seen: &mut HashSet<(u64, u64)>, real: &Path, path: PathBuf, kind: Where) {
    if let Some(id) = file_id(real) {
        if !seen.insert(id) {
            return;
        }
    }
    out.push(Candidate { path, kind });
}

#[cfg(unix)]
fn dev_of(p: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(p).ok().map(|m| m.dev())
}
#[cfg(not(unix))]
fn dev_of(_: &Path) -> Option<u64> {
    None
}
#[cfg(unix)]
fn file_id(p: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(p).ok().map(|m| (m.dev(), m.ino()))
}
#[cfg(not(unix))]
fn file_id(_: &Path) -> Option<(u64, u64)> {
    None
}

fn is_history(name: &str) -> bool {
    name.ends_with("_history") || name.ends_with("-history") || name == ".histfile" || name == "fish_history"
}

fn is_env(name: &str) -> bool {
    name == ".env" || name.starts_with(".env.") || name.ends_with(".env") || name == ".envrc"
}

const SHELL_RC: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_aliases",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zsh_aliases",
    ".kshrc",
    ".cshrc",
    ".tcshrc",
    "config.fish",
    ".xprofile",
];

const CONFIG_EXT: &[&str] = &[
    "json",
    "jsonl",
    "toml",
    "yaml",
    "yml",
    "ini",
    "conf",
    "cfg",
    "env",
    "properties",
    "txt",
    "md",
    "log",
    "sh",
    "zsh",
    "bash",
    "fish",
    "xml",
    "plist",
    "config",
    "local",
    "credentials",
    "netrc",
];

/// The usual leak spots. Everything else needs `--all`.
fn wanted(rel: &str, name: &str) -> bool {
    if name.starts_with('.') || is_history(name) || is_env(name) || SHELL_RC.contains(&name) {
        return true;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    // Anything config-like inside a dot folder (~/.config, ~/.aws, ~/.claude ...).
    if rel.starts_with('.') && ext.as_deref().map_or(true, |e| CONFIG_EXT.contains(&e)) {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.starts_with("credentials")
        || lower.starts_with("secrets.")
        || lower.ends_with(".tfvars")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.starts_with("id_rsa")
        || lower.starts_with("id_ed25519")
        || lower.starts_with("id_ecdsa")
        || lower.starts_with("docker-compose")
        || lower == "compose.yml"
        || lower == "compose.yaml"
        || lower.starts_with("service-account")
}

const AGENT_DIRS: &[&str] = &[
    "claude", "codex", "gemini", "opencode", "aider", "cursor", "continue", "grok", "kimi", "cline", "goose",
    "hermes", "windsurf", "copilot", "amp",
];

fn classify(rel: &str, name: &str) -> Where {
    let lower = rel.to_ascii_lowercase();
    let first = lower.split('/').next().unwrap_or("");
    let in_agent_dir = first.starts_with('.') && AGENT_DIRS.iter().any(|a| first.contains(a))
        || lower.starts_with(".local/share/opencode")
        || lower.starts_with(".config/opencode");
    if is_history(name) && !in_agent_dir {
        return Where::History;
    }
    if is_env(name) {
        return Where::EnvFile;
    }
    if SHELL_RC.contains(&name)
        || name.ends_with(".zsh")
        || name.ends_with(".sh")
        || name.ends_with(".bash")
        || name.ends_with(".fish")
    {
        return Where::ShellConfig;
    }
    if name == ".gitconfig" || lower.ends_with(".git/config") || lower.ends_with(".config/git/config") {
        return Where::GitConfig;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
    if in_agent_dir
        && (name.starts_with(".aider")
            || matches!(ext.as_deref(), Some("jsonl" | "md" | "log" | "txt"))
            || lower.contains("history")
            || lower.contains("session"))
    {
        return Where::AgentLog;
    }
    let cred_names = [
        ".npmrc",
        ".netrc",
        ".pypirc",
        ".git-credentials",
        ".boto",
        ".s3cfg",
        ".terraformrc",
        ".dockercfg",
        "hosts.yml",
        "rclone.conf",
    ];
    if cred_names.contains(&name)
        || lower.contains("credential")
        || name == "auth.json"
        || lower.starts_with(".aws/")
        || lower.starts_with(".kube/")
        || lower.starts_with(".docker/")
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
    {
        return Where::CredentialFile;
    }
    if first.starts_with('.') {
        return Where::AppConfig;
    }
    Where::File
}

/// Risk of a place before detector adjustments, and an optional note.
fn base_risk(c: &Candidate, home: Option<&Path>) -> (Risk, Option<String>) {
    match c.kind {
        Where::History | Where::AgentLog | Where::ShellConfig | Where::GitConfig => (Risk::High, None),
        Where::EnvFile => match git_ignored(&c.path, home) {
            Some((repo, false)) => (
                Risk::Critical,
                Some(format!("inside git repo {} and not in .gitignore", display(&repo, home))),
            ),
            Some((_, true)) => (Risk::Medium, Some("git-ignored".into())),
            None => (Risk::Medium, None),
        },
        Where::CredentialFile => (Risk::Low, None),
        Where::AppConfig | Where::File => (Risk::Medium, None),
    }
}

// ---------------------------------------------------------------- one file

struct RawPlace {
    detector: usize,
    id: String,
    masked: String,
    line: usize,
    column: usize,
    context: String,
    encrypted: bool,
    shared_readable: bool,
}

enum FileResult {
    Hits(Vec<RawPlace>, u64),
    Large,
    Binary,
    Unreadable,
}

fn scan_file(path: &Path, limit: u64, strict: bool) -> FileResult {
    let Ok(f) = fs::File::open(path) else { return FileResult::Unreadable };
    let Ok(meta) = f.metadata() else { return FileResult::Unreadable };
    if meta.len() > limit {
        return FileResult::Large;
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    if f.take(limit + 1).read_to_end(&mut buf).is_err() {
        return FileResult::Unreadable;
    }
    if buf.len() as u64 > limit {
        return FileResult::Large;
    }
    if buf[..buf.len().min(8192)].contains(&0) {
        return FileResult::Binary;
    }
    #[cfg(unix)]
    let shared_readable = {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o044 != 0
    };
    #[cfg(not(unix))]
    let shared_readable = false;
    let text = String::from_utf8_lossy(&buf);
    let hits = detect::find(&text, strict);
    if hits.is_empty() {
        return FileResult::Hits(Vec::new(), buf.len() as u64);
    }
    let line_starts: Vec<usize> =
        std::iter::once(0).chain(text.match_indices('\n').map(|(i, _)| i + 1)).collect();
    let places = hits
        .iter()
        .map(|h| {
            let det = &DETECTORS[h.detector];
            let secret = &text[h.start..h.end];
            let li = line_starts.partition_point(|&s| s <= h.start) - 1;
            let (id, encrypted) = if det.id == "private-key" {
                // Group private keys by their body, not by the shared header.
                let body: String = text[h.end..].chars().filter(|c| !c.is_whitespace()).take(120).collect();
                (
                    detect::fingerprint(det, &body),
                    secret.contains("ENCRYPTED") || text[h.end..].starts_with("\nProc-Type: 4,ENCRYPTED"),
                )
            } else {
                (detect::fingerprint(det, secret), false)
            };
            RawPlace {
                detector: h.detector,
                id,
                masked: detect::mask(det, secret),
                line: li + 1,
                column: h.start - line_starts[li] + 1,
                context: context(&text, h, &hits),
                encrypted,
                shared_readable,
            }
        })
        .collect();
    FileResult::Hits(places, buf.len() as u64)
}

/// The hit's line with every detected secret masked and any other long random
/// token blanked, trimmed to a window around the hit.
fn context(text: &str, hit: &detect::Hit, all: &[detect::Hit]) -> String {
    let w = detect::near(text, hit.start, hit.end);
    let mut ws = w.as_ptr() as usize - text.as_ptr() as usize;
    let mut we = ws + w.len();
    // Never cut a secret or a token in half at the window edges.
    let tokenish = |b: u8| b.is_ascii_alphanumeric() || b"_-+/=.".contains(&b);
    let bytes = text.as_bytes();
    while ws > 0 && tokenish(bytes[ws - 1]) {
        ws -= 1;
    }
    while we < bytes.len() && tokenish(bytes[we]) {
        we += 1;
    }
    let first = all.partition_point(|h| h.end <= ws);
    let near: Vec<&detect::Hit> = all[first..].iter().take_while(|h| h.start < we).collect();
    if let Some(h) = near.first() {
        ws = ws.min(h.start);
    }
    if let Some(h) = near.last() {
        we = we.max(h.end);
    }
    let mut out = String::new();
    let mut at = ws;
    let mut focus = 0;
    for h in near {
        out.push_str(&blank_tokens(&text[at..h.start]));
        if h.start == hit.start {
            focus = out.chars().count();
        }
        out.push_str(&detect::mask(&DETECTORS[h.detector], &text[h.start..h.end]));
        at = h.end;
    }
    out.push_str(&blank_tokens(&text[at..we]));
    // zsh extended history prefix ": 1726000000:0;"
    let trimmed_lead = out.len() - out.trim_start().len();
    let mut chars: Vec<char> = out.trim().chars().collect();
    focus = focus.saturating_sub(trimmed_lead);
    if chars.first() == Some(&':') {
        if let Some(p) = chars.iter().position(|&c| c == ';') {
            if p < 20 {
                chars.drain(..=p);
                focus = focus.saturating_sub(p + 1);
            }
        }
    }
    const W: usize = 96;
    if chars.len() > W {
        let start = focus.saturating_sub(40).min(chars.len() - W);
        let mut s: String = chars[start..start + W].iter().collect();
        if start > 0 {
            s.insert(0, '…');
        }
        if start + W < chars.len() {
            s.push('…');
        }
        return s;
    }
    chars.into_iter().collect()
}

fn blank_tokens(s: &str) -> String {
    use regex::Regex;
    use std::sync::OnceLock;
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"[A-Za-z0-9_\-+/=.]{20,}").unwrap());
    re.replace_all(s, |c: &regex::Captures| {
        let t = &c[0];
        let digits = t.bytes().any(|b| b.is_ascii_digit());
        if digits && detect::entropy(t) >= 3.5 && !t.contains('/') {
            "•••".to_string()
        } else {
            t.to_string()
        }
    })
    .into_owned()
}

// ---------------------------------------------------------------- advice

fn advice(s: &Secret, det: &Detector) -> Vec<String> {
    let mut fix = Vec::new();
    let kinds: Vec<Where> = {
        let mut k: Vec<Where> = s.places.iter().map(|p| p.kind).collect();
        k.sort();
        k.dedup();
        k
    };
    let burned = kinds.iter().any(|k| matches!(k, Where::History | Where::AgentLog | Where::GitConfig))
        || s.risk == Risk::Critical;
    let rotate = if det.rotate.starts_with("http") {
        format!("Rotate it at {}", det.rotate)
    } else {
        det.rotate.to_string()
    };
    fix.push(if burned { format!("{rotate}. It sat in plain text, so treat it as leaked.") } else { rotate });
    let var = env_name(s);
    for k in kinds {
        let line = match k {
            Where::History => {
                let mut files: Vec<&str> = s.places.iter().filter(|p| p.kind == Where::History).map(|p| p.path.as_str()).collect();
                files.dedup();
                let file = files[0];
                let lines: Vec<String> = s.places.iter().filter(|p| p.path == file).map(|p| p.line.to_string()).collect();
                let which = match lines.len() {
                    1 => format!("line {}", lines[0]),
                    n if n <= 4 => format!("lines {}", lines.join(", ")),
                    n => format!("all {n} lines with it (line {}, {}, {} …)", lines[0], lines[1], lines[2]),
                };
                let others = if files.len() > 1 { format!(" and {} more history files", files.len() - 1) } else { String::new() };
                let tip = if file.contains("fish") {
                    "In fish: `history delete --contains <first chars>`."
                } else if file.contains("bash") {
                    "Tip: `HISTCONTROL=ignorespace`, then start secret commands with a space."
                } else {
                    "Tip: `setopt HIST_IGNORE_SPACE`, then start secret commands with a space."
                };
                format!("Delete {which} from {file}{others}, with other terminals closed. {tip}")
            }
            Where::AgentLog => "It was pasted into an AI chat, so it also went to that AI provider. Rotate it, then delete the session log.".into(),
            Where::EnvFile => {
                if s.places.iter().any(|p| p.kind == Where::EnvFile && p.risk == Risk::Critical) {
                    "Add `.env` to .gitignore before your next commit. If it was ever committed or pushed, only rotating fixes it.".into()
                } else {
                    format!("OK for local dev while git-ignored. Safer: keep it in your keyring and load it at run time ({}).", keyring_load(&var))
                }
            }
            Where::ShellConfig => format!("Move it to your keyring: {}, then replace the line with: export {var}=\"$({})\"", keyring_store(&var), keyring_lookup(&var)),
            Where::GitConfig => "Take the token out of the remote URL: `git remote set-url origin <url without the token>`, and let a credential helper store it.".into(),
            Where::CredentialFile => {
                let p = s.places.iter().find(|p| p.kind == Where::CredentialFile).unwrap();
                format!("This tool expects it here. Keep the file private: `chmod 600 {}`.", p.path)
            }
            Where::AppConfig | Where::File => "If the app can read it from an environment variable or the keyring, move it there; else `chmod 600` the file.".into(),
        };
        fix.push(line);
    }
    fix
}

fn env_name(s: &Secret) -> String {
    for p in &s.places {
        if let Some(i) = p.context.find(&s.masked) {
            let before = p.context[..i].trim_end_matches(['=', ' ', '"', '\'', ':']);
            let name: String =
                before.chars().rev().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            let name: String = name.chars().rev().collect();
            if name.len() >= 3
                && name.chars().any(|c| c.is_ascii_uppercase())
                && name == name.to_ascii_uppercase()
            {
                return name;
            }
        }
    }
    let p: String = s
        .provider
        .to_ascii_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    format!("{p}_API_KEY")
}

fn keyring_store(var: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("`security add-generic-password -a \"$USER\" -s {var} -w`")
    } else {
        format!("`secret-tool store --label={var} keyleak {var}`")
    }
}

fn keyring_lookup(var: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("security find-generic-password -s {var} -w")
    } else {
        format!("secret-tool lookup keyleak {var}")
    }
}

fn keyring_load(var: &str) -> String {
    format!("`{var}=\"$({})\" npm run dev`", keyring_lookup(var))
}
