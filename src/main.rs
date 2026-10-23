use keyleak::ignore::Ignore;
use keyleak::scan::{self, Options};
use keyleak::{demo, html, term};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const HELP: &str = "\
keyleak - find API keys leaked in your shell history, .env files, dotfiles and AI agent logs

USAGE:
    keyleak [OPTIONS]          scan your home folder
    keyleak demo [DIR]         write a fake home with fake keys to DIR (default: a temp folder) and scan it

OPTIONS:
    -p, --path <PATH>          scan this folder or file instead of ~ (repeatable)
    -a, --all                  scan every text file, not only the usual leak spots
        --json                 print the report as JSON
        --html [FILE]          also write an HTML report (default: keyleak-report.html)
        --ignore-file <FILE>   extra ignore file (always read: ~/.keyleakignore, <path>/.keyleakignore)
        --max-size <MB>        skip files bigger than this (default: 10; history and agent logs: 64)
        --show <N>             places listed per key in the terminal (default: 3)
        --color / --no-color   force colours on or off (default: on for a terminal, off with NO_COLOR)
    -h, --help                 print this help
    -V, --version              print the version

Keys are always masked. Nothing is changed and nothing is sent over the network.
Exit code: 0 no keys found, 1 keys found, 2 error.
";

struct Args {
    demo: Option<Option<PathBuf>>,
    paths: Vec<PathBuf>,
    all: bool,
    json: bool,
    html: Option<PathBuf>,
    ignore_files: Vec<PathBuf>,
    max_size: u64,
    show: usize,
    color: Option<bool>,
}

fn parse() -> Result<Args, String> {
    let mut a = Args {
        demo: None,
        paths: vec![],
        all: false,
        json: false,
        html: None,
        ignore_files: vec![],
        max_size: scan::DEFAULT_MAX_SIZE,
        show: 3,
        color: None,
    };
    let mut it = std::env::args_os().skip(1).peekable();
    let mut first = true;
    while let Some(arg) = it.next() {
        let s = arg.to_string_lossy().into_owned();
        let mut value = |name: &str| it.next().ok_or_else(|| format!("{name} needs a value"));
        match s.as_str() {
            "demo" if first => {
                let dir = match it.peek() {
                    Some(v) if !v.to_string_lossy().starts_with('-') => {
                        Some(PathBuf::from(it.next().unwrap()))
                    }
                    _ => None,
                };
                a.demo = Some(dir);
            }
            "-p" | "--path" => a.paths.push(PathBuf::from(value(&s)?)),
            "-a" | "--all" => a.all = true,
            "--json" => a.json = true,
            "--html" => {
                a.html = Some(match it.peek() {
                    Some(v) if !v.to_string_lossy().starts_with('-') => PathBuf::from(it.next().unwrap()),
                    _ => PathBuf::from("keyleak-report.html"),
                })
            }
            "--ignore-file" => a.ignore_files.push(PathBuf::from(value(&s)?)),
            "--max-size" => {
                let mb: f64 =
                    value(&s)?.to_string_lossy().parse().map_err(|_| "--max-size takes a number of MB")?;
                a.max_size = (mb * 1024.0 * 1024.0) as u64;
            }
            "--show" => a.show = value(&s)?.to_string_lossy().parse().map_err(|_| "--show takes a number")?,
            "--color" => a.color = Some(true),
            "--no-color" => a.color = Some(false),
            "-h" | "--help" => {
                print!("{HELP}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("keyleak {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            _ => return Err(format!("unknown argument '{s}' (see keyleak --help)")),
        }
        first = false;
    }
    Ok(a)
}

fn main() -> ExitCode {
    match run() {
        Ok(found) => ExitCode::from(if found { 1 } else { 0 }),
        Err(e) => {
            eprintln!("keyleak: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool, String> {
    let a = parse()?;
    let real_home = std::env::var_os("HOME").map(PathBuf::from).filter(|h| h.is_dir());
    let (roots, home) = if let Some(dir) = &a.demo {
        let dir = dir.clone().unwrap_or_else(|| std::env::temp_dir().join("keyleak-demo-home"));
        demo::write_fake_home(&dir).map_err(|e| format!("cannot write demo to {}: {e}", dir.display()))?;
        let dir = std::fs::canonicalize(&dir).map_err(|e| e.to_string())?;
        if !a.json {
            eprintln!("keyleak: demo home with fake keys written to {}", short(&dir, real_home.as_deref()));
        }
        (vec![dir.clone()], Some(dir))
    } else if !a.paths.is_empty() {
        for p in &a.paths {
            if !p.exists() {
                return Err(format!("{} does not exist", p.display()));
            }
        }
        let roots = a.paths.iter().map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone())).collect();
        (roots, real_home.clone())
    } else {
        let h = real_home.clone().ok_or("HOME is not set; use --path")?;
        (vec![h], real_home.clone())
    };

    let mut ignore = Ignore::default();
    let mut ignore_files: Vec<PathBuf> = Vec::new();
    if a.demo.is_none() {
        ignore_files.extend(real_home.iter().map(|h| h.join(".keyleakignore")));
    }
    ignore_files.extend(roots.iter().map(|r| r.join(".keyleakignore")));
    for f in &ignore_files {
        if let Ok(t) = std::fs::read_to_string(f) {
            ignore.add(&t, home.as_deref());
        }
    }
    for f in &a.ignore_files {
        let t = std::fs::read_to_string(f).map_err(|e| format!("cannot read {}: {e}", f.display()))?;
        ignore.add(&t, home.as_deref());
    }

    let opts = Options { roots, all: a.all, max_size: a.max_size, ignore, home };
    let report = scan::scan(&opts);

    if let Some(path) = &a.html {
        write_html(path, &html::render(&report))?;
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        let color = a
            .color
            .unwrap_or_else(|| std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none());
        print!("{}", term::render(&report, &term::Style { color, max_places: a.show }));
        if let Some(path) = &a.html {
            println!("  HTML report: {}\n", short(path, real_home.as_deref()));
        }
    }
    Ok(report.secrets_exposed > 0)
}

/// `p` relative to the working folder or `~`-shortened, for messages.
fn short(p: &Path, home: Option<&Path>) -> String {
    let cwd = std::env::current_dir().ok();
    let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
    scan::short(&abs, home, cwd.as_deref())
}

/// The report holds only masked keys, but paths and context are still
/// private, so the file is created readable by the owner only.
fn write_html(path: &Path, body: &str) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    f.write_all(body.as_bytes()).map_err(|e| e.to_string())
}
