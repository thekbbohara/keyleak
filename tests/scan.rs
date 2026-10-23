//! End-to-end tests on generated fake homes. No real keys anywhere.

use keyleak::demo::{fake, write_fake_home};
use keyleak::ignore::Ignore;
use keyleak::scan::{scan, Options, Report, Risk, DEFAULT_MAX_SIZE};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn opts(root: &Path) -> Options {
    Options {
        roots: vec![root.to_path_buf()],
        all: false,
        max_size: DEFAULT_MAX_SIZE,
        ignore: Ignore::default(),
        home: Some(root.to_path_buf()),
    }
}

fn demo_home() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(t.path()).unwrap().join("home");
    write_fake_home(&home).unwrap();
    (t, home)
}

/// Every raw secret in the fixture, found by the detectors themselves.
fn raw_secrets(root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(t) = fs::read_to_string(&p) {
                for h in keyleak::detect::find(&t, false) {
                    out.insert(t[h.start..h.end].to_string());
                }
            }
        }
    }
    out
}

fn detectors(r: &Report) -> Vec<&str> {
    let mut v: Vec<&str> = r.secrets.iter().map(|s| s.detector).collect();
    v.sort();
    v
}

#[test]
fn demo_home_finds_every_planted_key() {
    let (_t, home) = demo_home();
    let r = scan(&opts(&home));
    assert_eq!(
        detectors(&r),
        vec![
            "anthropic",
            "aws-key-id",
            "aws-secret",
            "deepgram-curl",
            "github",
            "github",
            "gitlab",
            "google",
            "groq",
            "huggingface",
            "netrc",
            "npm",
            "openai",
            "openrouter",
            "replicate",
            "slack-webhook",
            "stripe",
            "telegram",
            "url-password",
            "xai",
        ]
    );
    let openai = r.secrets.iter().find(|s| s.detector == "openai").unwrap();
    assert_eq!(openai.places.len(), 38, "37 history lines + 1 agent log");
    assert_eq!(openai.places[0].path, "~/.zsh_history");
    // The .env inside a repo without a .gitignore is the worst place.
    let tg = r.secrets.iter().find(|s| s.detector == "telegram").unwrap();
    assert_eq!(tg.risk, Risk::Critical);
    assert!(tg.places[0].note.as_deref().unwrap().contains("not in .gitignore"));
    // A git-ignored .env.local is only medium.
    let hook = r.secrets.iter().find(|s| s.detector == "slack-webhook").unwrap();
    assert_eq!(hook.risk, Risk::Medium);
    // Private credential files (0600) are low.
    assert_eq!(r.secrets.iter().find(|s| s.detector == "netrc").unwrap().risk, Risk::Low);
    // Placeholders in .env.example and the README are not reported.
    assert!(r.secrets.iter().flat_map(|s| &s.places).all(|p| !p.path.ends_with(".env.example")));
}

#[test]
fn no_output_ever_contains_a_full_secret() {
    let (_t, home) = demo_home();
    let secrets = raw_secrets(&home);
    assert!(secrets.len() >= 20);
    let r = scan(&opts(&home));
    let outputs = [
        serde_json::to_string(&r).unwrap(),
        keyleak::html::render(&r),
        keyleak::term::render(&r, &keyleak::term::Style { color: true, max_places: 100 }),
    ];
    for out in &outputs {
        for s in &secrets {
            // Also no long slice of it: at most the public prefix plus 4 chars.
            let probe = &s[s.len() - 12..];
            assert!(!out.contains(probe), "secret leaked into output");
        }
    }
}

#[test]
fn symlinks_never_leave_the_root() {
    let t = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(t.path()).unwrap();
    let outside = base.join("outside");
    let home = base.join("home");
    fs::create_dir_all(&outside).unwrap();
    fs::create_dir_all(home.join("dotfiles")).unwrap();
    let key = fake("ghp_", 36, 1);
    fs::write(outside.join(".env"), format!("T={key}\n")).unwrap();
    fs::write(home.join("dotfiles/zshrc"), format!("export GH={}\n", fake("ghp_", 36, 2))).unwrap();
    std::os::unix::fs::symlink(outside.join(".env"), home.join(".env")).unwrap();
    std::os::unix::fs::symlink(&outside, home.join(".linked-dir")).unwrap();
    std::os::unix::fs::symlink(home.join("dotfiles/zshrc"), home.join(".zshrc")).unwrap();
    let r = scan(&opts(&home));
    assert_eq!(r.secrets.len(), 1, "only the stow-style link inside home");
    assert_eq!(r.secrets[0].places[0].path, "~/.zshrc");
    assert_eq!(r.stats.skipped_symlinks, 2);
}

#[test]
fn skips_binary_large_and_excluded_folders() {
    let t = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(t.path()).unwrap();
    let key = fake("hf_", 34, 3);
    let mut bin = b"\0\x01binary".to_vec();
    bin.extend_from_slice(key.as_bytes());
    fs::write(home.join(".blob"), bin).unwrap();
    fs::write(home.join(".big"), format!("{key}\n{}", "x".repeat(2 * 1024 * 1024))).unwrap();
    fs::create_dir_all(home.join("app/node_modules/pkg")).unwrap();
    fs::write(home.join("app/node_modules/pkg/.env"), format!("K={key}\n")).unwrap();
    fs::create_dir_all(home.join(".ssh")).unwrap();
    fs::write(home.join(".ssh/id_rsa"), ["-----BEGIN RSA ", "PRIVATE KEY-----\nabc\n"].concat()).unwrap();
    let mut o = opts(&home);
    o.max_size = 1024 * 1024;
    let r = scan(&o);
    assert_eq!(r.secrets.len(), 0);
    assert_eq!(r.stats.skipped_binary, 1);
    assert_eq!(r.stats.skipped_large, 1);
}

#[test]
fn ignore_file_by_id_and_path() {
    let (_t, home) = demo_home();
    let r = scan(&opts(&home));
    let openai = r.secrets.iter().find(|s| s.detector == "openai").unwrap().id.clone();
    let mut o = opts(&home);
    o.ignore = Ignore::parse(&format!("id:{openai}\nprojects/**\n"), Some(&home));
    let r2 = scan(&o);
    assert!(r2.secrets.iter().all(|s| s.detector != "openai"));
    assert!(r2.secrets.iter().flat_map(|s| &s.places).all(|p| !p.path.starts_with("~/projects")));
    assert!(r2.stats.skipped_ignored > 0);
}

#[test]
fn usual_spots_vs_all() {
    let t = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(t.path()).unwrap();
    fs::create_dir_all(home.join("code")).unwrap();
    fs::write(
        home.join("code/main.py"),
        format!("client = OpenAI(api_key=\"{}\")\n", fake("sk-proj-", 60, 4)),
    )
    .unwrap();
    assert_eq!(scan(&opts(&home)).secrets.len(), 0, "source files need --all");
    let mut o = opts(&home);
    o.all = true;
    assert_eq!(scan(&o).secrets.len(), 1);
}

#[test]
fn cli_exit_codes_json_and_private_html() {
    let bin = env!("CARGO_BIN_EXE_keyleak");
    let t = tempfile::tempdir().unwrap();
    let demo = t.path().join("demo");
    let html = t.path().join("report.html");
    let out =
        Command::new(bin).arg("demo").arg(&demo).arg("--json").arg("--html").arg(&html).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["secrets_exposed"], 20);
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(&html).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(fs::read_to_string(&html).unwrap().contains("keys exposed"));

    let clean = t.path().join("clean");
    fs::create_dir_all(&clean).unwrap();
    fs::write(clean.join(".env"), "DEBUG=true\nAPI_KEY=your_api_key_here\n").unwrap();
    let out = Command::new(bin).arg("--path").arg(&clean).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("0 keys exposed"));

    let out = Command::new(bin).arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn no_color_means_no_escape_codes() {
    let t = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_keyleak"))
        .arg("demo")
        .arg(t.path().join("demo"))
        .arg("--no-color")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&out.stdout).contains('\x1b'));
}

#[test]
fn cli_messages_never_show_the_home_path() {
    let bin = env!("CARGO_BIN_EXE_keyleak");
    let t = tempfile::tempdir().unwrap();
    let home = fs::canonicalize(t.path()).unwrap();
    let work = home.join("work");
    fs::create_dir_all(&work).unwrap();
    let out = Command::new(bin)
        .current_dir(&work)
        .env("HOME", &home)
        .args(["demo", "out/demo", "--no-color", "--html"])
        .arg(home.join("report.html"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let (stdout, stderr) = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(stderr.contains("written to out/demo\n"), "{stderr}");
    assert!(stdout.contains("HTML report: ~/report.html\n"), "{stdout}");
    let home = home.to_string_lossy();
    assert!(!stdout.contains(&*home) && !stderr.contains(&*home));
    assert!(!fs::read_to_string(t.path().join("report.html")).unwrap().contains(&*home));
}

#[test]
fn short_paths() {
    use keyleak::scan::short;
    let (home, cwd) = (Some(Path::new("/home/u")), Some(Path::new("/home/u/code/app")));
    assert_eq!(short(Path::new("/home/u/code/app/target/d"), home, cwd), "target/d");
    assert_eq!(short(Path::new("/home/u/code/app"), home, cwd), ".");
    assert_eq!(short(Path::new("/home/u/r.html"), home, cwd), "~/r.html");
    assert_eq!(short(Path::new("/tmp/d"), home, cwd), "/tmp/d");
    assert_eq!(short(Path::new("/tmp/d"), home, Some(Path::new("/"))), "/tmp/d");
}
