//! `.keyleakignore` files and a small glob matcher shared with the
//! `.gitignore` check.
//!
//! Format, one entry per line:
//!   # comment
//!   id:3fa9c2d1          ignore one secret everywhere (the id is in the report)
//!   *.example            no slash: matches a file or folder name at any depth
//!   projects/old/**      with a slash: matches the path relative to the scan root
//!   ~/notes/keys.md      starting with ~/ or /: matches the absolute path

use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Default, Debug)]
pub struct Ignore {
    ids: HashSet<String>,
    globs: Vec<Glob>,
}

#[derive(Debug)]
struct Glob {
    pat: String,
    kind: GlobKind,
}

#[derive(Debug, PartialEq)]
enum GlobKind {
    Name,
    Relative,
    Absolute,
}

impl Ignore {
    pub fn parse(text: &str, home: Option<&Path>) -> Ignore {
        let mut ig = Ignore::default();
        ig.add(text, home);
        ig
    }

    pub fn add(&mut self, text: &str, home: Option<&Path>) {
        for line in text.lines().map(str::trim) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(id) = line.strip_prefix("id:") {
                self.ids.insert(id.trim().to_ascii_lowercase());
                continue;
            }
            let mut pat = line.trim_end_matches('/').to_string();
            if let Some(stripped) = pat.strip_suffix("/**") {
                pat = stripped.to_string();
            }
            let kind = if let Some(rest) = pat.strip_prefix("~/") {
                match home {
                    Some(h) => pat = format!("{}/{rest}", h.display()),
                    None => continue,
                }
                GlobKind::Absolute
            } else if pat.starts_with('/') {
                GlobKind::Absolute
            } else if pat.contains('/') {
                GlobKind::Relative
            } else {
                GlobKind::Name
            };
            self.globs.push(Glob { pat, kind });
        }
    }

    pub fn ignores_id(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    /// `rel` is relative to the scan root. A matching folder prunes its subtree.
    pub fn ignores_path(&self, abs: &Path, rel: &str) -> bool {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        let abs = abs.to_string_lossy();
        self.globs.iter().any(|g| match g.kind {
            GlobKind::Name => glob(&g.pat, name),
            GlobKind::Relative => glob(&g.pat, rel),
            GlobKind::Absolute => glob(&g.pat, &abs),
        })
    }
}

/// Glob match: `*` and `?` stay inside one path segment, `**` crosses them.
pub fn glob(pat: &str, s: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') if p.get(1) == Some(&b'*') => {
                let rest = p[2..].strip_prefix(b"/").unwrap_or(&p[2..]);
                (0..=s.len()).any(|i| go(rest, &s[i..]))
            }
            Some(b'*') => {
                let mut i = 0;
                loop {
                    if go(&p[1..], &s[i..]) {
                        return true;
                    }
                    if i == s.len() || s[i] == b'/' {
                        return false;
                    }
                    i += 1;
                }
            }
            Some(b'?') => !s.is_empty() && s[0] != b'/' && go(&p[1..], &s[1..]),
            Some(&c) => s.first() == Some(&c) && go(&p[1..], &s[1..]),
        }
    }
    go(pat.as_bytes(), s.as_bytes())
}

/// Is `file` covered by a `.gitignore` of the repository it lives in?
/// Returns `None` when the file is not inside a git repository.
/// A simplified check (no `!` negations), good enough to warn about `.env`.
pub fn git_ignored(file: &Path, home: Option<&Path>) -> Option<(PathBuf, bool)> {
    let dir = file.parent()?;
    let repo = dir.ancestors().find(|a| a.join(".git").exists())?.to_path_buf();
    let rel = file.strip_prefix(&repo).ok()?.to_string_lossy().into_owned();
    let mut sources: Vec<(PathBuf, String)> = Vec::new();
    for anc in dir.ancestors() {
        if let Ok(t) = std::fs::read_to_string(anc.join(".gitignore")) {
            sources.push((anc.to_path_buf(), t));
        }
        if anc == repo {
            break;
        }
    }
    if let Ok(t) = std::fs::read_to_string(repo.join(".git/info/exclude")) {
        sources.push((repo.clone(), t));
    }
    let global = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| home.map(|h| h.join(".config")))
        .map(|c| c.join("git/ignore"));
    if let Some(t) = global.and_then(|g| std::fs::read_to_string(g).ok()) {
        sources.push((repo.clone(), t));
    }
    let ignored = sources.iter().any(|(base, text)| {
        let sub = file.strip_prefix(base).map(|p| p.to_string_lossy().into_owned()).unwrap_or(rel.clone());
        text.lines().map(str::trim).any(|l| {
            if l.is_empty() || l.starts_with('#') || l.starts_with('!') {
                return false;
            }
            let anchored = l.starts_with('/') || l.trim_end_matches('/').contains('/');
            let p = l.trim_start_matches('/').trim_end_matches('/');
            if anchored {
                glob(p, &sub) || glob(&format!("{p}/**"), &sub)
            } else {
                sub.split('/').any(|seg| glob(p, seg))
            }
        })
    });
    Some((repo, ignored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs() {
        assert!(glob("*.example", ".env.example"));
        assert!(glob(".env*", ".env.local"));
        assert!(!glob("*.env", "dir/x.env"));
        assert!(glob("projects/**/secrets.txt", "projects/a/b/secrets.txt"));
        assert!(glob("projects/**/secrets.txt", "projects/secrets.txt"));
        assert!(glob("a/?.txt", "a/b.txt"));
        assert!(!glob("a/*", "a/b/c"));
    }

    #[test]
    fn ignore_file() {
        let ig = Ignore::parse(
            "# x\nid:ABCD1234\n*.example\nprojects/old/**\n~/notes/keys.md\n",
            Some(Path::new("/h")),
        );
        assert!(ig.ignores_id("abcd1234"));
        assert!(ig.ignores_path(Path::new("/h/p/.env.example"), "p/.env.example"));
        assert!(ig.ignores_path(Path::new("/h/projects/old"), "projects/old"));
        assert!(ig.ignores_path(Path::new("/h/notes/keys.md"), "notes/keys.md"));
        assert!(!ig.ignores_path(Path::new("/h/projects/new/.env"), "projects/new/.env"));
    }

    #[test]
    fn gitignore_check() {
        let t = tempfile::tempdir().unwrap();
        let repo = t.path().join("app");
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        std::fs::create_dir_all(repo.join("sub")).unwrap();
        assert_eq!(git_ignored(&repo.join(".env"), None).map(|r| r.1), Some(false));
        std::fs::write(repo.join(".gitignore"), "node_modules/\n.env\n").unwrap();
        assert_eq!(git_ignored(&repo.join(".env"), None).map(|r| r.1), Some(true));
        assert_eq!(git_ignored(&repo.join("sub/.env"), None).map(|r| r.1), Some(true));
        assert_eq!(git_ignored(&t.path().join("loose.env"), None), None);
    }
}
