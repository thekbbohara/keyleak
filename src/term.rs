//! Coloured terminal report.

use crate::scan::{Report, Risk};
use std::fmt::Write;

pub struct Style {
    pub color: bool,
    /// Places listed per secret before "and N more".
    pub max_places: usize,
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[38;5;196m";
const ORANGE: &str = "\x1b[38;5;208m";
const YELLOW: &str = "\x1b[38;5;220m";
const BLUE: &str = "\x1b[38;5;75m";
const GREEN: &str = "\x1b[38;5;48m";
const GREY: &str = "\x1b[38;5;245m";
const BG_RED: &str = "\x1b[48;5;196m\x1b[38;5;231m";

/// 3x5 pixel digits; each pixel is drawn two cells wide.
const DIGITS: [[&str; 5]; 10] = [
    ["###", "# #", "# #", "# #", "###"],
    [" # ", "## ", " # ", " # ", "###"],
    ["###", "  #", "###", "#  ", "###"],
    ["###", "  #", "###", "  #", "###"],
    ["# #", "# #", "###", "  #", "  #"],
    ["###", "#  ", "###", "  #", "###"],
    ["###", "#  ", "###", "# #", "###"],
    ["###", "  #", "  #", "  #", "  #"],
    ["###", "# #", "###", "# #", "###"],
    ["###", "# #", "###", "  #", "###"],
];

fn big_number(n: usize) -> [String; 5] {
    let mut rows: [String; 5] = Default::default();
    for (i, ch) in n.to_string().chars().enumerate() {
        let g = &DIGITS[ch.to_digit(10).unwrap() as usize];
        for (r, row) in rows.iter_mut().enumerate() {
            if i > 0 {
                row.push_str("  ");
            }
            for px in g[r].chars() {
                row.push_str(if px == '#' { "██" } else { "  " });
            }
        }
    }
    rows
}

fn risk_color(r: Risk) -> &'static str {
    match r {
        Risk::Critical => RED,
        Risk::High => ORANGE,
        Risk::Medium => YELLOW,
        Risk::Low => BLUE,
    }
}

pub fn render(rep: &Report, st: &Style) -> String {
    let c = |code: &'static str| if st.color { code } else { "" };
    let mut o = String::new();
    let secs = rep.duration_ms as f64 / 1000.0;
    let _ = writeln!(
        o,
        "\n  {}{} KEYLEAK {}  {}scanned {} files in {} · {:.2}s · offline, read-only{}",
        c(BOLD),
        c(BG_RED),
        c(RESET),
        c(GREY),
        group(rep.stats.files_scanned),
        rep.roots.join(", "),
        secs,
        c(RESET)
    );
    o.push('\n');

    let n = rep.secrets_exposed;
    if n == 0 {
        let _ =
            writeln!(o, "  {}{}✔ 0 keys exposed.{} Nothing key-shaped found.\n", c(BOLD), c(GREEN), c(RESET));
        return o;
    }
    let rows = big_number(n);
    let side = [
        String::new(),
        format!("{}{}{}", c(BOLD), if n == 1 { "KEY" } else { "KEYS" }, c(RESET)),
        format!("{}{}EXPOSED{}", c(BOLD), c(RED), c(RESET)),
        format!("{}in {} places{}", c(GREY), group(rep.places), c(RESET)),
        String::new(),
    ];
    for (r, row) in rows.iter().enumerate() {
        let _ = writeln!(o, "  {}{}{}{}   {}", c(BOLD), c(RED), row, c(RESET), side[r]);
    }
    o.push('\n');

    let mut by_risk = [0usize; 4];
    for s in &rep.secrets {
        by_risk[s.risk as usize] += 1;
    }
    let mut line = String::from("  ");
    for r in [Risk::Critical, Risk::High, Risk::Medium, Risk::Low] {
        if by_risk[r as usize] > 0 {
            let _ = write!(
                line,
                "{}{}● {} {}{}   ",
                c(BOLD),
                c(risk_color(r)),
                by_risk[r as usize],
                r.label().to_lowercase(),
                c(RESET)
            );
        }
    }
    let _ = writeln!(o, "{}\n", line.trim_end());

    for s in &rep.secrets {
        let col = c(risk_color(s.risk));
        let _ = writeln!(
            o,
            "  {}{}{:<8}{} {}{}{}  {}{}{}  {}×{}{}  {}id:{}{}",
            c(BOLD),
            col,
            s.risk.label(),
            c(RESET),
            c(BOLD),
            s.name,
            c(RESET),
            col,
            s.masked,
            c(RESET),
            c(GREY),
            s.places.len(),
            c(RESET),
            c(DIM),
            s.id,
            c(RESET)
        );
        let shown = s.places.iter().take(st.max_places);
        let width =
            s.places.iter().take(st.max_places).map(|p| loc(p).chars().count()).max().unwrap_or(0).min(34);
        for p in shown {
            let l = loc(p);
            let pad = " ".repeat(width.saturating_sub(l.chars().count()));
            let note = p
                .note
                .as_ref()
                .map(|n| format!("  {}{}⚠ {}{}", c(BOLD), c(risk_color(p.risk)), n, c(RESET)))
                .unwrap_or_default();
            let _ = writeln!(
                o,
                "           {}{}{}{}  {}{}{}{}",
                c(BLUE),
                l,
                c(RESET),
                pad,
                c(GREY),
                p.context,
                c(RESET),
                note
            );
        }
        if s.places.len() > st.max_places {
            let _ = writeln!(
                o,
                "           {}… and {} more places{}",
                c(GREY),
                s.places.len() - st.max_places,
                c(RESET)
            );
        }
        for (i, f) in s.fix.iter().enumerate() {
            let label = if i == 0 { "Fix" } else { "   " };
            let _ = writeln!(o, "           {}{}{} {}", c(GREEN), label, c(RESET), f);
        }
        o.push('\n');
    }

    let types: Vec<String> = rep.count_by(|s| s.provider).iter().map(|(k, v)| format!("{k} {v}")).collect();
    let wheres: Vec<String> =
        rep.places_by_where().iter().map(|(k, v)| format!("{} {v}", k.label())).collect();
    let _ = writeln!(o, "  {}By provider{}  {}", c(BOLD), c(RESET), types.join(" · "));
    let _ = writeln!(o, "  {}By place{}     {}", c(BOLD), c(RESET), wheres.join(" · "));
    let _ = writeln!(
        o,
        "\n  {}Keys are masked. Nothing was changed or sent anywhere. Silence one with `id:<id>` in ~/.keyleakignore.{}\n",
        c(DIM),
        c(RESET)
    );
    o
}

fn loc(p: &crate::scan::Place) -> String {
    format!("{}:{}", p.path, p.line)
}

pub fn group(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    #[test]
    fn grouping_and_digits() {
        assert_eq!(super::group(1234567), "1,234,567");
        assert_eq!(super::group(12), "12");
        assert_eq!(super::big_number(37)[0], "██████  ██████");
    }
}
