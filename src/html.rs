//! Self-contained HTML report: no external fonts, scripts or images, so it
//! opens offline and makes no network requests.

use crate::scan::{Report, Risk};
use std::fmt::Write;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(ch),
        }
    }
    o
}

/// Inline `code` spans in advice text.
fn rich(s: &str) -> String {
    esc(s)
        .split('`')
        .enumerate()
        .map(|(i, part)| if i % 2 == 1 { format!("<code>{part}</code>") } else { linkify(part) })
        .collect()
}

fn linkify(s: &str) -> String {
    s.split(' ')
        .map(|w| {
            let url = w.trim_end_matches(['.', ',', ')']);
            if url.starts_with("https://") {
                format!("<a href=\"{url}\" rel=\"noreferrer\">{url}</a>{}", &w[url.len()..])
            } else {
                w.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn risk_class(r: Risk) -> &'static str {
    match r {
        Risk::Critical => "crit",
        Risk::High => "high",
        Risk::Medium => "med",
        Risk::Low => "low",
    }
}

const MAX_PLACES: usize = 6;

pub fn render(rep: &Report) -> String {
    let mut cards = String::new();
    for s in &rep.secrets {
        let mut places = String::new();
        for p in s.places.iter().take(MAX_PLACES) {
            let note = p
                .note
                .as_ref()
                .map(|n| format!("<span class=\"note {}\">⚠ {}</span>", risk_class(p.risk), esc(n)))
                .unwrap_or_default();
            let _ = write!(
                places,
                "<li><div class=\"loc\"><span class=\"tag\">{}</span><span class=\"path\">{}<b>:{}</b></span>{note}</div><code class=\"ctx\">{}</code></li>",
                esc(p.kind.label()),
                esc(&p.path),
                p.line,
                esc(&p.context)
            );
        }
        if s.places.len() > MAX_PLACES {
            let _ = write!(places, "<li class=\"more\">+ {} more places</li>", s.places.len() - MAX_PLACES);
        }
        let fixes: String = s.fix.iter().map(|f| format!("<li>{}</li>", rich(f))).collect();
        let _ = write!(
            cards,
            r#"<article class="card {rc}">
  <header><span class="badge {rc}">{risk}</span><h2>{name}</h2><span class="count">×{n}</span></header>
  <div class="key"><code>{masked}</code><span class="id">id:{id}</span></div>
  <ul class="places">{places}</ul>
  <div class="fix"><h3>How to fix</h3><ol>{fixes}</ol></div>
</article>
"#,
            rc = risk_class(s.risk),
            risk = s.risk.label(),
            name = esc(s.name),
            n = s.places.len(),
            masked = esc(&s.masked),
            id = esc(&s.id),
        );
    }

    let mut chips = String::new();
    for r in [Risk::Critical, Risk::High, Risk::Medium, Risk::Low] {
        let n = rep.secrets.iter().filter(|s| s.risk == r).count();
        if n > 0 {
            let _ = write!(
                chips,
                "<span class=\"chip {}\"><i></i>{n} {}</span>",
                risk_class(r),
                r.label().to_lowercase()
            );
        }
    }
    let providers: String = rep
        .count_by(|s| s.provider)
        .iter()
        .map(|(p, n)| format!("<span>{} <b>{n}</b></span>", esc(p)))
        .collect();
    let wheres: String = rep
        .places_by_where()
        .iter()
        .map(|(w, n)| format!("<span>{} <b>{n}</b></span>", esc(w.label())))
        .collect();

    let n = rep.secrets_exposed;
    let headline = if n == 0 {
        "No keys exposed".to_string()
    } else {
        format!("{} exposed", if n == 1 { "key" } else { "keys" })
    };
    TEMPLATE
        .replace("{{N}}", &n.to_string())
        .replace("{{HEADLINE}}", &headline)
        .replace("{{STATE}}", if n == 0 { "clean" } else { "leaky" })
        .replace("{{PLACES}}", &crate::term::group(rep.places))
        .replace("{{FILES}}", &crate::term::group(rep.stats.files_scanned))
        .replace("{{ROOTS}}", &esc(&rep.roots.join(", ")))
        .replace("{{SECS}}", &format!("{:.2}", rep.duration_ms as f64 / 1000.0))
        .replace("{{VERSION}}", rep.version)
        .replace("{{CHIPS}}", &chips)
        .replace("{{PROVIDERS}}", &providers)
        .replace("{{WHERES}}", &wheres)
        .replace("{{CARDS}}", &cards)
}

const TEMPLATE: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Keyleak report</title>
<style>
:root {
  --bg: #0a0b0e; --panel: #12141a; --line: #23262f; --text: #e8e9ed; --dim: #8b8f9c;
  --crit: #ff3b4e; --high: #ff8a3d; --med: #ffcc4d; --low: #5aa9ff; --ok: #33d69f;
  --mono: ui-monospace, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { margin: 0; color: var(--text); font: 15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
main { max-width: 860px; margin: 0 auto; padding: 40px 24px 64px; }
.top { display: flex; align-items: center; gap: 10px; color: var(--dim); font-size: 13px; }
.logo { background: var(--crit); color: #fff; font-weight: 800; letter-spacing: .08em; padding: 3px 8px; border-radius: 6px; font-size: 12px; }
.hero { padding: 36px 0 28px; border-bottom: 1px solid var(--line); }
.big { font-size: clamp(120px, 26vw, 220px); line-height: .9; font-weight: 900; letter-spacing: -.05em; color: var(--crit); text-shadow: 0 0 60px rgba(255,59,78,.45); font-variant-numeric: tabular-nums; }
.clean .big { color: var(--ok); text-shadow: 0 0 60px rgba(51,214,159,.35); }
.headline { font-size: clamp(28px, 6vw, 44px); font-weight: 800; letter-spacing: -.02em; margin-top: 6px; }
.sub { color: var(--dim); margin-top: 6px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 20px; }
.chip { display: inline-flex; align-items: center; gap: 8px; padding: 6px 12px; border-radius: 999px; background: var(--panel); border: 1px solid var(--line); font-weight: 600; font-size: 14px; }
.chip i { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
.chip.crit { color: var(--crit); } .chip.high { color: var(--high); } .chip.med { color: var(--med); } .chip.low { color: var(--low); }
.sums { display: grid; grid-template-columns: 110px 1fr; gap: 6px 16px; margin: 22px 0 8px; font-size: 14px; }
.sums dt { color: var(--dim); }
.sums dd { margin: 0; display: flex; flex-wrap: wrap; gap: 4px 14px; }
.sums b { color: var(--text); font-variant-numeric: tabular-nums; }
.sums span { color: var(--dim); }
.card { background: var(--panel); border: 1px solid var(--line); box-shadow: inset 4px 0 0 var(--c); border-radius: 14px; padding: 18px 20px; margin-top: 16px; opacity: 0; transform: translateY(10px); animation: in .45s ease forwards; }
.card.crit { --c: var(--crit); } .card.high { --c: var(--high); } .card.med { --c: var(--med); } .card.low { --c: var(--low); }
@keyframes in { to { opacity: 1; transform: none; } }
.card header { display: flex; align-items: center; gap: 12px; }
.card h2 { font-size: 17px; margin: 0; font-weight: 700; flex: 1; min-width: 0; }
.badge { font-size: 11px; font-weight: 800; letter-spacing: .08em; padding: 3px 8px; border-radius: 6px; color: #0a0b0e; background: var(--c); }
.count { font-weight: 800; font-size: 18px; color: var(--c); font-variant-numeric: tabular-nums; }
.key { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 10px; }
.key code { font: 600 15px var(--mono); color: var(--c); background: rgba(255,255,255,.04); padding: 4px 8px; border-radius: 6px; }
.id { font: 12px var(--mono); color: var(--dim); }
.places { list-style: none; padding: 0; margin: 14px 0 0; display: grid; gap: 10px; }
.places li { min-width: 0; }
.loc { display: flex; flex-wrap: wrap; align-items: center; gap: 4px 10px; font-size: 13px; }
.tag { font-size: 11px; font-weight: 600; color: var(--dim); border: 1px solid var(--line); border-radius: 5px; padding: 0 6px; }
.path { font-family: var(--mono); color: var(--low); word-break: break-all; }
.path b { color: var(--dim); font-weight: 400; }
.note { font-size: 12px; font-weight: 700; color: var(--c); }
.note.crit { color: var(--crit); }
.ctx { display: block; margin-top: 4px; font: 12.5px/1.45 var(--mono); color: #b9bcc6; background: #0c0d11; border: 1px solid var(--line); border-radius: 8px; padding: 7px 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
.more { color: var(--dim); font-size: 13px; }
.fix { margin-top: 16px; padding-top: 14px; border-top: 1px dashed var(--line); }
.fix h3 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase; letter-spacing: .1em; color: var(--ok); }
.fix ol { margin: 0; padding-left: 20px; display: grid; gap: 4px; font-size: 14px; }
.fix code { font: 12.5px var(--mono); background: rgba(255,255,255,.06); padding: 1px 5px; border-radius: 4px; word-break: break-all; }
a { color: var(--ok); text-decoration: none; border-bottom: 1px solid rgba(51,214,159,.4); word-break: break-all; }
footer { margin-top: 40px; color: var(--dim); font-size: 13px; text-align: center; }
@media (max-width: 520px) { main { padding: 28px 16px 48px; } .sums { grid-template-columns: 1fr; } .card { padding: 16px; } }
.still .card { animation: none; opacity: 1; transform: none; }
@media (prefers-reduced-motion: reduce) { .card { animation: none; opacity: 1; transform: none; } }
</style>
</head>
<body class="{{STATE}}">
<main>
  <div class="top"><span class="logo">KEYLEAK</span><span>{{ROOTS}} · {{FILES}} files · {{SECS}}s · offline, read-only</span></div>
  <section class="hero">
    <div class="big" id="n" data-n="{{N}}">{{N}}</div>
    <div class="headline">{{HEADLINE}}</div>
    <div class="sub">in {{PLACES}} places. Keys are masked; nothing was changed or sent.</div>
    <div class="chips">{{CHIPS}}</div>
    <dl class="sums"><dt>By provider</dt><dd>{{PROVIDERS}}</dd><dt>By place</dt><dd>{{WHERES}}</dd></dl>
  </section>
  {{CARDS}}
  <footer>Keyleak {{VERSION}} · scans your home for leaked API keys · MIT</footer>
</main>
<script>
(function () {
  var el = document.getElementById('n'), n = +el.dataset.n;
  // #still: final frame right away (screenshots, printing).
  if (location.hash === '#still') { document.body.classList.add('still'); return; }
  if (!n || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var t0 = null, dur = Math.min(1600, 400 + n * 40);
  function step(t) {
    t0 = t0 || t;
    var p = Math.min(1, (t - t0) / dur);
    el.textContent = Math.round(n * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  }
  el.textContent = '0';
  requestAnimationFrame(step);
  document.querySelectorAll('.card').forEach(function (c, i) { c.style.animationDelay = (0.15 + i * 0.07) + 's'; });
})();
</script>
</body>
</html>
"#;
