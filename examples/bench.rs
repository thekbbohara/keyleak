//! Time each detector on a file: `cargo run --release --example bench -- FILE`.
//! Prints only timings and hit counts, never the matches.

fn main() {
    let path = std::env::args().nth(1).expect("usage: bench FILE");
    let text = String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned();
    let mb = text.len() as f64 / 1e6;
    let t = std::time::Instant::now();
    let hits = keyleak::detect::find(&text, false).len();
    let s = t.elapsed().as_secs_f64();
    println!("all detectors: {:.1} MB in {:.3}s = {:.0} MB/s, {hits} hits", mb, s, mb / s);
    for (id, secs) in keyleak::detect::profile(&text) {
        println!("{id:>16} {:>8.1} MB/s", mb / secs);
    }
}
