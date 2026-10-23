# Builds run in a memory-capped scope when systemd is available.
CAP := $(shell command -v systemd-run >/dev/null 2>&1 && echo systemd-run --user --scope -q -p MemoryMax=4G)
BIN := target/release/keyleak
DEMO := target/demo-home

.PHONY: build test check demo demo-html shots gif release clean

build:
	$(CAP) cargo build --release --locked

test:
	$(CAP) cargo test --locked

check:
	cargo fmt --check
	$(CAP) cargo clippy --all-targets --locked -- -D warnings
	$(CAP) cargo test --locked

# Fake home with fake keys, scanned in colour. For screen recordings.
demo: build
	clear
	@$(BIN) demo $(DEMO) --color || true

# Same, plus the HTML report (opens in your browser).
demo-html: build
	@$(BIN) demo $(DEMO) --html target/keyleak-demo.html >/dev/null || true
	@echo "target/keyleak-demo.html  (add #still to the URL to skip the animation)"
	@xdg-open target/keyleak-demo.html 2>/dev/null || open target/keyleak-demo.html 2>/dev/null || true

# Screenshots of the demo HTML report (needs Chrome or Chromium).
shots: build
	sh scripts/screenshots.sh

# docs/demo.gif from `keyleak demo` (needs asciinema and agg).
gif: build
	sh scripts/demo-gif.sh

# Static x86_64 Linux tarball + SHA256SUMS (musl), in target/dist.
release:
	$(CAP) sh scripts/release.sh

clean:
	cargo clean
