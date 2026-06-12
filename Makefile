# Compiled by `make build-examples`; the golden comparison reads the
# counter artifact from here.
COUNTER_VERIFIER := target/nocturne/counter_contract/counter/keys/increment.verifier
GOLDEN_VERIFIER  := tests/golden/counter-increment.verifier

# Regenerating the golden needs the stock Compact compiler on PATH
# (~/.compact/bin/compactc on a default install). Override to use another.
COMPACTC ?= compactc

.PHONY: help fmt fmt-check clippy check test build audit ci \
        build-examples golden-check regen-golden

help:
	@echo "Nocturne make targets:"
	@echo ""
	@echo "  Lint / build / test"
	@echo "    fmt            cargo fmt --all"
	@echo "    fmt-check      cargo fmt --all --check"
	@echo "    clippy         cargo clippy --workspace --all-targets -- -D warnings"
	@echo "    check          cargo check --workspace"
	@echo "    test           cargo test --workspace (includes the prove+verify suite; slow)"
	@echo "    build          cargo build --workspace"
	@echo "    audit          cargo audit (needs cargo-audit installed)"
	@echo "    ci             fmt-check + clippy + check + test (the CI gates)"
	@echo ""
	@echo "  Contract artifacts"
	@echo "    build-examples build + keygen both example contracts via cargo-nocturne"
	@echo "    golden-check   byte-compare the counter verifier key against the compactc golden"
	@echo "    regen-golden   regenerate the golden with compactc (see tests/golden/README.md)"

# ============================================================
# Lint / build / test  (the CI workflow calls these targets)
# ============================================================

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets --locked -- -D warnings

check:
	cargo check --workspace --all-targets --locked

test:
	cargo test --workspace --locked

build:
	cargo build --workspace --locked

# cargo audit checks Cargo.lock against the RustSec advisory database.
# Not yet a CI gate; run it before releases.
audit:
	cargo audit

ci: fmt-check clippy check test
	@echo "OK: local CI gates passed"

# ============================================================
# Contract artifacts
# ============================================================

# Build + keygen the example contracts. cargo-nocturne resolves the
# target dir via cargo metadata, so this works from the repo root as-is.
# The first run downloads Midnight's universal setup params (network).
build-examples:
	cargo run --locked -p cargo-nocturne -- nocturne build

golden-check:
	@test -f $(COUNTER_VERIFIER) || { echo "missing $(COUNTER_VERIFIER); run 'make build-examples' first"; exit 1; }
	cmp $(COUNTER_VERIFIER) $(GOLDEN_VERIFIER)
	@echo "OK: counter verifier key matches the compactc golden"

# Regenerate the compactc golden. Bump the compactc version recorded in
# tests/golden/README.md whenever this runs.
regen-golden:
	@command -v $(COMPACTC) >/dev/null || { echo "compactc not found ('$(COMPACTC)'); set COMPACTC=<path>"; exit 1; }
	rm -rf /tmp/nocturne-golden-out
	$(COMPACTC) tests/golden/counter.compact /tmp/nocturne-golden-out
	cp /tmp/nocturne-golden-out/keys/increment.verifier $(GOLDEN_VERIFIER)
	@echo "OK: golden regenerated; update the compactc version in tests/golden/README.md"
