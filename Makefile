FEATURES ?= logging,tls12


.PHONY: fmt
fmt:
	cargo fmt --all --check

.PHONY: lint
lint:
	cargo clippy --workspace --all-targets -F "$(FEATURES)"

.PHONY: test
test:
	cargo test --all-targets -F "$(FEATURES)"

.PHONY: build
build:
	cargo build --all-targets -F "$(FEATURES)"