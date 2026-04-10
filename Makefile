FEATURES ?= logging,tls12
CARGO_FEATURES := $(if $(strip $(FEATURES)),-F "$(FEATURES)",)


.PHONY: fmt
fmt:
	cargo fmt --all --check

.PHONY: lint
lint:
	cargo clippy --workspace --all-targets $(CARGO_FEATURES)

.PHONY: check
check:
	cargo check --workspace --all-targets $(CARGO_FEATURES)

.PHONY: test
test:
	cargo test --all-targets $(CARGO_FEATURES)

.PHONY: build
build:
	cargo build --all-targets $(CARGO_FEATURES)
