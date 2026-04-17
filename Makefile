FEATURES ?= logging,tls12
CARGO_FEATURES := $(if $(strip $(FEATURES)),-F "$(FEATURES)",)


.PHONY: fmt
fmt:
	cargo fmt --check

.PHONY: lint
lint:
	cargo clippy --all-targets $(CARGO_FEATURES)

.PHONY: check
check:
	cargo check --all-targets $(CARGO_FEATURES)

.PHONY: test
test:
	cargo test --all-targets $(CARGO_FEATURES)

.PHONY: build
build:
	cargo build --all-targets $(CARGO_FEATURES)

.PHONY: doc
doc:
	RUSTDOCFLAGS="-D missing_docs" cargo doc --no-deps -F logging,tls12,mlkem
