default:
    @echo "Listing available tasks..."
    @just --list

test:
    cargo test
#    cargo clippy -- --deny warnings
#    cargo clippy --tests -- --deny warnings
#    cargo fmt --check
#    cargo doc --workspace --all-features --no-deps --document-private-items

#fix:
#    cargo fmt
#    cargo clippy --fix --allow-dirty

build:
    cargo build --release

dev:
    cargo build
