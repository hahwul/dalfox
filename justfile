default:
    @echo "Listing available tasks..."
    @just --list

test:
    cargo test

test_all:
    cargo test -- --include-ignored

#fix:
#    cargo fmt
#    cargo clippy --fix --allow-dirty

build:
    cargo build --release

dev:
    cargo build

nix-update:
    nix flake update

xss_maze:
    # Install and Run xssmaze
    # git clone https://github.com/hahwul/xssmaze
    # cd xssmaze
    # shards build
    # ./bin/xssmaze

    # Basic
    ./target/debug/dalfox scan "http://localhost:3000/basic/level1/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level2/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level3/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level4/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level5/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/basic/level6/?query=a"

    # DOM
    ./target/debug/dalfox scan "http://localhost:3000/dom/level1/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level2/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level3/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level4/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level5/"
    ./target/debug/dalfox scan "http://localhost:3000/dom/level6/"

    # Decode
    ./target/debug/dalfox scan "http://localhost:3000/decode/level1/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/decode/level2/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/decode/level3/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/decode/level4/?query=a"

    # Hidden
    ./target/debug/dalfox scan "http://localhost:3000/hidden/level1/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/hidden/level2/?query=a"
    ./target/debug/dalfox scan "http://localhost:3000/hidden/level3/?query=a"

    # Path
    ./target/debug/dalfox scan "http://localhost:3000/path/level1/a"
    ./target/debug/dalfox scan "http://localhost:3000/path/level2/a"
    ./target/debug/dalfox scan "http://localhost:3000/path/level3/a"
    ./target/debug/dalfox scan "http://localhost:3000/path/level4/a"
