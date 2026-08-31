# Maintainer: HAHWUL <hahwul@gmail.com>
pkgname=dalfox
pkgver=3.2.2
pkgrel=1
pkgdesc="Powerful open-source XSS scanner and utility focused on automation"
arch=('x86_64' 'aarch64')
url="https://github.com/hahwul/dalfox"
license=('MIT')
depends=('gcc-libs')
makedepends=('cargo')
# Disable LTO: makepkg's -flto leaks into ring's `cc` build, producing objects
# that fail to link with lld (undefined `ring_core_*` symbols). See #1061.
options=(!lto)
source=("$pkgname-$pkgver.tar.gz::https://github.com/hahwul/dalfox/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

prepare() {
    cd "$pkgname-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
    cd "$pkgname-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --frozen --release --all-features
}

check() {
    cd "$pkgname-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --frozen --release
}

package() {
    cd "$pkgname-$pkgver"
    install -Dm0755 -t "$pkgdir/usr/bin/" "target/release/$pkgname"
    install -Dm0644 -t "$pkgdir/usr/share/licenses/$pkgname/" LICENSE.txt
    install -Dm0644 -t "$pkgdir/usr/share/doc/$pkgname/" README.md
    # The man page and the shell completions are rendered by the binary we just
    # built (`dalfox man`, `dalfox completion <shell>`) instead of shipping
    # generated copies in the source tree.
    "target/release/$pkgname" man > "$pkgname.1"
    install -Dm0644 "$pkgname.1" "$pkgdir/usr/share/man/man1/$pkgname.1"
    "target/release/$pkgname" completion bash > "$pkgname.bash"
    "target/release/$pkgname" completion zsh > "_$pkgname"
    "target/release/$pkgname" completion fish > "$pkgname.fish"
    install -Dm0644 "$pkgname.bash" "$pkgdir/usr/share/bash-completion/completions/$pkgname"
    install -Dm0644 "_$pkgname" "$pkgdir/usr/share/zsh/site-functions/_$pkgname"
    install -Dm0644 "$pkgname.fish" "$pkgdir/usr/share/fish/vendor_completions.d/$pkgname.fish"
}
