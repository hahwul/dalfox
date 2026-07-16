+++
title = "설치"
description = "macOS, Linux, Windows, NixOS, Arch Linux에 Dalfox를 설치하거나 소스에서 직접 빌드합니다."
weight = 2
toc = true
+++

플랫폼에 맞는 설치 방법을 고르세요. Dalfox는 별도로 관리할 런타임 없이 단일 실행 파일 하나로 배포됩니다.

## Homebrew (macOS & Linux)

```bash
brew install dalfox
```

Homebrew formula는 최신 안정 버전을 따라갑니다. 출처: [formulae.brew.sh/formula/dalfox](https://formulae.brew.sh/formula/dalfox).

## Snap (Ubuntu / Linux)

```bash
sudo snap install dalfox
```

## Arch Linux (AUR)

AUR 헬퍼 사용(권장):

```bash
yay -S dalfox
# 또는
paru -S dalfox
```

[AUR 패키지](https://aur.archlinux.org/packages/dalfox)에서 직접 빌드:

```bash
git clone https://aur.archlinux.org/dalfox.git
cd dalfox
makepkg -si
```

## Nix & NixOS

```bash
# 설치 없이 한 번만 실행
nix-shell -p dalfox

# Nix flakes: GitHub에서 최신 버전 실행
nix run github:hahwul/dalfox -- scan https://example.com

# 프로필에 설치
nix profile install github:hahwul/dalfox

# Dalfox가 준비된 개발 셸로 진입
nix develop github:hahwul/dalfox
```

Dalfox는 nixpkgs에 등록되어 있습니다. 최신 릴리스는 먼저 `unstable`에 올라옵니다.

## Cargo (crates.io)

```bash
cargo install dalfox
```

최신 Rust 툴체인이 필요합니다(stable이면 충분). `~/.cargo/bin/dalfox`에 빌드됩니다.

## 사전 빌드된 바이너리

[github.com/hahwul/dalfox/releases](https://github.com/hahwul/dalfox/releases)에서 OS/아키텍처에 맞는 릴리스 아카이브를 내려받아 압축을 풀고, 바이너리를 `PATH`에 있는 경로(`/usr/local/bin`, `~/.local/bin` 등)에 두면 됩니다.

릴리스마다 다음 Linux 빌드를 함께 제공합니다.

- `linux-x86_64` (glibc)
- `linux-x86_64-musl` (정적 링크, Alpine·Docker·CI에 권장)
- `linux-aarch64` (glibc)
- `linux-aarch64-musl` (정적 링크)

## 소스에서 빌드

```bash
git clone https://github.com/hahwul/dalfox
cd dalfox
cargo build --release
# 바이너리 경로: ./target/release/dalfox
```

Rust(2024 edition)가 필요합니다. 없다면 [rustup](https://rustup.rs/)으로 설치하세요.

## 설치 확인

```bash
dalfox --version
```

`dalfox 3.1.2` 같은 버전 정보와 함께 Dalfox 배너가 보이면 됩니다.

## 셸 자동완성 갱신 (선택)

Dalfox는 [clap](https://github.com/clap-rs/clap)을 쓰기 때문에 도움말을 언제든 볼 수 있습니다.

```bash
dalfox --help
dalfox scan --help
```

## 다음 단계

[빠른 시작](../quick-start/)에서 첫 스캔을 실행해 보세요. 스캔 전에 기본값을 조정하고 싶다면 [설정](../configuration/)으로 넘어가세요.
