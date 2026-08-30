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
```

Dalfox는 nixpkgs에 등록되어 있습니다. 최신 릴리스는 먼저 `unstable`에 올라오므로, 릴리스 사이 기간에는 위 flake 쪽이 `nixpkgs`보다 앞서 있습니다.

flake가 지원하는 시스템은 `x86_64-linux`, `aarch64-linux`, `aarch64-darwin`입니다. nixpkgs `unstable`이 `x86_64-darwin`을 제외했기 때문에 Intel macOS는 빠져 있으니, 아래의 `macos-x86_64` 릴리스 아카이브를 쓰세요.

이 flake가 고정한 nixpkgs 대신 사용자의 `nixpkgs`로 Dalfox를 빌드하려면 오버레이를 쓰세요. 시스템 flake에서는 이렇게 선언합니다.

```nix
# flake.nix
{
  inputs.dalfox.url = "github:hahwul/dalfox";

  outputs = { self, nixpkgs, dalfox, ... }@inputs: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      specialArgs = { inherit inputs; };
      modules = [ ./configuration.nix ];
    };
  };
}
```

그리고 `inputs`를 전달받는 모듈에서 적용합니다.

```nix
# configuration.nix
{ pkgs, inputs, ... }:
{
  nixpkgs.overlays = [ inputs.dalfox.overlays.default ];
  environment.systemPackages = [ pkgs.dalfox ];
}
```

flake는 Dalfox 자체를 개발할 때 쓰는 셸도 제공합니다. Rust 툴체인과 [`just`](https://github.com/casey/just), 테스트 하네스가 필요로 하는 Crystal 런타임이 들어 있고 `dalfox` 바이너리는 포함하지 않습니다.

```bash
git clone https://github.com/hahwul/dalfox && cd dalfox
nix develop
```

[direnv](https://direnv.net)를 설치했다면 저장소의 `.envrc` 덕분에 `direnv allow` 한 번으로 같은 셸이 자동으로 활성화됩니다.

## Cargo (crates.io)

```bash
cargo install dalfox
```

최신 Rust 툴체인이 필요합니다(stable이면 충분). `~/.cargo/bin/dalfox`에 빌드됩니다.

## 사전 빌드된 바이너리

[github.com/hahwul/dalfox/releases](https://github.com/hahwul/dalfox/releases)에서 OS/아키텍처에 맞는 릴리스 아카이브를 내려받아 압축을 풀고, 바이너리를 `PATH`에 있는 경로(`/usr/local/bin`, `~/.local/bin` 등)에 두면 됩니다.

릴리스마다 다음 빌드가 함께 올라갑니다.

- `macos-x86_64`, `macos-aarch64`
- `linux-x86_64` (glibc), `linux-x86_64-musl` (정적 링크, Alpine·Docker·CI에 권장)
- `linux-aarch64` (glibc), `linux-aarch64-musl` (정적 링크)
- `windows-x86_64`

Linux는 두 아키텍처 모두 `.deb`와 `.rpm` 패키지도 나오며, 모든 아카이브에는 `.sha256`이 붙고 `checksum.txt`도 함께 올라갑니다.

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

`dalfox 3.2.1` 같은 버전 정보와 함께 Dalfox 배너가 보이면 됩니다.

## 셸 자동완성

Homebrew, AUR 패키지, `.deb` / `.rpm` 패키지, Nix 플레이크로 설치하면 bash·zsh·fish 자동완성이 함께 설치되므로 따로 할 일이 없습니다.

Cargo, 릴리스 아카이브, 소스 빌드처럼 다른 방법으로 설치했다면 직접 생성하면 됩니다.

```bash
dalfox completion bash > /etc/bash_completion.d/dalfox
dalfox completion zsh > "${fpath[1]}/_dalfox"
dalfox completion fish > ~/.config/fish/completions/dalfox.fish
```

`powershell`과 `elvish`도 지원합니다. 자세한 내용은 [CLI 레퍼런스](../../reference/cli/)를 참조하세요.

## 도움말 보기

Dalfox는 [clap](https://github.com/clap-rs/clap)을 쓰기 때문에 도움말을 언제든 볼 수 있습니다.

```bash
dalfox --help
dalfox scan --help
```

## 다음 단계

[빠른 시작](../quick-start/)에서 첫 스캔을 실행해 보세요. 스캔 전에 기본값을 조정하고 싶다면 [설정](../configuration/)으로 넘어가세요.
