+++
title = "환경 변수"
description = "Dalfox가 런타임에 읽는 환경 변수."
weight = 3
toc = true
+++

Dalfox는 파일이나 명령줄에 두기 적합하지 않은 설정을 위해 소수의 환경 변수를 인식합니다.

| 변수 | 사용 위치 | 용도 |
|----------|---------|---------|
| `DALFOX_API_KEY` | `dalfox server` | `X-API-KEY` 헤더에 요구되는 값. `--api-key`와 동일. |
| `NO_COLOR` | 모든 모드 | 비어 있지 않은 값으로 설정되면 ANSI 색상 출력을 비활성화. [NO_COLOR](https://no-color.org) 관례를 따름. |
| `XDG_CONFIG_HOME` | 설정 로더 | 설정 파일의 기준 디렉터리 (`$XDG_CONFIG_HOME/dalfox/config.toml`). `$HOME/.config`로 폴백. |
| `HOME` | 설정 로더 | `XDG_CONFIG_HOME`이 설정되지 않았을 때 사용. |

## 예시

### 프로세스 인자에서 API 키 노출 방지

```bash
export DALFOX_API_KEY="$(pass dalfox/api-key)"
dalfox server --port 6664
```

### 전역으로 색상 비활성화

```bash
export NO_COLOR=1
```

### 프로젝트 로컬 설정 사용

```bash
XDG_CONFIG_HOME=./.config dalfox scan https://target.app
# Dalfox reads ./.config/dalfox/config.toml
```

## 환경 변수가 아닌 것

환경 변수처럼 *보이지만* 실제로는 아닌 몇 가지입니다.

- **프록시.** `--proxy` 또는 설정의 `proxy`를 사용하세요. Dalfox는 의도치 않은 트래픽 가로채기를 피하기 위해 `HTTP_PROXY`/`HTTPS_PROXY`를 읽지 않습니다.
- **타임아웃, 워커, 형식.** CLI 플래그 또는 설정으로만 지정합니다.
- **디버그.** 명령줄에서 `--debug`를 전달하거나 설정에서 `debug = true`로 지정하세요.
