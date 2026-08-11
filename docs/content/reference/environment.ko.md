+++
title = "환경 변수"
description = "Dalfox가 런타임에 읽는 환경 변수."
weight = 3
toc = true
+++

Dalfox는 설정 파일이나 명령줄에 두기 적합하지 않은 설정을 몇 가지 환경 변수로 받습니다.

| 변수 | 사용 위치 | 용도 |
|----------|---------|---------|
| `DALFOX_API_KEY` | `dalfox server` | `X-API-KEY` 헤더에 요구되는 값. `--api-key`와 동일. |
| `DALFOX_STDIN_WAIT_MS` | `dalfox scan` (auto 입력) | 명령줄에도 대상을 준 상태에서 파이프된 `stdin`의 첫 바이트를 기다릴 밀리초. 기본값 `500`, `0`이면 stdin 병합을 건너뜁니다. 항상 대기하는 `--input-type pipe`/`har`에는 적용되지 않습니다. |
| `NO_COLOR` | 모든 모드 | 빈 문자열을 포함해 어떤 값으로든 설정되면 ANSI 색상 출력을 비활성화. `--no-color` 및 설정 파일의 `no_color = true`와 동일. [NO_COLOR](https://no-color.org) 관례 참고. |
| `XDG_CONFIG_HOME` | 설정 로더 | 설정 파일의 기준 디렉터리 (`$XDG_CONFIG_HOME/dalfox/config.toml`). `$HOME/.config`로 폴백. |
| `HOME` | 설정 로더 | `XDG_CONFIG_HOME`이 설정되지 않았을 때 사용. |
| `USERPROFILE` | 설정 로더 | `XDG_CONFIG_HOME`과 `HOME`이 모두 없을 때 사용하는 Windows 폴백 기준 디렉터리. |

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

`--no-color`는 한 번의 실행에, 설정 파일의 `no_color = true`는 모든 실행에 같은 효과를 냅니다. 또한 stdout이 TTY가 아니면 색상이 자동으로 비활성화되므로, 파이프하거나 리다이렉트한 스캔은 아무 설정 없이도 일반 텍스트로 출력됩니다.

```bash
dalfox scan https://target.app --no-color
dalfox scan https://target.app > scan.log   # 이미 일반 텍스트
```

출력 가이드의 [색상 및 TTY 동작](../../guide/output/#색상-및-tty-동작)을 참고하세요.

### 프로젝트 로컬 설정 사용

```bash
XDG_CONFIG_HOME=./.config dalfox scan https://target.app
# Dalfox reads ./.config/dalfox/config.toml
```

## 환경 변수가 아닌 것

환경 변수처럼 *보이지만* 실제로는 아닌 몇 가지입니다.

- **프록시.** `--proxy`나 설정 파일의 `proxy`를 쓰세요. Dalfox는 의도치 않은 트래픽 가로채기를 막으려고 `HTTP_PROXY`/`HTTPS_PROXY`를 읽지 않습니다.
- **타임아웃, 워커, 형식.** CLI 플래그나 설정 파일로만 지정합니다.
- **디버그.** 명령줄에 `--debug`를 주거나 설정 파일에 `debug = true`를 넣으세요.
