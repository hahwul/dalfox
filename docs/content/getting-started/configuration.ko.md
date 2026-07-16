+++
title = "설정"
description = "즐겨 쓰는 플래그를 Dalfox 설정 파일에 저장합니다."
weight = 4
toc = true
+++

Dalfox는 시작 시 설정 파일을 읽으므로 매번 동일한 플래그를 전달할 필요가 없습니다. 설정 파일에 지정한 값은 명시적인 CLI 플래그로 덮어쓸 수 있으므로, 여기에 "기본값"을 두어도 안전합니다.

## 파일 위치

Dalfox는 다음 순서로 파일을 찾습니다.

1. `$XDG_CONFIG_HOME/dalfox/config.toml`
2. `$HOME/.config/dalfox/config.toml`

`--config`로 다른 위치를 지정할 수 있습니다.

```bash
dalfox --config ./dalfox.toml scan https://target.app
```

파일이 없으면, Dalfox는 처음 실행할 때 기본 경로에 템플릿을 생성합니다.

## 최소 설정

```toml
[scan]
format = "json"
output = "results.json"
timeout = 15
workers = 100
encoders = ["url", "html"]
```

스캔을 실행하면 해당 플래그가 자동으로 적용됩니다.

```bash
dalfox https://target.app?q=test
# → writes JSON results to results.json with workers=100
```

## 우선순위

```
CLI flag  >  Config file  >  Built-in defaults
```

커맨드 라인에 지정한 것이 우선합니다. 이를 통해 설정 파일에 합리적인 기본값을 유지하면서, 스캔마다 개별적으로 덮어쓸 수 있습니다.

```bash
# Config sets workers=100, but for this quick scan use 20
dalfox --workers 20 https://target.app
```

## 형식

Dalfox는 TOML과 JSON을 모두 지원합니다. TOML이 기본값이며, 도구나 UI에서 파일을 생성하는 경우 JSON이 편리합니다.

```toml
# ~/.config/dalfox/config.toml
[scan]
format = "sarif"
silence = true
```

```json
{
  "scan": {
    "format": "sarif",
    "silence": true
  }
}
```

## 무엇을 설정할 수 있나요?

`dalfox scan` 아래에 CLI 플래그가 있는 모든 항목은 `[scan]` 테이블에 넣을 수 있습니다. 일반적인 예시는 다음과 같습니다.

| 키 | 예시 | 기능 |
|-----|---------|--------------|
| `format` | `"json"` | 출력 형식(`plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml`) |
| `output` | `"report.json"` | 기본 출력 파일 |
| `silence` | `true` | 로그를 억제하고 탐지 결과만 출력 |
| `timeout` | `15` | 요청 타임아웃(초) |
| `delay` | `200` | 요청 간 지연(ms) |
| `workers` | `100` | 대상당 동시 워커 수 |
| `encoders` | `["url","html","base64"]` | 페이로드 인코더 |
| `remote_payloads` | `["portswigger"]` | 원격 페이로드 소스 |
| `remote_wordlists` | `["burp"]` | 원격 파라미터 워드리스트 |
| `headers` | `["Accept: text/html"]` | 추가 요청 헤더 |
| `user_agent` | `"Dalfox Scanner"` | 기본 User-Agent |
| `waf_bypass` | `"auto"` | WAF 우회 모드(`auto`, `force`, `off`) |
| `insecure` | `true` | TLS 인증서 검증 건너뛰기(`false`로 설정 시 강제) |
| `follow_redirects` | `true` | 3xx 응답 따라가기 |

모든 키는 [설정 파일 레퍼런스](../../reference/config/)를 참고하세요.

## 시크릿

설정 파일을 커밋한다면, API 키, 베어러 토큰, blind-XSS 콜백 호스트명은 설정 파일에서 제외하세요. 환경 변수를 사용하는 것이 좋습니다.

```bash
# .env or your shell profile
export DALFOX_API_KEY="..."
```

또는 커맨드 라인에서 전달하고 절대 저장하지 마세요.

## 다음 단계

- [첫 스캔 실행하기](../quick-start/)
- [스캐닝 모드 살펴보기](../../guide/scanning-modes/)
- [전체 CLI 레퍼런스 보기](../../reference/cli/)
