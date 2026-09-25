+++
title = "설정"
description = "즐겨 쓰는 플래그를 Dalfox 설정 파일에 저장합니다."
weight = 4
toc = true
+++

Dalfox는 시작할 때 설정 파일을 읽으므로 매번 같은 플래그를 붙일 필요가 없습니다. 명시적인 CLI 플래그가 설정 파일의 값을 항상 덮어쓰니, 여기에 "기본값"을 두어도 안전합니다.

## 파일 위치

Dalfox는 `XDG_CONFIG_HOME`이 설정되어 있고 비어 있지 않으면 `$XDG_CONFIG_HOME/dalfox/config.toml`을, 그렇지 않으면 `$HOME/.config/dalfox/config.toml`을 읽습니다. 같은 디렉터리에 `config.toml`이 없으면 `config.json`을 읽습니다.

`--config`로 다른 위치를 지정할 수 있습니다.

```bash
dalfox --config ./dalfox.toml scan https://target.app
```

파일이 없으면 Dalfox는 처음 실행할 때 기본 경로에 템플릿을 만듭니다. 모든 줄이 주석 처리되어 있으므로 직접 고치기 전까지는 아무것도 바꾸지 않습니다.

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
dalfox 'https://target.app/?q=test'
# → workers=100으로 스캔하고 JSON 결과를 results.json에 씀
```

## 우선순위

```
CLI 플래그  >  설정 파일  >  내장 기본값
```

명령줄에 지정한 것이 우선합니다. 그래서 설정 파일에는 무난한 기본값을 두고, 스캔할 때마다 필요한 값만 덮어쓰면 됩니다.

```bash
# 설정 파일은 workers=100이지만, 이번 빠른 스캔은 20으로
dalfox scan --workers 20 https://target.app
```

스캔 플래그를 쓰려면 `scan` 서브커맨드를 명시해야 합니다. `dalfox <TARGET>` 축약형은 대상과 전역 플래그만 받습니다. `deep_scan = true`처럼 설정 파일에서 켠 스위치는 끄는 명령줄 플래그가 없어서 모든 실행에 그대로 적용됩니다. 자세한 내용은 [우선순위](../../reference/config/#우선순위)를 참고하세요.

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

`dalfox scan` 아래에 CLI 플래그가 있는 모든 항목은 `[scan]` 테이블에 넣을 수 있습니다(`--blind`의 키 이름은 `blind_callback_url`). 이 파일은 CLI 스캔에만 적용되며 `dalfox server`와 `dalfox mcp`는 읽지 않습니다. 자주 쓰는 키 몇 가지입니다.

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
| `waf_bypass` | `"auto"` | WAF 우회 모드(`auto`, 탐지만 하려면 `off`) |
| `insecure` | `true` | TLS 인증서 검증 건너뛰기(`false`면 검증 수행) |
| `follow_redirects` | `true` | 3xx 응답 따라가기 |

모든 키는 [설정 파일 레퍼런스](../../reference/config/)를 참고하세요.

## 시크릿

설정 파일을 커밋한다면 API 키, 베어러 토큰, blind-XSS 콜백 호스트명은 파일에서 빼세요. Dalfox가 환경 변수에서 읽는 시크릿은 REST 서버의 API 키 하나뿐입니다.

```bash
# .env 또는 셸 프로필
export DALFOX_API_KEY="..."
```

나머지(`-H "Authorization: …"`, `--cookies`, `-b`)는 명령줄에서만 넘기고 파일에는 남기지 마세요.

## 다음 단계

- [첫 스캔 실행하기](../quick-start/)
- [스캐닝 모드 살펴보기](../../guide/scanning-modes/)
- [전체 CLI 레퍼런스 보기](../../reference/cli/)
