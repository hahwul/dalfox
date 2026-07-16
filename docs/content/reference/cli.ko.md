+++
title = "CLI 레퍼런스"
description = "Dalfox가 지원하는 모든 서브커맨드와 플래그."
weight = 1
toc = true
+++

Dalfox는 네 개의 서브커맨드로 구성되어 있습니다. 기본값(대상만 전달했을 때)은 `scan`입니다.

```
dalfox [SUBCOMMAND] [TARGET] [FLAGS]
```

| 서브커맨드 | 용도 |
|------------|---------|
| `scan` | 대상에서 XSS를 스캔합니다 (생략 시 기본값) |
| `server` | REST API 서버를 실행합니다 |
| `payload` | 내장/원격 페이로드를 나열하거나 가져옵니다 |
| `mcp` | Model Context Protocol stdio 서버를 실행합니다 |
| `help` | 임의의 서브커맨드에 대한 도움말을 출력합니다 |

## 전역 플래그

| 플래그 | 설명 |
|------|-------------|
| `--config <FILE>` | 설정 파일 경로(TOML 또는 JSON). 기본 검색 경로를 덮어씁니다. |
| `--debug` | 디버그 로깅을 활성화합니다. |
| `-h`, `--help` | 도움말을 출력합니다. |
| `-V`, `--version` | 버전을 출력합니다. |

종료 코드:

| 코드 | 의미 |
|------|---------|
| `0` | 성공, 탐지 결과 없음 |
| `1` | 성공, 탐지 결과 보고됨 |
| `2` | 입력 / 설정 / 런타임 오류 |

---

## `dalfox scan`

대상에서 XSS를 스캔합니다. 서브커맨드를 생략해도 동일합니다.

```bash
dalfox scan [TARGETS]... [FLAGS]
```

### 입력

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--input-type` | `-i` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |

### 출력

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--format` | `-f` | `plain` | `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` |
| `--output` | `-o` | — | 출력을 파일에 씁니다 |
| `--include-request` | — | false | 출력에 HTTP 요청을 포함합니다 |
| `--include-response` | — | false | 출력에 응답 본문을 포함합니다 |
| `--include-all` | — | false | 두 include 플래그의 축약형 |
| `--no-color` | — | false | ANSI 색상을 비활성화합니다 |
| `--silence` | `-S` | false | STDOUT에 탐지 결과만 출력합니다 |
| `--dry-run` | — | false | 페이로드를 보내지 않고 탐색 및 계획만 수행합니다 |
| `--stream-findings` | — | false | 스캔 종료 요약 이후가 아니라 각 탐지 결과가 검증되는 즉시 출력합니다 (plain 형식만; `--output`, `--limit`, `--only-poc` 사용 시 자동 비활성화) |
| `--poc-type` | — | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--limit` | — | — | 표시되는 전체 결과 수를 제한합니다 |
| `--limit-result-type` | — | `all` | `--limit`에 집계되는 유형: `all`, `v`, `r`, `a` |
| `--only-poc` | — | — | 쉼표로 구분된 필터: `v`, `r`, `a` |

### 대상 형태 지정

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--param` | `-p` | — | 분석할 파라미터; `name:location` 형식 지원 (위치: `query`, `body`, `json`, `cookie`, `header`) |
| `--data` | `-d` | — | 요청 본문 |
| `--headers` | `-H` | — | 추가 HTTP 헤더 (반복 지정 가능) |
| `--cookies` | — | — | 쿠키 (반복 지정 가능) |
| `--method` | `-X` | `GET` | HTTP 메서드 재정의 (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` / RFC 10008) |
| `--user-agent` | — | — | 사용자 지정 User-Agent |
| `--cookie-from-raw` | — | — | raw HTTP 요청 파일에서 쿠키를 불러옵니다 |

### 범위

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--include-url` | — | 포함할 URL의 정규식 패턴 |
| `--exclude-url` | — | 제외할 URL의 정규식 패턴 |
| `--ignore-param` | — | 건너뛸 파라미터 이름 |
| `--out-of-scope` | — | 건너뛸 와일드카드 도메인 패턴 |
| `--out-of-scope-file` | — | 범위 외 도메인을 나열한 파일 |

### 탐색

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--only-discovery` | false | 탐색 후 중지하고 XSS 페이로드를 보내지 않습니다 |
| `--skip-discovery` | false | 모든 탐색을 건너뜁니다 |
| `--skip-reflection-header` | false | 헤더 기반 반사 검사를 건너뜁니다 |
| `--skip-reflection-cookie` | false | 쿠키 기반 반사 검사를 건너뜁니다 |
| `--skip-reflection-path` | false | 경로 기반 반사 검사를 건너뜁니다 |

### 마이닝

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--mining-dict-word` | `-W` | — | 파라미터 워드리스트 파일 |
| `--remote-wordlists` | — | — | 원격 소스: `burp`, `assetnote` |
| `--skip-mining` | — | false | 모든 마이닝을 건너뜁니다 |
| `--skip-mining-dict` | — | false | 사전 마이닝을 건너뜁니다 |
| `--skip-mining-dom` | — | false | DOM 마이닝을 건너뜁니다 |

### 네트워크

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--timeout` | — | `10` | 요청당 타임아웃(초) (네트워크 한정; 전체 스캔 시간을 제한하지 않음) |
| `--scan-timeout` | — | `0` | 스캔 단계(프리플라이트 이후)에 대한 대상별 하드 실제 시간 상한(초). 초과 시 해당 대상을 중단합니다. 여러 순차 단계가 부분적으로 멈춘 엔드포인트에 대해 각각 요청당 `--timeout` 비용을 치를 때 유용합니다. `0`은 비활성화합니다. |
| `--delay` | — | `0` | 요청 간 지연(ms), 워커별 |
| `--rate-limit` | `-r`, `--rl` | `0` | 모든 워커와 대상에 걸쳐 공유되는 **전역** 아웃바운드 요청 속도를 초당 요청 수로 제한합니다 (`0` = 무제한). 하나의 워커만 간격을 두는 `--delay`와 달리, `workers × concurrent targets`에서 발생하는 총 동시 진행 버스트를 제한하여 공유 IP / 엣지 WAF 임계값에 더 친화적입니다. |
| `--retries` | — | `0` | HTTP 5xx 및 일시적 전송 오류(타임아웃, 연결 재설정) 시 실패한 요청을 이 횟수만큼 재시도합니다 (`0` = 끔). HTTP 429는 항상 재시도됩니다. |
| `--retry-delay` | — | `1000` | `--retries` 시도 사이의 지수 백오프 기본 지연(ms) (시도마다 두 배로 증가, 내부적으로 상한 적용). 429에서는 서버의 `Retry-After` 헤더가 우선합니다. |
| `--proxy` | — | — | 프록시 URL (`http://`, `socks5://`) |
| `--insecure` | — | `true` | TLS/SSL 인증서 검증을 건너뜁니다 (자체 서명, 만료, 호스트명 불일치 인증서 허용). 스캐너 사용을 위해 기본적으로 켜져 있으며, 인증서 검증을 강제하려면 `--insecure=false`를 전달합니다. |
| `--follow-redirects` | `-F` | false | 3xx 응답을 따라갑니다 |
| `--ignore-return` | — | — | 무시할 HTTP 상태 코드 |

### 엔진

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--workers` | `50` | 대상별 동시 워커 수 |
| `--max-concurrent-targets` | `50` | 전역 동시 대상 수 |
| `--max-targets-per-host` | `100` | 호스트별 상한 |

### XSS 스캐닝

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--encoders` | `-e` | `url,html` | 쉼표로 구분된 인코더 |
| `--remote-payloads` | — | — | `portswigger`, `payloadbox` |
| `--custom-blind-xss-payload` | — | — | 사용자 지정 블라인드 페이로드 템플릿 파일 |
| `--blind` | `-b` | — | 블라인드 XSS 콜백 URL |
| `--blind-oob[=servers]` | — | — | interactsh를 통한 OOB/OAST 블라인드 XSS를 활성화합니다; 선택적으로 쉼표로 구분된 서버 도메인 (기본값: 공용 메시). `=` 형식이 필요합니다: `--blind-oob=oast.fun,oast.me` |
| `--blind-oob-secret` | — | — | 자체 호스팅 interactsh 서버용 인증 토큰 (register/poll/deregister 시 `Authorization`으로 전송) |
| `--blind-oob-wait` | — | `30` | 모든 페이로드 전송 후 OOB 콜백을 계속 폴링할 시간(초) (`0` = 스캔 종료 후 추가 대기 없음) |
| `--custom-payload` | — | — | 사용자 지정 페이로드 파일 |
| `--only-custom-payload` | — | false | 사용자 지정 페이로드만 사용합니다 |
| `--custom-alert-value` | — | `1` | `alert()`/`prompt()`/`confirm()` 안에 들어가는 값 |
| `--custom-alert-type` | — | `none` | `none` 또는 `str` |
| `--inject-marker` | — | — | 이 토큰을 페이로드로 치환합니다 (예: `FUZZ`) |
| `--skip-xss-scanning` | — | false | 페이로드 주입을 건너뜁니다 |
| `--deep-scan` | — | false | 첫 탐지 결과 이후에도 계속 테스트합니다 |
| `--sxss` | — | false | Stored XSS 모드를 활성화합니다 |
| `--sxss-url` | — | — | SXSS용 조회 URL |
| `--sxss-method` | — | `GET` | 조회 메서드 |
| `--sxss-retries` | — | `3` | 저장된 출력을 가져올 때 조회 URL에 대한 재시도 횟수 |
| `--max-payloads-per-param` | — | `0` | 파라미터별로 테스트하는 페이로드 수 제한 (`0` = 제한 없음) |
| `--skip-ast-analysis` | — | false | AST DOM-XSS를 건너뜁니다 |
| `--analyze-external-js` | — | false | 동일 출처의 `<script src>` 번들을 가져와 AST DOM-XSS 분석을 수행합니다 (프리플라이트, 대상별 1회; 최대 16개 파일, 각 512 KiB; `--include-url`/`--exclude-url`을 준수) |
| `--hpp` | — | false | HTTP 파라미터 오염 |
| `--detect-outdated-libs` | — | false | 오래되었거나 알려진 취약점이 있는 JS 라이브러리도 보고합니다 (정보성, CWE-1104; 추가 요청 0회) |

### WAF

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--waf-bypass` | `auto` | `auto`, `force`, `off` |
| `--skip-waf-probe` | false | 능동 WAF 핑거프린팅을 건너뜁니다 |
| `--force-waf` | — | `--waf-bypass force`일 때 사용할 WAF 이름 |
| `--waf-evasion` | false | WAF 탐지 시 적응형 회피: 요청 간 무작위 지터 + 차단된 응답이 몰릴 때 점증하는 쿨다운 (기존의 단순한 `workers=1`/`delay=3000` 프리셋을 대체). 이 플래그가 없어도 WAF별 페이싱 힌트는 탐지 시 자동으로 적용됩니다. `--rate-limit`와 함께 쓰면 좋습니다. |
| `--waf-min-confidence` | `0.3` | 이 신뢰도 미만의 핑거프린트를 제거합니다 (0.0–1.0). 기본값 `0.3`은 `Server: Google Frontend`(0.15) 같은 약한 매칭을 억제합니다. 약한 신호를 유지하려면 더 낮게 설정하고, `1.0`은 완전한 신뢰도를 가진 핑거프린트만 유지합니다. |

---

## `dalfox server`

REST API 서버를 시작합니다.

```bash
dalfox server [FLAGS]
```

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--port` | `-p` | `6664` | 수신 포트 |
| `--host` | `-H` | `127.0.0.1` | 바인딩 주소 |
| `--api-key` | — | — | 필수 `X-API-KEY` 헤더 값 (또는 `DALFOX_API_KEY`) |
| `--log-file` | — | — | 일반 텍스트 로그 파일 |
| `--allowed-origins` | — | — | CORS 오리진 (쉼표로 구분, `*` 및 `regex:` 지원) |
| `--jsonp` | — | false | 응답을 JSONP로 감쌉니다 |
| `--callback-param-name` | — | `callback` | JSONP 콜백 파라미터 |
| `--cors-allow-methods` | — | `GET,POST,OPTIONS,PUT,PATCH,DELETE` | CORS 메서드 |
| `--cors-allow-headers` | — | `Content-Type,X-API-KEY,Authorization` | CORS 헤더 |
| `--rate-limit` | `-r`, `--rl` | `0` | 전역 아웃바운드 요청 속도를 제한합니다 (초당 요청 수, `0` = 무제한) |
| `--scan-timeout` | — | `0` | 스캔 단계에 대한 대상별 하드 실제 시간 상한(초) |
| `--max-concurrent-scans` | — | `0` | 동시 스캔 수 제한 (`0` = 무제한) |
| `--max-body-bytes` | — | `0` | 분석용 응답 본문 바이트 제한 (`0` = 무제한) |

엔드포인트는 [REST API Server](../../integrations/server/)를 참조하세요.

---

## `dalfox payload`

페이로드 컬렉션을 나열하거나 가져옵니다.

```bash
dalfox payload <SELECTOR>
```

선택자:

| 선택자 | 출력 내용 |
|----------|----------------|
| `event-handlers` | DOM 이벤트 핸들러 속성 이름 |
| `useful-tags` | 유용한 HTML 태그 |
| `uri-scheme` | `javascript:`/`data:` URL 페이로드 |
| `portswigger` | 원격: PortSwigger XSS 치트시트 |
| `payloadbox` | 원격: PayloadBox XSS 목록 |

---

## `dalfox mcp`

MCP stdio 서버를 실행합니다.

```bash
dalfox mcp
```

추가 플래그는 없습니다. 도구 정의는 [MCP Server](../../integrations/mcp/)를 참조하세요.

---

## 함께 보기

- [Config File reference](../config/)
- [Environment variables](../environment/)
