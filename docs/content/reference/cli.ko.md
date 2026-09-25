+++
title = "CLI 레퍼런스"
description = "Dalfox가 지원하는 모든 서브커맨드와 플래그."
weight = 1
toc = true
+++

Dalfox는 다섯 개의 서브커맨드와 기본 제공 `help`로 구성되어 있습니다. 기본값(대상만 전달했을 때)은 `scan`이지만, 이 축약형은 대상과 아래의 전역 플래그만 받습니다. 그 밖의 스캔 플래그를 쓰려면 서브커맨드를 명시해야 합니다. `dalfox scan <TARGET> --workers 20`은 동작하지만 `dalfox <TARGET> --workers 20`은 예상하지 못한 인자로 거부됩니다.

```
dalfox [SUBCOMMAND] [TARGET] [FLAGS]
```

| 서브커맨드 | 용도 |
|------------|---------|
| `scan` | 대상에서 XSS를 스캔합니다 (생략 시 기본값) |
| `server` | REST API 서버를 실행합니다 |
| `payload` | 내장/원격 페이로드를 나열하거나 가져옵니다 |
| `mcp` | Model Context Protocol stdio 서버를 실행합니다 |
| `completion` | 셸 자동완성 스크립트를 생성합니다 |
| `help` | 서브커맨드별 도움말을 출력합니다 |

## 전역 플래그

| 플래그 | 설명 |
|------|-------------|
| `--config <FILE>` | 설정 파일 경로(TOML이나 JSON). 기본 검색 경로를 덮어씁니다. |
| `--debug` | 디버그 로깅을 활성화합니다. |
| `--no-color` | ANSI 색상을 비활성화합니다 (`NO_COLOR`도 따릅니다). |
| `-S`, `--silence` | PoC 출력을 제외한 모든 로그를 STDOUT에서 숨깁니다. |
| `-h`, `--help` | 도움말을 출력합니다. |
| `-V`, `--version` | 버전을 출력합니다. |

`--config`, `--debug`, `--no-color`, `--silence`는 서브커맨드 앞뒤 어디에 써도 됩니다(`dalfox --config ./dalfox.toml scan …`과 `dalfox scan … --config ./dalfox.toml`은 같습니다).

종료 코드:

| 코드 | 의미 |
|------|---------|
| `0` | 성공, 탐지 결과 없음 |
| `1` | 성공, 탐지 결과 보고됨 (티어 무관 — `V`만 게이트하려면 `--only-poc v`와 함께) |
| `2` | 입력 / 설정 / 런타임 오류 |

탐지 결과 없이 깨끗하게 끝나지 못한 실행(모든 대상이 건너뛰어짐, 세션 유실, 스캔 워커 크래시, 대량의 요청 유실)도 `2`입니다. 전체 규칙은 [종료 코드](../../guide/output/#종료-코드)를 참고하세요. `server`와 `mcp`는 시작하지 못하면(예: 포트가 이미 사용 중) `2`로 종료합니다. `payload`는 알 수 없는 선택자를 받으면 `2`로 종료합니다.

---

## `dalfox scan`

대상에서 XSS를 스캔합니다. 서브커맨드를 생략해도 스캔이 실행되지만, 이때는 대상과 전역 플래그만 받습니다(위 참고).

```bash
dalfox scan [TARGETS]... [FLAGS]
```

### 입력

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--input-type` | `-i` | `auto` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `--dedup-urls` | — | `exact` | 대상 중복 제거: `exact`(URL+메서드가 완전히 같은 것만 제거), `signature`(파라미터 *값*만 다른 URL도 하나로 병합), `off`(입력의 모든 줄을 그대로 스캔) |
| `--state-file` | — | — | 끝난 대상을 파일에 기록해 두고 같은 스캔을 다시 돌릴 때 건너뜁니다. 중단된 대량 스캔을 처음부터가 아니라 이어서 진행합니다. raw HTTP/HAR 요청 데이터는 지문으로 기록되므로 바뀐 캡처는 다시 스캔합니다. `-H` / `--cookies` / `--cookie-from-raw`로 준 자격 증명 값은 식별자에서 제외되므로 세션을 갱신해도 이어서 진행합니다. 캡처 안의 자격 증명은 그대로 포함됩니다 |

무엇을 건너뛰고 무엇을 다시 시도하는지는 [중단된 스캔 이어하기](../../guide/scanning-modes/#중단된-스캔-이어하기)를 참고하세요.

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
| `--stream-findings` | — | false | 스캔 종료 요약 이후가 아니라 각 탐지 결과가 검증되는 즉시 출력합니다 (plain 형식만; `--output`, `--limit`, `--only-poc`, `--baseline` 사용 시 자동 비활성화) |
| `--poc-type` | — | `plain` | `plain`, `curl`, `httpie`, `http-request` |
| `--limit` | — | — | 표시되는 전체 결과 수를 제한합니다 (`1` 이상이어야 하며, 제한하지 않으려면 생략) |
| `--limit-result-type` | — | `all` | `--limit`에 집계되는 유형: `all`, `v`, `r`, `a`, `i` |
| `--only-poc` | — | — | 쉼표로 구분된 필터: `v`(취약), `r`(반사됨), `a`(AST), `i`(정보성) |
| `--baseline` | — | — | 이전 Dalfox JSON/JSONL 리포트와 비교해 그 이후 새로 생긴 건만 보고합니다. 평범한 `-f json -o` 리포트가 그대로 베이스라인입니다 |
| `--baseline-mode` | — | `filter` | `filter`는 알려진 건을 제거하고(카운트와 종료 코드가 신규 기준), `annotate`는 유지한 채 각각에 `new`를 표시합니다 |

지문 규칙과 CI 레시피는 [베이스라인](../../guide/output/#베이스라인-새로-생긴-것만-보고하기)을 참고하세요.

### 대상 형태 지정

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--param` | `-p` | — | 분석할 파라미터; `name:location` 형식 지원 (위치: `query`, `body`, `json`, `multipart`, `cookie`, `header`, `graphql`, `xml`) |
| `--data` | `-d` | — | 요청 본문 |
| `--headers` | `-H` | — | 추가 HTTP 헤더 (반복 지정 가능) |
| `--cookies` | — | — | 쿠키 (반복 지정 가능) |
| `--method` | `-X` | `GET` | HTTP 메서드 재정의 (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY` / RFC 10008) |
| `--user-agent` | — | — | 사용자 지정 User-Agent |
| `--cookie-from-raw` | — | — | raw HTTP 요청 파일에서 쿠키를 불러옵니다. 파일을 읽을 수 없거나 `Cookie:` 헤더가 없으면 종료 코드 `2`로 중단합니다 — 그대로 진행하면 로그아웃 상태로 스캔해 `0 XSS`를 보고하기 때문입니다 |

### 세션

인증 세션이 스캔 도중 만료되어 이후 모든 요청이 로그인 페이지를 받고도 "취약점 0건"으로
정상 종료되는 조용한 실패를 막습니다. [세션 모니터링](../../guide/scanning-modes/#세션-모니터링)을 참고하세요.

자격증명이 있으면(`--cookies`, `--cookie-from-raw`, 또는 `Cookie` / `Authorization` 헤더)
자동으로 켜지고, `--session-check` 계열 플래그를 직접 지정해도 켜집니다. 그 외에는 꺼져 있으며
추가 요청도 발생하지 않습니다.

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--session-check` | — | 인증된 응답 본문에 계속 매칭되어야 하는 정규식. 지정하면 이 값이 기준이 되며 내장 휴리스틱은 사용하지 않습니다 |
| `--session-check-url` | — | 세션 재검증 시 스캔 대상 대신 이 URL(절대 `http(s)://`)을 조회합니다 (예: 가벼운 `/api/me` 엔드포인트) |
| `--on-session-loss` | `abort` | `abort`는 해당 대상을 중단하고 같은 호스트의 나머지 대상도 건너뛰며, 탐지 결과가 없으면 `2`로 종료합니다. `continue`는 스캔을 계속하고 종료 코드를 바꾸지 않습니다. 어느 쪽이든 대상은 `clean`이 아니라 `incomplete` / `SESSION_LOST`로 보고됩니다 |

### 스코프

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--include-url` | — | 이 정규식에 매칭되는 URL만 스캔합니다(부분 매칭). 패턴을 더 주려면 플래그를 반복하며, URL은 그중 하나 이상에 매칭되어야 합니다 |
| `--exclude-url` | — | 이 정규식에 매칭되는 URL을 건너뜁니다(부분 매칭). 패턴을 더 주려면 플래그를 반복합니다 |
| `--ignore-param` | — | 건너뛸 파라미터 이름(정확히 일치). 이름을 더 주려면 플래그를 반복합니다 |
| `--out-of-scope` | — | 호스트가 이 패턴에 맞는 대상을 건너뜁니다. `*.example.com`은 `example.com`과 모든 하위 도메인에 맞고, 그 밖의 값은 호스트와 정확히 같아야 합니다(대소문자 무관). 패턴을 더 주려면 플래그를 반복합니다: `--out-of-scope '*.gov' --out-of-scope cdn.example.com`. 쉼표는 구분자가 아닙니다 |
| `--out-of-scope-file` | — | 스코프 외 패턴을 한 줄에 하나씩 적은 파일(빈 줄과 `#` 줄은 무시). 매칭 방식은 `--out-of-scope`와 같습니다. 읽을 수 없는 경로는 치명적 오류(`FILE_READ_ERROR`)입니다 — 제외 목록 없이 계속 진행하면 그 목록에 적힌 호스트를 전부 공격하게 됩니다 |

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
| `--skip-mining-dom` | — | false | HTML `id`/`name` 속성에서 파라미터 이름 수집을 건너뜁니다 (DOM-XSS 탐지가 아님 — `--skip-ast-analysis` 참고) |

### 네트워크

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--timeout` | — | `10` | 요청당 타임아웃(초), `1`–`3600` (네트워크 한정; 전체 스캔 시간을 제한하지 않음) |
| `--scan-timeout` | — | `0` | 페이로드 주입(스캔) 단계의 대상별 실제 경과 시간 하드 상한(초, 최대 `86400`). 초과 시 해당 대상을 중단합니다. 여러 순차 단계가 부분적으로 멈춘 엔드포인트에 대해 각각 요청당 `--timeout` 비용을 치를 때 유용합니다. 이 단계보다 먼저 실행되는 프리플라이트와 파라미터 분석(탐색 + 마이닝)은 이 상한에 포함되지 않습니다. `0`은 비활성화합니다. |
| `--delay` | — | `0` | 요청 간 지연(ms), 워커별; 최대 `60000` |
| `--rate-limit` | `-r`, `--rl` | `0` | 모든 워커와 대상에 걸쳐 공유되는 **전역** 아웃바운드 요청 속도를 초당 요청 수로 제한합니다 (`0` = 무제한). 하나의 워커만 간격을 두는 `--delay`와 달리, `workers × concurrent targets`에서 한꺼번에 나가는 전체 요청량을 제한하므로 공유 IP / 엣지 WAF 임계값에 더 친화적입니다. 최대 `100000`. |
| `--retries` | — | `0` | HTTP 5xx 및 일시적 전송 오류(타임아웃, 연결 재설정) 시 실패한 요청을 이 횟수만큼 재시도합니다 (`0` = 끔, 최대 `100`). HTTP 429는 이 값과 무관하게 항상 재시도합니다. |
| `--retry-delay` | — | `1000` | `--retries` 시도 사이의 지수 백오프 기본 지연(ms) (시도마다 두 배로 증가, 내부적으로 상한 적용; 최대 `60000`). 429에서는 서버의 `Retry-After` 헤더가 우선합니다. |
| `--proxy` | — | — | 프록시 URL — `http(s)://` 또는 `socks4/5(h)://`만 허용; 라우팅 불가한 스킴(예: `ftp://`)은 조용히 직접 스캔하지 않고 시작 시 거부됨 |
| `--insecure` | — | `true` | TLS/SSL 인증서 검증을 건너뜁니다 (자체 서명, 만료, 호스트명 불일치 인증서 허용). 스캐너 사용을 위해 기본적으로 켜져 있으며, 인증서 검증을 강제하려면 `--insecure=false`를 전달합니다. 스캔 대상과 `--blind-oob=`로 직접 지정한 OAST 서버에 적용되며, 공개 interactsh 메시는 항상 검증합니다. |
| `--follow-redirects` | `-F` | false | 3xx 응답을 따라갑니다 |
| `--ignore-return` | — | — | 무시할 HTTP 상태 코드 (쉼표로 구분, 예: `302,403,404`) |

### 엔진

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--workers` | `50` | 대상별 동시 워커 수 (`1`–`500`) |
| `--max-concurrent-targets` | `50` | 전역 동시 대상 수 (`1` 이상) |
| `--max-targets-per-host` | `100` | 호스트별 상한 (`1` 이상) |

### XSS 스캐닝

| 플래그 | 약칭 | 기본값 | 설명 |
|------|-------|---------|-------------|
| `--encoders` | `-e` | `url,html` | 쉼표로 구분된 인코더: `none`, `url`, `2url`, `3url`, `4url`, `html`, `htmlpad`, `base64`, `unicode`, `zwsp` |
| `--remote-payloads` | — | — | `portswigger`, `payloadbox` |
| `--custom-blind-xss-payload` | — | — | 블라인드 페이로드 템플릿 파일(한 줄에 템플릿 하나). 각 줄에는 `{callback}`이 있어야 하며, 이 자리에 `-b` URL이나 OOB 콜백 URL이 들어갑니다. `{callback}`이 없는 줄은 경고와 함께 건너뛰고, 쓸 수 있는 줄이 하나도 없으면 내장 템플릿을 대신 보냅니다. `-b`나 `--blind-oob`와 함께일 때만 사용됩니다 |
| `--blind` | `-b` | — | 블라인드 XSS 콜백 URL |
| `--blind-oob[=servers]` | — | — | interactsh로 OOB/OAST 블라인드 XSS를 활성화합니다; 선택적으로 쉼표로 구분된 서버 도메인 (기본값: 공용 메시). `=` 형식이 필요합니다: `--blind-oob=oast.fun,oast.me` |
| `--blind-oob-secret` | — | — | 자체 호스팅 interactsh 서버용 인증 토큰 (register/poll/deregister 시 `Authorization`으로 전송) |
| `--blind-oob-wait` | — | `30` | 모든 페이로드 전송 후 OOB 콜백을 계속 폴링할 시간(초) (`0` = 스캔 종료 후 추가 대기 없음) |
| `--custom-payload` | — | — | 사용자 지정 페이로드 파일(한 줄에 하나, 빈 줄과 `#` 줄은 무시). `--only-custom-payload`가 없으면 내장 페이로드에 추가됩니다 |
| `--only-custom-payload` | — | false | 사용자 지정 페이로드만 사용합니다. `--custom-payload`가 필요합니다 (없으면 종료 코드 `2`) |
| `--custom-alert-value` | — | `1` | 컨텍스트에 맞춘 반사 페이로드의 `alert()`/`prompt()`/`confirm()` 안에 들어가는 값 (DOM 검증용·폴백 페이로드는 `1` 유지) |
| `--custom-alert-type` | — | `none` | `none` 또는 `str` |
| `--inject-marker` | — | — | 이 토큰을 페이로드로 치환합니다 (예: `FUZZ`) |
| `--skip-xss-scanning` | — | false | 페이로드 주입을 건너뜁니다 |
| `--deep-scan` | — | false | 첫 탐지 결과 이후에도 계속 테스트합니다 |
| `--sxss` | — | false | Stored XSS 모드를 활성화합니다 |
| `--sxss-url` | — | — | SXSS용 조회 URL (절대 `http(s)://`); `--sxss`와 함께일 때만 사용됨. 생략하면 `--sxss`가 폼 탐색 결과에서 조회 페이지를 자동으로 찾습니다 |
| `--sxss-method` | — | `GET` | 조회 메서드 |
| `--sxss-retries` | — | `3` | 저장된 출력을 가져올 때 조회 URL에 대한 재시도 횟수 (최대 `20`; 재시도마다 500 ms × 시도 횟수만큼 대기, 최대 5초) |
| `--max-payloads-per-param` | — | `0` | 파라미터별로 테스트하는 페이로드 수 제한 (`0`은 `--deep-scan`이 없으면 세트당 3000개의 내장 안전 상한을 적용) |
| `--skip-ast-analysis` | — | false | AST DOM-XSS(`[A]` 결과를 만드는 source→sink 패스)를 건너뜁니다. `--skip-mining-dom`이 아니라 이 플래그입니다 |
| `--analyze-external-js` | — | false | 동일 출처의 `<script src>` 번들을 가져와 AST DOM-XSS 분석을 수행합니다 (프리플라이트, 대상별 1회; 최대 16개 파일, 각 512 KiB; `--include-url`/`--exclude-url`을 준수) |
| `--hpp` | — | false | HTTP 파라미터 오염(HPP) |
| `--detect-outdated-libs` | — | false | 오래되었거나 알려진 취약점이 있는 JS 라이브러리도 보고합니다 (정보성, CWE-1104; 추가 요청 0회) |

### WAF

| 플래그 | 기본값 | 설명 |
|------|---------|-------------|
| `--waf-bypass` | `auto` | `auto`는 탐지된 WAF에 맞는 우회 변형과 추가 인코더를 적용합니다. `off`는 WAF를 탐지해 보고만 하고 페이로드는 바꾸지 않습니다. `force`도 받지만 현재는 `auto`와 똑같이 동작하므로, WAF를 지정하려면 `--force-waf`를 쓰세요 |
| `--skip-waf-probe` | false | 자극 프로브를 건너뜁니다(프리플라이트 응답의 헤더와 본문에 대한 패시브 탐지는 그대로 실행) |
| `--force-waf` | — | 탐지 결과 대신 대상을 이 WAF로 간주합니다. `auto`와 `force`에서 동작하며, `off`에서는 WAF를 보고만 하고 우회는 적용하지 않습니다. 이름: `cloudflare`, `aws`, `akamai`, `imperva`, `modsecurity`, `owasp-crs`, `sucuri`, `f5`, `barracuda`, `fortiweb`, `azure`, `cloudarmor`, `fastly`, `wordfence`, `citrix` (대소문자 무관; `cf`, `modsec`, `incapsula`, `netscaler` 같은 별칭도 허용) |
| `--waf-evasion` | false | 적응형 회피: 요청 간 무작위 지터(WAF 탐지 여부와 무관하게 적용), 차단된 응답이 몰릴 때 점증하는 쿨다운, 파라미터별 페이로드를 하나씩 순차 전송. 이 플래그가 없어도 WAF별 페이싱 힌트는 탐지 시 자동으로 적용됩니다. `--rate-limit`와 함께 쓰면 좋습니다. [WAF 우회](../../guide/waf-bypass/#회피-스로틀) 참고. |
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
| `--api-key` | — | — | 필수 `X-API-KEY` 헤더 값 (또는 `DALFOX_API_KEY`; 둘 다 있으면 플래그가 우선). 빈 값 `--api-key ""`는 인증을 끕니다 |
| `--log-file` | — | — | 일반 텍스트 로그 파일 (Unix에서는 `0600` 권한으로 생성; 기존 파일을 그룹/기타 사용자가 읽을 수 있으면 서버가 시작 시 경고) |
| `--allowed-origins` | — | — | CORS 오리진(쉼표로 구분). 정확한 오리진, `regex:<pattern>`, `*`를 쓸 수 있으며, 패턴은 포트를 포함한 오리진 전체와 맞아야 합니다 |
| `--jsonp` | — | false | 응답을 JSONP로 감쌉니다 |
| `--callback-param-name` | — | `callback` | JSONP 콜백 파라미터 |
| `--cors-allow-methods` | — | `GET,POST,OPTIONS,PUT,PATCH,DELETE` | CORS 메서드 |
| `--cors-allow-headers` | — | `Content-Type,X-API-KEY,Authorization` | CORS 헤더 |
| `--rate-limit` | — | — | **스캔마다** 적용되는 서버 전역 아웃바운드 요청 속도 상한 (초당 요청 수, 지정하지 않거나 `0`이면 무제한). 제출된 스캔은 더 낮게 요청할 수는 있어도 이 값을 넘을 수는 없습니다 |
| `--scan-timeout` | — | — | **스캔마다** 적용되는 서버 전역 전체 실행 시간 상한(초, 지정하지 않거나 `0`이면 무제한). 제출된 스캔은 더 짧게 요청할 수는 있어도 이 값을 넘을 수는 없습니다 |
| `--max-concurrent-scans` | — | `100` | 동시(큐 대기 + 실행 중) 스캔 수 제한. 초과하면 새 제출은 `503`을 받습니다 (`0` = 무제한) |
| `--allowed-hosts` | — | — | 요청 `Host` 헤더에서 추가로 허용할 호스트명(쉼표로 구분). 바인딩 호스트, `localhost`, IP 리터럴은 기본 허용입니다. 리버스 프록시가 공개 호스트명을 전달할 때 필요합니다 |
| `--max-retained-scans` | — | `1000` | 메모리에 보관하는 *종료된* 스캔 수 상한. 초과하면 가장 오래된 것부터 제거됩니다 (`0` = 무제한). 큐에 있거나 실행 중인 스캔은 제거되지 않습니다 |
| `--max-body-bytes` | — | `1048576` | `POST /scan` 및 `/preflight`가 허용하는 최대 요청 본문 크기(바이트). 초과 시 `400`(`invalid request body`)으로 거부 |

엔드포인트는 [REST API 서버](../../integrations/server/)를 참고하세요.

---

## `dalfox payload`

페이로드 컬렉션을 나열하거나 가져옵니다.

```bash
dalfox payload [SELECTOR] [--json]
```

선택한 페이로드를 한 줄에 하나씩이 아니라 JSON 배열로 출력하려면 `--json`을 쓰세요. 선택자 없이 실행하면 요약(사용 예시와 선택자별 개수)을 출력하며, `--json`을 주면 JSON으로 출력합니다. 알 수 없는 선택자는 가장 가까운 이름을 제안하고 종료 코드 `2`로 끝납니다.

선택자:

| 선택자 | 출력 내용 |
|----------|----------------|
| `javascript` | JS 문자열 / 스크립트 컨텍스트에서 쓰이는 표준 JavaScript 실행 페이로드(`alert(1)`, 백틱 및 키워드 분할 변형 등) |
| `event-handlers` | DOM 이벤트 핸들러 속성 이름 |
| `useful-tags` | 유용한 HTML 태그 |
| `uri-scheme` | `javascript:`/`data:` URL 페이로드 |
| `special-chars` | 컨텍스트 프로빙용 특수 문자(및 인코딩된 변형) |
| `functions` | 필터를 우회하는 변형이 포함된 확인 가능한 싱크(`alert`, `prompt`, ...) |
| `awesome-alert` | 스크린샷용으로 다듬어진 alert PoC(`alert(document.domain)`, ...) |
| `dom-clobbering` | DOM 클로버링 벡터 |
| `mxss` | Mutation-XSS / 새니타이저 우회 페이로드 |
| `blind` | Blind-XSS 스켈레톤(`{}` = OOB 콜백 URL) |
| `portswigger` | 원격: PortSwigger XSS 치트시트 |
| `payloadbox` | 원격: PayloadBox XSS 목록 |
| `all` | 위의 모든 로컬 선택자를 한 번에, 각 그룹 앞에 `# name` 헤더를 붙여 출력 (네트워크 요청 없음) |

---

## `dalfox mcp`

MCP stdio 서버를 실행합니다.

```bash
dalfox mcp
```

전역 플래그 외에는 플래그가 없습니다. 도구 정의는 [MCP 서버](../../integrations/mcp/)를 참고하세요.

---

## `dalfox completion`

셸 자동완성 스크립트를 생성해 stdout으로 출력합니다.

```bash
dalfox completion <SHELL>
```

지원하는 셸: `bash`, `zsh`, `fish`, `powershell`, `elvish`.

```bash
# bash
dalfox completion bash > /etc/bash_completion.d/dalfox

# zsh
dalfox completion zsh > "${fpath[1]}/_dalfox"

# fish
dalfox completion fish > ~/.config/fish/completions/dalfox.fish
```

stdout에는 스크립트 외에 아무것도 출력되지 않으므로, 출력을 그대로 파일로 리다이렉트해도 안전합니다. 아래의 숨김 명령은 생성된 스크립트에 포함되지 않습니다.

---

## 숨김 명령

`--help`와 자동완성 스크립트에는 나오지 않는 명령입니다.

| 명령 | 같은 동작 |
|------|-----------|
| `dalfox url -u <URL> [FLAGS]` | `dalfox scan -i url <URL> [FLAGS]` |
| `dalfox file <FILE> [FLAGS]` | `dalfox scan -i file <FILE> [FLAGS]` |
| `dalfox pipe [FLAGS]` | `dalfox scan -i pipe [FLAGS]` (stdin에서 대상 읽기) |
| `dalfox man` | roff 형식 man 페이지를 stdout으로 출력 (패키징용) |

`url`, `file`, `pipe`는 v2 시절 스크립트를 위해 남아 있으며 `dalfox scan` 플래그를 모두 받습니다. `-i`를 명시하면 그 값이 우선하므로 `dalfox pipe -i har`는 stdin에서 HAR 파일을 읽습니다. 새로 작성하는 스크립트에서는 `dalfox scan`을 쓰세요.

---

## 함께 보기

- [설정 파일 레퍼런스](../config/)
- [환경 변수](../environment/)
