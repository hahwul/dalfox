+++
title = "설정 파일"
description = "Dalfox의 TOML/JSON 설정 파일이 지원하는 모든 키."
weight = 2
toc = true
+++

Dalfox는 설정 디렉터리를 하나만 고릅니다.

1. `XDG_CONFIG_HOME`이 설정되어 있고 비어 있지 않으면 `$XDG_CONFIG_HOME/dalfox/`
2. 그렇지 않으면 `$HOME/.config/dalfox/` (`HOME`이 없으면 `%USERPROFILE%\.config\dalfox\`, 예: Windows)

첫 번째 디렉터리에 파일이 없다고 두 번째 디렉터리로 넘어가지는 않습니다. 고른 디렉터리에서 `config.toml`을 읽고, `config.toml`이 없으면 `config.json`을 읽습니다. 둘 다 없으면 전부 주석 처리된 `config.toml` 템플릿을 만들고 내장 기본값으로 실행합니다. 이 템플릿은 `scan`뿐 아니라 `completion`과 `man`을 제외한 어떤 서브커맨드를 처음 실행할 때도 만들어집니다.

`--config <path>`로 재정의할 수 있습니다. TOML과 JSON 모두 허용됩니다. `.json` 경로는 JSON으로 먼저, 그 밖의 경로는 TOML로 먼저 파싱하고, 실패하면 다른 형식으로 다시 시도합니다. 존재하지 않는 `--config` 경로는 기본 템플릿(`.json` 경로면 JSON)으로 새로 만들어지고, 실행은 내장 기본값으로 진행되며 stderr에 안내가 출력됩니다. 설정 파일 크기는 최대 1 MiB입니다.

모든 항목은 `[scan]` 테이블 아래에 위치하며 `dalfox scan` 플래그 이름(snake-case)을 그대로 따릅니다. 이름이 다른 것은 `--blind` / `-b` 하나로, 키 이름은 `blind_callback_url`입니다. 전역 `--debug` 플래그는 `debug` 키에 대응합니다.

설정 파일은 CLI 스캔에만 적용됩니다. `dalfox server`와 `dalfox mcp`는 요청마다 스캔 옵션을 받으며 `[scan]`을 읽지 않습니다.

## 전체 예시

```toml
[scan]
# INPUT
input_type = "auto"   # auto, url, file, pipe, raw-http, har
dedup_urls = "exact"  # exact, signature (파라미터 값만 다른 URL 병합), off
# state_file = "scan.state"  # 완료된 대상을 기록해 재실행 시 건너뜁니다. CLI 전용 — `dalfox server`/MCP는 무시

# OUTPUT
format = "plain"
# output = "results.json"
include_request = false
include_response = false
include_all = false
silence = false
dry_run = false
stream_findings = false
poc_type = "plain"
# limit = 100
limit_result_type = "all"
only_poc = []
# baseline = "baseline.json"
baseline_mode = "filter"
no_color = false

# TARGETS
param = []
# data = "user=test"
# headers = ["Accept: text/html"]
cookies = []
method = "GET"
# user_agent = "Mozilla/5.0"
# cookie_from_raw = "request.txt"

# SESSION
# session_check = "Sign out"
# session_check_url = "https://app.example.com/api/me"
on_session_loss = "abort"

# SCOPE
include_url = []
exclude_url = []
ignore_param = []
out_of_scope = []    # 항목 하나에 패턴 하나: ["*.gov", "cdn.example.com"]
# out_of_scope_file = "scope.txt"

# DISCOVERY
only_discovery = false
skip_discovery = false
skip_reflection_header = false
skip_reflection_cookie = false
skip_reflection_path = false

# MINING
# mining_dict_word = "params.txt"
remote_wordlists = []
skip_mining = false
skip_mining_dict = false
skip_mining_dom = false

# NETWORK
timeout = 10
scan_timeout = 0
delay = 0
rate_limit = 0
retries = 0
retry_delay = 1000
# proxy = "http://127.0.0.1:8080"
insecure = true
follow_redirects = false
ignore_return = []

# ENGINE
workers = 50
max_concurrent_targets = 50
max_targets_per_host = 100

# XSS SCANNING
encoders = ["url", "html"]
remote_payloads = []
# custom_blind_xss_payload = "blind.txt"
# blind_callback_url = "https://callback.example"
# blind_oob = []                       # [] = enable with the public interactsh mesh; or name servers: ["oast.fun"]
# blind_oob_secret = "token"           # auth token for a self-hosted interactsh server
# blind_oob_wait = 30                  # seconds to keep polling after payloads are sent
# custom_payload = "payloads.txt"
only_custom_payload = false
# inject_marker = "FUZZ"
custom_alert_value = "1"
custom_alert_type = "none"
skip_xss_scanning = false
deep_scan = false
sxss = false
# sxss_url = "https://target.app/retrieval"
sxss_method = "GET"
sxss_retries = 3
max_payloads_per_param = 0
skip_ast_analysis = false
analyze_external_js = false
detect_outdated_libs = false
hpp = false

# WAF
waf_bypass = "auto"
skip_waf_probe = false
# force_waf = "cloudflare"
waf_evasion = false
waf_min_confidence = 0.3

# LOGGING
debug = false
```

## 키 레퍼런스

### 입력

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `input_type` | string | `"auto"` | `auto`, `url`, `file`, `pipe`, `raw-http`, `har` |
| `dedup_urls` | string | `"exact"` | `exact`, `signature`(파라미터 값만 다른 URL을 하나로 병합), `off` |
| `state_file` | string | — | 완료된 대상을 기록해 재실행 시 건너뜁니다. **CLI 전용** — `dalfox server`/MCP는 무시합니다 |

### 출력

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `format` | string | `"plain"` | `plain`, `json`, `jsonl`, `markdown`, `sarif`, `toml` |
| `output` | string | — | 출력 파일 경로 |
| `include_request` | bool | `false` | 원본 HTTP 요청 첨부 |
| `include_response` | bool | `false` | 응답 본문 첨부 |
| `include_all` | bool | `false` | 위 둘을 함께 적용하는 축약 |
| `silence` | bool | `false` | 로그 억제 |
| `dry_run` | bool | `false` | 페이로드를 전송하지 않음 |
| `stream_findings` | bool | `false` | 스캔 종료 요약 이후가 아니라 스캔 도중에 각 탐지 결과를 출력 (plain 형식만; `output`, `limit`, `only_poc`, `baseline` 중 하나라도 설정되면 꺼짐) |
| `poc_type` | string | `"plain"` | `plain`, `curl`, `httpie`, `http-request` |
| `limit` | int | — | 결과 개수 상한 (`1` 이상이어야 하며, `0`은 경고와 함께 무시) |
| `limit_result_type` | string | `"all"` | 집계 대상 타입: `all`, `v`, `r`, `a`, `i` |
| `only_poc` | array | `[]` | 출력 필터: `["v","a"]` |
| `baseline` | string | — | 비교할 이전 JSON/JSONL 리포트. 그 이후 새로 생긴 건만 보고합니다. **CLI 전용** — `dalfox server`/MCP는 무시합니다 |
| `baseline_mode` | string | `"filter"` | `filter`는 알려진 건을 제거, `annotate`는 유지한 채 `new` 표시 |
| `no_color` | bool | `false` | ANSI 색상 비활성화 |

### 대상

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `param` | array | `[]` | 파라미터 이름 (선택적으로 `name:location`) |
| `data` | string | — | 요청 본문 |
| `headers` | array | `[]` | HTTP 헤더 |
| `cookies` | array | `[]` | 쿠키 문자열 |
| `method` | string | `"GET"` | HTTP 메서드 (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`, `OPTIONS`, `PATCH`, `QUERY`) |
| `user_agent` | string | — | User-Agent 재정의 |
| `cookie_from_raw` | string | — | 쿠키용 원본 요청 파일 |

### 세션

스캔 도중 세션 만료 감지 — [세션 모니터링](../../guide/scanning-modes/)을 참고하세요.

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `session_check` | string | — | 인증된 응답 본문에 계속 매칭되어야 하는 정규식 |
| `session_check_url` | string | — | 재검증 전용 프로브 URL (절대 `http(s)://`) |
| `on_session_loss` | string | `"abort"` | `abort` 또는 `continue` |

### 스코프

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `include_url` | array | `[]` | 정규식 패턴(부분 매칭). 하나 이상에 매칭되는 URL만 스캔합니다 |
| `exclude_url` | array | `[]` | 건너뛸 URL의 정규식 패턴(부분 매칭) |
| `ignore_param` | array | `[]` | 건너뛸 파라미터 이름(정확히 일치) |
| `out_of_scope` | array | `[]` | 건너뛸 호스트 패턴, 항목 하나에 하나씩(`["*.gov", "cdn.example.com"]`). `*.example.com`은 `example.com`과 하위 도메인에 맞고, 그 밖의 값은 호스트와 정확히 같아야 합니다. 한 항목 안의 쉼표는 구분자가 아닙니다 |
| `out_of_scope_file` | string | — | 스코프 외 패턴을 한 줄에 하나씩 적은 파일. 읽을 수 없는 경로면 스캔을 중단합니다 |

### 탐색 및 마이닝

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `only_discovery` | bool | `false` | 탐색 후 중단 |
| `skip_discovery` | bool | `false` | 탐색을 완전히 건너뜀 |
| `skip_reflection_header` | bool | `false` | 헤더 반사 검사 건너뜀 |
| `skip_reflection_cookie` | bool | `false` | 쿠키 반사 검사 건너뜀 |
| `skip_reflection_path` | bool | `false` | 경로 반사 검사 건너뜀 |
| `mining_dict_word` | string | — | 워드리스트 경로 |
| `remote_wordlists` | array | `[]` | `burp`, `assetnote` |
| `skip_mining` | bool | `false` | 모든 마이닝 건너뜀 |
| `skip_mining_dict` | bool | `false` | 사전 기반 마이닝 건너뜀 |
| `skip_mining_dom` | bool | `false` | HTML `id`/`name` 속성에서 파라미터 이름 수집 건너뜀 (DOM-XSS 탐지가 아님 — `skip_ast_analysis` 참고) |

### 네트워크

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `timeout` | int | `10` | 요청 타임아웃 (초, `1`–`3600`); 원격 페이로드/워드리스트를 가져올 때도 사용 |
| `scan_timeout` | int | `0` | 페이로드 주입 단계의 대상별 실제 경과 시간 하드 상한(초, 최대 `86400`); 프리플라이트와 탐색/마이닝은 포함되지 않음. 0이면 비활성화. |
| `delay` | int | `0` | 요청 간 지연 (ms), 워커별; 최대 `60000` |
| `rate_limit` | int | `0` | 모든 워커/대상이 공유하는 전역 요청 속도 상한 (req/sec); `0` = 무제한, 최대 `100000` |
| `retries` | int | `0` | 5xx / 일시적 전송 오류를 이 횟수만큼 재시도 (`0` = 끔, 최대 `100`; 429는 항상 재시도) |
| `retry_delay` | int | `1000` | `retries` 시도 사이의 기본 백오프 (ms, 지수 증가; 최대 `60000`) |
| `proxy` | string | — | 프록시 URL (`http(s)://` 또는 `socks4/5(h)://`); 원격 페이로드/워드리스트를 가져올 때도 사용 |
| `insecure` | bool | `true` | TLS 인증서 검증 건너뜀; 검증을 강제하려면 `false`로 설정. 스캔 대상과 `--blind-oob=`로 지정한 OAST 서버에 적용되며, 공개 interactsh 메시는 항상 검증 |
| `follow_redirects` | bool | `false` | 3xx 응답 추적 |
| `ignore_return` | array | `[]` | 무시할 HTTP 상태 코드, 정수로 지정 (`[302, 403]`) |

### 엔진

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `workers` | int | `50` | 대상별 동시 워커 수 (`1`–`500`) |
| `max_concurrent_targets` | int | `50` | 전역 동시 대상 수 (`1` 이상) |
| `max_targets_per_host` | int | `100` | 호스트별 상한 (`1` 이상) |

### XSS 스캐닝

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `encoders` | array | `["url","html"]` | 적용할 인코더: `none`, `url`, `2url`, `3url`, `4url`, `html`, `htmlpad`, `base64`, `unicode`, `zwsp` |
| `remote_payloads` | array | `[]` | 원격 페이로드 소스: `portswigger`, `payloadbox` |
| `custom_blind_xss_payload` | string | — | 블라인드 템플릿 파일. 각 줄에 `{callback}`이 있어야 합니다(없는 줄은 건너뜀) |
| `blind_callback_url` | string | — | 블라인드 XSS 콜백 URL (`--blind` / `-b` 플래그) |
| `blind_oob` | array | — | interactsh로 OOB/OAST 블라인드 XSS 활성화 (`[]` = 공개 메시; 또는 서버 이름 지정). `--blind-oob`와 동일 |
| `blind_oob_secret` | string | — | 자체 호스팅 interactsh 서버용 인증 토큰 |
| `blind_oob_wait` | int | `30` | 페이로드 전송 후 OOB 콜백을 계속 폴링할 시간(초) |
| `custom_payload` | string | — | 커스텀 페이로드 파일(한 줄에 하나) |
| `only_custom_payload` | bool | `false` | 커스텀 페이로드만 사용; `custom_payload`(또는 `--custom-payload`)가 함께 없으면 스캔이 종료 코드 `2`로 끝남 |
| `inject_marker` | string | — | 페이로드로 치환할 토큰 |
| `custom_alert_value` | string | `"1"` | `alert(X)` 값 |
| `custom_alert_type` | string | `"none"` | `none` 또는 `str` |
| `skip_xss_scanning` | bool | `false` | 공격 없이 탐색만 수행 |
| `deep_scan` | bool | `false` | 첫 탐지 결과 이후에도 계속 진행 |
| `sxss` | bool | `false` | Stored XSS 모드 활성화 |
| `sxss_url` | string | — | 조회 URL |
| `sxss_method` | string | `"GET"` | 조회 메서드 (`method`와 같은 값 집합) |
| `sxss_retries` | int | `3` | 조회 URL을 가져올 때의 재시도 횟수 (최대 `20`) |
| `max_payloads_per_param` | int | `0` | 파라미터당 테스트하는 기본 페이로드 상한 (`0`은 `deep_scan`이 켜져 있지 않으면 세트당 3000개 안전 상한을 적용) |
| `skip_ast_analysis` | bool | `false` | AST DOM-XSS 건너뜀 |
| `analyze_external_js` | bool | `false` | 동일 출처의 `<script src>` 번들을 가져와 AST DOM-XSS 분석 수행 (프리플라이트, 대상당 1회; 최대 16개 파일, 각 512 KiB; `include_url`/`exclude_url` 준수) |
| `detect_outdated_libs` | bool | `false` | 오래되었거나 알려진 취약점이 있는 JS 라이브러리도 보고 (정보성, CWE-1104; 추가 요청 0회) |
| `hpp` | bool | `false` | HTTP Parameter Pollution |

### WAF

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `waf_bypass` | string | `"auto"` | `auto` 또는 `off`(탐지와 보고만). `force`도 받지만 `auto`와 똑같이 동작하며, WAF를 고르는 것은 `force_waf`입니다 |
| `skip_waf_probe` | bool | `false` | 능동적 핑거프린팅 건너뜀 |
| `force_waf` | string | — | 탐지 결과 대신 대상을 이 WAF로 간주 (`--force-waf`와 같은 이름, 대소문자 무관) |
| `waf_evasion` | bool | `false` | WAF 탐지 시 적응형 회피: 랜덤 지터 + 차단 클러스터에 대한 점증 쿨다운 (`rate_limit`과 함께 사용) |
| `waf_min_confidence` | float | `0.3` | 이 신뢰도 미만의 핑거프린트 제거 (0.0–1.0); 기본값은 약한 매칭을 억제 |

### 로깅

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `debug` | bool | `false` | 디버그 라인 출력 |

## 우선순위

```
CLI flag  >  Config file  >  Built-in default
```

- 목록 키(`headers`, `encoders`, `param` 등)는 합쳐지지 않고 통째로 대체됩니다. 명령줄에 `-H`를 하나만 줘도 설정 파일의 `headers` 항목은 모두 빠집니다.
- `deep_scan`이나 `silence` 같은 켜고 끄는 스위치는 명령줄에서 켜기만 할 수 있습니다. 설정 파일에서 `true`로 켜 두면 한 번의 실행만 끄는 플래그는 없습니다. 예외는 `insecure`로, `--insecure=false`가 설정 값을 덮어씁니다.

## 검증

설정 값은 CLI 인자 파서를 거치지 않으므로, Dalfox는 파일을 읽을 때 따로 검사합니다.

- 선택지가 정해진 키(`format`, `poc_type`, `limit_result_type`, `only_poc`, `baseline_mode`, `custom_alert_type`, `dedup_urls`, `waf_bypass`, `on_session_loss`, `encoders`)에 잘못된 값을 넣거나, 알 수 없는 `method` / `sxss_method` / `force_waf`, 올바른 정규식이 아닌 `session_check`, 절대 URL이 아닌 `session_check_url`, `limit = 0`을 쓰면 stderr에 `Warning:`이 출력됩니다. 해당 키는 내장 기본값으로 돌아가고 스캔은 계속됩니다. `method`, `sxss_method`, `force_waf`는 플래그와 똑같이 대소문자가 정규화됩니다.
- `proxy`, `sxss_url`, `session_check_url`은 플래그와 같은 시작 검사를 거칩니다. Dalfox가 라우팅할 수 없는 프록시 스킴이나 스킴이 `http`/`https`가 아닌 URL이면 `PARSE_ERROR`(종료 코드 `2`)로 스캔이 중단됩니다.
- 숫자 키는 대응하는 플래그와 같은 범위 제한을 받습니다(`workers`, `timeout`, `delay`, `scan_timeout`, `rate_limit`, `retries`, `retry_delay`, `sxss_retries`, `max_concurrent_targets`, `max_targets_per_host`, `waf_min_confidence`). 범위를 벗어나면 `INVALID_INPUT_TYPE`(종료 코드 `2`)으로 스캔이 중단됩니다.
- 알 수 없는 키와 `[scan]` 테이블 밖에 둔 키는 경고 없이 무시됩니다. 효과가 없는 것 같은 키가 있다면 철자와 위치를 확인하세요.
- 파싱에 실패한 파일(TOML 문법 오류, `workers = "10"`처럼 타입이 틀린 값 등)은 통째로 무시됩니다. `--config`로 지정한 파일이면 경고가 출력되고, 기본 경로의 파일이면 아무 메시지 없이 무시됩니다.

예시는 [시작하기 → 설정](../../getting-started/configuration/)을 참고하세요.
