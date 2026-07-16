+++
title = "설정 파일"
description = "Dalfox의 TOML/JSON 설정 파일이 지원하는 모든 키."
weight = 2
toc = true
+++

Dalfox는 다음 순서로 설정 파일을 찾습니다.

1. `$XDG_CONFIG_HOME/dalfox/config.toml`
2. `$HOME/.config/dalfox/config.toml`

`--config <path>`로 재정의할 수 있습니다. TOML과 JSON 모두 허용되며, TOML이 기본값입니다.

모든 항목은 `[scan]` 테이블 아래에 위치하며 CLI 플래그 이름(snake-case)을 그대로 따릅니다.

## 전체 예시

```toml
[scan]
# INPUT
input_type = "auto"   # auto, url, file, pipe, raw-http, har

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
no_color = false

# TARGETS
param = []
# data = "user=test"
headers = ["Accept: text/html"]
cookies = []
method = "GET"
user_agent = "Dalfox/3"
# cookie_from_raw = "request.txt"

# SCOPE
include_url = []
exclude_url = []
ignore_param = []
out_of_scope = []
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
| `stream_findings` | bool | `false` | 스캔 종료 요약 이후가 아니라 스캔 도중에 각 탐지 결과를 출력 (plain 형식만) |
| `poc_type` | string | `"plain"` | `plain`, `curl`, `httpie`, `http-request` |
| `limit` | int | — | 결과 개수 상한 |
| `limit_result_type` | string | `"all"` | 집계 대상 타입: `all`, `v`, `r`, `a` |
| `only_poc` | array | `[]` | 출력 필터: `["v","a"]` |
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

### 스코프

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `include_url` | array | `[]` | 포함할 URL의 정규식 패턴 |
| `exclude_url` | array | `[]` | 제외할 URL의 정규식 패턴 |
| `ignore_param` | array | `[]` | 건너뛸 파라미터 이름 |
| `out_of_scope` | array | `[]` | 와일드카드 도메인 패턴 |
| `out_of_scope_file` | string | — | 스코프 외 호스트를 나열한 파일 |

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
| `skip_mining_dom` | bool | `false` | DOM 마이닝 건너뜀 |

### 네트워크

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `timeout` | int | `10` | 요청 타임아웃 (초) |
| `scan_timeout` | int | `0` | 스캔 단계(프리플라이트 이후)에서 대상별 실제 경과 시간 상한(초). 0이면 비활성화. |
| `delay` | int | `0` | 요청 간 지연 (ms), 워커별 |
| `rate_limit` | int | `0` | 모든 워커/대상이 공유하는 전역 요청 속도 상한 (req/sec); `0` = 무제한 |
| `retries` | int | `0` | 5xx / 일시적 전송 오류를 이 횟수만큼 재시도 (`0` = 끔; 429는 항상 재시도) |
| `retry_delay` | int | `1000` | `retries` 시도 사이의 기본 백오프 (ms, 지수 증가) |
| `proxy` | string | — | 프록시 URL |
| `insecure` | bool | `true` | TLS 인증서 검증 건너뜀; 검증을 강제하려면 `false`로 설정 |
| `follow_redirects` | bool | `false` | 3xx 응답 추적 |
| `ignore_return` | array | `[]` | 무시할 HTTP 상태 코드 |

### 엔진

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `workers` | int | `50` | 대상별 동시 워커 수 |
| `max_concurrent_targets` | int | `50` | 전역 동시 대상 수 |
| `max_targets_per_host` | int | `100` | 호스트별 상한 |

### XSS 스캐닝

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `encoders` | array | `["url","html"]` | 적용할 인코더 |
| `remote_payloads` | array | `[]` | 원격 페이로드 소스 |
| `custom_blind_xss_payload` | string | — | 커스텀 블라인드 템플릿 파일 |
| `blind_callback_url` | string | — | 아웃오브밴드 콜백 URL |
| `blind_oob` | array | — | interactsh를 통한 OOB/OAST 블라인드 XSS 활성화 (`[]` = 공개 메시; 또는 서버 이름 지정). `--blind-oob`와 동일 |
| `blind_oob_secret` | string | — | 자체 호스팅 interactsh 서버용 인증 토큰 |
| `blind_oob_wait` | int | `30` | 페이로드 전송 후 OOB 콜백을 계속 폴링할 시간(초) |
| `custom_payload` | string | — | 커스텀 페이로드 파일 |
| `only_custom_payload` | bool | `false` | 커스텀 페이로드만 사용 |
| `inject_marker` | string | — | 페이로드로 치환할 토큰 |
| `custom_alert_value` | string | `"1"` | `alert(X)` 값 |
| `custom_alert_type` | string | `"none"` | `none` 또는 `str` |
| `skip_xss_scanning` | bool | `false` | 공격 없이 탐색만 수행 |
| `deep_scan` | bool | `false` | 첫 탐지 결과 이후에도 계속 진행 |
| `sxss` | bool | `false` | Stored XSS 모드 활성화 |
| `sxss_url` | string | — | 조회 URL |
| `sxss_method` | string | `"GET"` | 조회 메서드 |
| `sxss_retries` | int | `3` | 조회 URL을 가져올 때의 재시도 횟수 |
| `max_payloads_per_param` | int | `0` | 파라미터당 테스트하는 페이로드 상한 (`0` = 무제한) |
| `skip_ast_analysis` | bool | `false` | AST DOM-XSS 건너뜀 |
| `analyze_external_js` | bool | `false` | 동일 출처의 `<script src>` 번들을 가져와 AST DOM-XSS 분석 수행 (프리플라이트, 대상당 1회; 최대 16개 파일, 각 512 KiB; `include_url`/`exclude_url` 준수) |
| `detect_outdated_libs` | bool | `false` | 오래되었거나 알려진 취약점이 있는 JS 라이브러리도 보고 (정보성, CWE-1104; 추가 요청 0회) |
| `hpp` | bool | `false` | HTTP Parameter Pollution |

### WAF

| 키 | 타입 | 기본값 | 설명 |
|-----|------|---------|-------------|
| `waf_bypass` | string | `"auto"` | `auto`, `force`, `off` |
| `skip_waf_probe` | bool | `false` | 능동적 핑거프린팅 건너뜀 |
| `force_waf` | string | — | `waf_bypass = "force"`일 때의 WAF 이름 |
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

예시는 [시작하기 → 설정](../../getting-started/configuration/)을 참고하세요.
