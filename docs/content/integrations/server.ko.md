+++
title = "REST API 서버"
description = "비동기 작업 관리, CORS, JSONP, API 키 인증을 갖춘 HTTP 서비스로 Dalfox를 실행합니다."
weight = 1
toc = true
+++

`dalfox server`는 스캔을 큐에 넣고 비동기로 실행하는 상시 구동 HTTP 서비스를 시작합니다. 스캔을 제출하면 `scan_id`를 돌려받으며, 원하는 대로 폴링하거나 취소할 수 있습니다.

## 서버 시작하기

```bash
dalfox server
# 기본값으로 http://127.0.0.1:6664 에서 대기
```

자주 쓰는 옵션:

```bash
dalfox server \
  --port 6664 \
  --host 0.0.0.0 \
  --api-key "8f2b1c6d4a9e7053b8c1f4d2e6a09b73" \
  --log-file /var/log/dalfox.log
```

`--log-file`은 제출된 모든 대상 URL을 기록하고, 그런 URL에는 대개 그 대상을 스캔할 이유가
된 자격증명이 들어 있습니다. 그래서 로그 파일을 새로 만들 때는 `0600`으로 생성합니다.
이미 있는 파일의 권한은 그대로 두며, 그룹/기타 사용자가 읽을 수 있으면 기동 시 경고합니다
— 구버전에서 그대로 업그레이드하면 이 상태가 됩니다. 파일 권한을 넓히지 말고 로그 수집기의
uid를 맞추세요.

### 인증

`--api-key`를 설정했거나 `DALFOX_API_KEY`를 export 했다면, 모든 요청에 다음이 들어가야 합니다:

```
X-API-KEY: 8f2b1c6d4a9e7053b8c1f4d2e6a09b73
```

API 키를 설정하지 않으면 서버는 인증 없는 요청도 받습니다. 그럴 때는 `127.0.0.1`에 바인딩하세요.

틀린 키에 대한 제한이나 잠금이 없으므로, 포트에 접근할 수 있는 공격자와 유효한 키 사이를
가로막는 것은 키 길이뿐입니다. 최소 24자의 무작위 문자열을 사용하세요 — 그보다 짧으면
서버가 기동 시 경고합니다:

```bash
export DALFOX_API_KEY="$(openssl rand -hex 16)"
```

### 브라우저 요청

`127.0.0.1` 바인딩은 네트워크를 막아 줄 뿐, *브라우저*를 막아 주지는 않습니다. 사용자가
방문한 웹페이지가 사용자 본인의 브라우저를 통해 루프백 API를 호출할 수 있기 때문입니다.
이 서버에서는 그 영향이 특히 큽니다 — `GET /scan`은 쿼리 파라미터만으로 스캔을 시작하고
`callback_url`은 결과를 임의의 주소로 POST 하므로, 공격자는 응답을 읽지 않고도 결과를
가져갈 수 있습니다.

그래서 서버는 브라우저가 크로스사이트로 표시한 요청을 거부합니다:

- `--allowed-origins`에 없는 `Origin` 헤더, 또는
- `Sec-Fetch-Site: cross-site` / `same-site` (브라우저가 `<img>`, `<script>`를 포함한
  모든 서브리소스 로드에 붙이는 헤더).

두 경우 모두 `403`으로 응답합니다. curl, CLI, 에이전트, CI 작업 같은 비브라우저
클라이언트는 두 헤더를 보내지 않으므로 영향을 받지 않습니다.

`Host` 헤더도 같은 방식으로 검사하며, 이것이 DNS 리바인딩(공격자가 소유한 호스트명을
사용자 머신으로 재해석시켜 브라우저가 동일 출처로 취급하게 만드는 공격)을 막습니다.
IP 리터럴, `localhost`, 바인딩한 `--host`는 항상 허용되고, 그 외 호스트명은 명시해야 합니다:

```bash
# 프록시가 공개 호스트명을 dalfox로 전달할 때만 필요합니다
dalfox server --allowed-hosts "dalfox.internal,scan.corp.example"
```

실제 웹 UI가 API를 호출하게 하려면 해당 출처를 지정하세요. 이것이 게이트를 통과하는
공식적인 방법입니다:

```bash
dalfox server --allowed-origins "https://app.example.com"
```

### CORS

```bash
dalfox server \
  --allowed-origins "https://app.example.com,https://admin.example.com" \
  --cors-allow-methods "GET,POST,OPTIONS,DELETE" \
  --cors-allow-headers "Content-Type,X-API-KEY,Authorization"
```

`*` 하나만 쓰면 모든 오리진을 허용하고(아래 참고), 항목 안에 들어간 `*`는
와일드카드입니다(`https://*.example.com`). 정규식은 `regex:^https://.*\.example\.com$` 형태로 지원됩니다.

`--allowed-origins`를 설정하지 않으면 CORS 헤더를 아예 보내지 않습니다. 설정했다면
`--cors-allow-methods`의 기본값은 `GET,POST,OPTIONS,PUT,PATCH,DELETE`,
`--cors-allow-headers`의 기본값은 `Content-Type,X-API-KEY,Authorization`입니다.

두 형태 모두 `Origin` **전체**와 매칭되므로, 패턴을 부분 문자열로 포함하는 더 긴 호스트가
통과할 수 없습니다 — `regex:https://app\.example\.com`은 `https://app.example.com.evil.com`과
매칭되지 않습니다. 앵커(`^`, `$`)를 직접 써도 됩니다. 중복일 뿐 문제가 되지는 않습니다.
반대로, 대상 오리진에 포트가 붙는다면 패턴도 포트를 포함해야 합니다
(`regex:https://app\.example\.com(:8443)?`). 정확히 일치하는 항목은 대소문자를 구분하지
않고 비교합니다.

`--allowed-origins '*'`는 모든 오리진을 허용한다는 뜻이며, `--jsonp`와 마찬가지로
크로스사이트 게이트를 꺼 버립니다. 둘 중 하나라도 API 키 없이 켜면 서버가 기동 시
경고합니다.

### JSONP

커스텀 헤더를 설정할 수 없는 브라우저 클라이언트를 위해:

```bash
dalfox server --jsonp --callback-param-name callback
# 그다음 GET /scan?target=...&callback=myFunction
```

JSONP는 `<script src>` 로드로 전달되는데, 스크립트 로드에는 검증할 `Origin`이 없습니다.
따라서 이 플래그를 켜면 위에서 설명한 크로스사이트 게이트가 함께 꺼지고, 임의의 사이트가
이 API로 스캔을 실행하고 결과를 읽을 수 있게 됩니다. `--api-key`와 함께 쓰거나, 게이트가
유지되는 CORS(`--allowed-origins`)를 우선 고려하세요. API 키 없이 `--jsonp`을 켜면 서버가
시작 시 경고를 출력합니다.

`--jsonp`를 켜면 모든 엔드포인트가 콜백 파라미터를 따릅니다. 본문은 `name(json);`
형태로 감싸져 `application/javascript`로 나갑니다. 콜백 이름은 `[A-Za-z0-9_$.]`로 된
1~64자여야 하며 영문자, `_`, `$` 중 하나로 시작해야 합니다. 그 밖의 값은 무시되고
일반 JSON이 돌아옵니다.

## 엔드포인트

| 메서드 | 경로 | 기능 |
|--------|------|--------------|
| `POST` | `/scan` | 새 스캔 제출 (JSON 본문) |
| `GET` | `/scan?target=...` | 새 스캔 제출 (쿼리 문자열) |
| `GET` | `/scan/{id}` | 스캔 상태 및 결과 조회 |
| `DELETE` | `/scan/{id}` | 큐에 있거나 실행 중인 스캔 취소 |
| `GET` | `/scans` | 모든 스캔 목록 조회 (선택적 `?status=`) |
| `GET` | `/result/{id}` | `/scan/{id}`의 별칭 |
| `POST` | `/preflight` | 페이로드를 보내지 않고 파라미터 탐색 |
| `GET` | `/health` | 서버 정보 + 기능 목록 |

이 엔드포인트들의 응답은 성공이든 실패든 모두 같은 `{code, msg, data}` 구조이며
`application/json`으로 나갑니다. 오류일 때 `code`는 HTTP 상태 코드와 같고, `msg`가
무엇이 잘못됐는지 알려 주며, `data`는 없습니다. 볼 수 있는 상태 코드는 `400`(잘못된
본문이나 옵션. `--max-body-bytes`를 넘는 본문도 여기에 해당), `401`(API 키 없음 또는
불일치), `403`(크로스사이트 요청 또는 신뢰하지 않는 `Host`,
[브라우저 요청](#브라우저-요청) 참고), `404`(알 수 없는 스캔 id), `409`(아직 활성
상태인 스캔의 purge), `500`(서버 내부에서 실패한 preflight), `503`(용량 초과)입니다.
예외는 두 가지입니다. CORS 사전 요청(`OPTIONS`)은 본문 없이 `204`로 답하고(브라우저 게이트가
거부하면 본문 없는 `403`), 표에 없는 경로나 메서드는 본문 없는 `404` / `405`를 받습니다.

### 스캔 제출

```bash
curl -X POST http://127.0.0.1:6664/scan \
  -H "X-API-KEY: 8f2b1c6d4a9e7053b8c1f4d2e6a09b73" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "https://target.app?q=test",
    "options": {
      "worker": 50,
      "timeout": 10,
      "encoders": ["url", "html"],
      "blind": "https://callback.interact.sh"
    }
  }'
```

스캔 대상 필드는 `target`입니다 (MCP `scan_with_dalfox` 도구 및 응답 페이로드와 동일). 레거시 필드명 `url`도 별칭으로 계속 받습니다. JSON 본문과 `?target=` / `?url=` 쿼리 문자열 모두에서 통하므로 기존 클라이언트는 그대로 동작합니다.

옵션은 `options` 아래에 둡니다. 최상위든 `options` 안이든 알 수 없는 키는 무시되지 않고
`400`으로 거부됩니다. 그래서 `{"target": ..., "worker": 5}` 같은 평평한 본문은 모든
옵션이 빠진 채 스캔되는 대신 곧바로 실패합니다.

응답:

```json
{
  "code": 200,
  "msg": "ok",
  "data": {
    "scan_id": "9f2c…",
    "target": "https://target.app?q=test"
  }
}
```

### 상태 폴링

```bash
curl -H "X-API-KEY: 8f2b1c6d4a9e7053b8c1f4d2e6a09b73" http://127.0.0.1:6664/scan/9f2c…
```

응답 (실행 중):

```json
{
  "code": 200,
  "msg": "ok",
  "data": {
    "target": "https://target.app?q=test",
    "status": "running",
    "progress": {
      "params_total": 12,
      "params_tested": 5,
      "requests_sent": 234,
      "requests_failed": 0,
      "findings_so_far": 1,
      "estimated_completion_pct": 41,
      "suggested_poll_interval_ms": 2000
    },
    "queued_at_ms": 1758700000000,
    "started_at_ms": 1758700000120,
    "finished_at_ms": null,
    "duration_ms": 8450
  }
}
```

- `results`는 스캔의 워커가 끝난 뒤에 나타납니다. `done` 스캔의 탐지 결과이거나,
  `error` / `cancelled` 스캔의 부분 탐지 결과입니다. 대상에 끝내 닿지 못했거나 시작
  전에 취소된 스캔에는 `results` 자체가 없습니다. 실행 중에 취소한 스캔은 곧바로
  `cancelled`로 보고되지만, `results`는 워커가 정리를 마친 뒤(몇 초 걸릴 수 있음)에야
  붙습니다.
- 스캔이 실패했거나 `scan_timeout`을 다 썼다면 `error_message`가 붙습니다.
- 스캔이 아직 `queued`이면 `progress`는 없습니다.
- `requests_failed`는 대상에 닿지 못한 요청(연결, TLS, 타임아웃) 수입니다. 이 값이
  `requests_sent`의 큰 비중을 차지한다면 스캔이 사실상 돌지 않은 것이므로, 탐지 결과
  0건을 "깨끗함"이 아니라 "스캔되지 않음"으로 읽으세요.
- `suggested_poll_interval_ms`는 10%를 넘으면 `3000`에서 `2000`으로, 80%를 넘으면
  `1000`으로 줄고, 스캔이 종료되면 `0`이 됩니다.

### 스캔 목록 조회

```bash
curl -H "X-API-KEY: 8f2b1c6d4a9e7053b8c1f4d2e6a09b73" 'http://127.0.0.1:6664/scans?status=running'
```

`status`는 `queued`, `running`, `done`, `error`, `cancelled` 중 하나입니다(그 밖의 값은
`400`). `offset`과 `limit`으로 목록을 페이지 단위로 넘깁니다(`limit=0`이 기본값이며
`offset`부터 전부 반환). 스캔은 최신순으로 옵니다:

```json
{
  "code": 200,
  "msg": "ok",
  "data": {
    "total": 1,
    "scans": [
      {
        "scan_id": "9f2c…",
        "target": "https://target.app?q=test",
        "status": "running",
        "result_count": 0,
        "queued_at_ms": 1758700000000,
        "started_at_ms": 1758700000120,
        "finished_at_ms": null,
        "duration_ms": 8450
      }
    ],
    "pagination": { "offset": 0, "limit": 0, "returned": 1, "has_more": false }
  }
}
```

실패한 스캔의 행에는 `error_message`도 담기므로, `result_count: 0`인 깨끗한 스캔과
헷갈리지 않습니다.

### 스캔 취소

```bash
curl -X DELETE -H "X-API-KEY: 8f2b1c6d4a9e7053b8c1f4d2e6a09b73" http://127.0.0.1:6664/scan/9f2c…
```

응답 데이터는 `{scan_id, target, cancelled, previous_status}`입니다. `cancelled`는
스캔이 `queued`나 `running`이었을 때만 `true`입니다. 이미 끝난 스캔이라면 이 호출은
아무 일도 하지 않고 `cancelled`는 `false`입니다. 취소된 스캔은 그때까지 모은 부분 결과를
가진 채 목록에 남습니다.

종료된 레코드를 제거하려면 `?purge=1`을 붙이세요. 이때 데이터는
`{scan_id, target, deleted: true, previous_status}`이고, 아직 `queued`나 `running`인
스캔은 `409`로 거부됩니다. 이는 명시적인 강제 삭제
경로입니다. MCP의 안전한 삭제와 달리 취소된 워커가 아직 정리 중이면 부분
결과나 종료 webhook을 버릴 수 있습니다.

### 프리플라이트 (공격 없음)

```bash
curl -X POST http://127.0.0.1:6664/preflight \
  -H "X-API-KEY: 8f2b1c6d4a9e7053b8c1f4d2e6a09b73" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://target.app"}'
```

응답에는 `params_discovered`, `estimated_total_requests`와 파라미터 목록이 담겨 있어, 실제 스캔에 들어가기 전에 범위를 정할 수 있습니다.

본문은 `POST /scan`과 같은 `{target, options}` 구조입니다. 데이터는
`{target, reachable, method, params_discovered, estimated_total_requests,
params: [{name, location, estimated_requests}]}` 형태로 돌아옵니다. 도달할 수 없는
대상은 `reachable: false`와 `error_code: "CONNECTION_FAILED"`를 돌려주며 파라미터는
비어 있습니다. 프리플라이트도 네트워크상으로는 조용하지 않습니다. 탐색과 마이닝이 실제
요청을 보내며, 요청의 `delay`, `worker`, `rate_limit`에 따라 속도가 조절되고 서버의
`--rate-limit`이 상한을 둡니다. 프리플라이트는 동시에 최대 32개까지 실행되며, 넘치면
서버가 `503`으로 응답합니다.

### 헬스

```bash
curl http://127.0.0.1:6664/health
```

`status: "ok"`, 버전, `auth_required`, 지원되는 엔드포인트 목록을 반환합니다. 가동 상태 확인에 유용합니다. API 키는 필요 없지만 [브라우저 요청](#브라우저-요청)의 브라우저 게이트는 그대로 적용됩니다.

## ScanOptions 참조 (요청 본문)

```jsonc
{
  "target": "https://target.app",
  "options": {
    "worker": 50,
    "delay": 0,
    "timeout": 10,
    "rate_limit": 0,
    "scan_timeout": 0,
    "blind": "https://callback.interact.sh",
    "method": "POST",
    "data": "user=test",
    "header": ["Authorization: Bearer token"],
    "cookie": "session=abc123; lang=en",
    "user_agent": "Custom",
    "encoders": ["url", "html"],
    "remote_payloads": ["portswigger"],
    "remote_wordlists": ["burp"],
    "include_request": false,
    "include_response": false,
    "callback_url": "https://your-webhook.example/dalfox",
    "param": ["q", "id:query"],
    "proxy": "http://127.0.0.1:8080",
    "insecure": true,
    "follow_redirects": false,
    "skip_mining": false,
    "skip_discovery": false,
    "deep_scan": false,
    "skip_ast_analysis": false,
    "analyze_external_js": false,
    "detect_outdated_libs": false,
    "waf_bypass": "auto",
    "skip_waf_probe": false,
    "force_waf": "cloudflare",
    "waf_evasion": false,
    "waf_min_confidence": 0.3,
    "max_payloads_per_param": 0
  }
}
```

필드는 CLI 플래그와 대응됩니다. 의미와 기본값은 [CLI 참조](../../reference/cli/)를 보세요.
`cookie`는 `Cookie:` 헤더 값 하나입니다. `name=value` 문자열의 리스트도 받으며 `; `로
이어 붙입니다. [MCP](../mcp/) 쪽 철자도 별칭으로 받으므로 `scan_with_dalfox`용으로 쓴
인자도 그대로 통합니다: `cookie`에 `cookies`, `header`에 `headers`, `worker`에
`workers`, `blind`에 `blind_callback_url`입니다.

숫자 옵션은 범위를 검사하며, 범위를 벗어나면 `400`입니다: `timeout` `1`~`299`초,
`delay` `0`~`9999`ms, `worker` `1`~`500`, `scan_timeout` `0`~`86400`초,
`max_payloads_per_param` `0`~`100000`.

`detect_outdated_libs`는 옵트인 방식입니다 (기본값 `false`). `true`로 설정하면
오래되었거나 알려진 취약점이 있는 JS 라이브러리도 정보성 `[I]` 탐지 결과로
보고합니다 (CWE-1104, 추가 요청 0건). 같은 키를 `GET /scan` 쿼리 파라미터로도 사용할 수 있습니다.
`insecure`는 기본값이 `true`입니다 (CLI 스캐너 기본값과 동일하게 TLS 인증서 검증을
건너뜁니다). 인증서 검증을 강제하려면 `"insecure": false` (또는 `GET /scan`에서
`?insecure=false`)를 보내세요.

`proxy`와 `callback_url`은 제출 시점에 검증하며, 사용할 수 없는 값이면 `400`입니다.
`callback_url`은 `http://`나 `https://`여야 합니다(비어 있으면 웹훅 없음).

`analyze_external_js`는 옵트인 방식입니다 (기본값 `false`). `true`로 설정하면
프리플라이트 시점에 동일 출처의 `<script src>` 번들을 가져와 DOM XSS를 위한 AST
분석을 수행합니다. 싱크(sink) 로직이 전부 외부 번들에 들어 있는 SPA에 유용합니다.
추가 요청 비용이 들기 때문에 기본적으로 꺼져 있습니다.

`rate_limit`은 스캔의 초당 아웃바운드 요청 수를 제한합니다 (`0` = 무제한, 기본값).
모든 워커 태스크에 걸쳐 적용됩니다. 서버 전역 `--rate-limit` 플래그는 상한선입니다.
요청은 더 낮은 속도를 지정할 수는 있으나 이를 초과하거나 비활성화할 수는 없습니다.

`max_payloads_per_param`은 발견된 각 파라미터를 테스트할 페이로드 수의 상한입니다
(기본값 `0` = 명시적 상한 없음. 내장 페이로드 안전 상한은 그대로 적용됩니다).
스모크 스캔에는 작은 값(예: `10`~`50`)을 쓰세요. MCP 스캔 도구의 동명 필드와
대응됩니다.

WAF 관련 다섯 개 필드는 CLI의 WAF 플래그와 대응되며 모두 선택 사항입니다. 생략하면
스캐너 기본값이 적용됩니다. `waf_bypass`는 처리 모드를 고릅니다: `"auto"`(탐지 후
우회, 기본값) 또는 `"off"`(탐지하고 보고만 함). `"force"`도 받지만 `"auto"`와 똑같이
동작합니다. `skip_waf_probe`는(기본값 `false`) 자극 프로브만 건너뛰며, 프리플라이트
응답에 대한 패시브 탐지는 그대로 실행됩니다. `force_waf`는 탐지 결과 대신 특정
프로필(예: `"cloudflare"`)을 고정합니다. `"auto"`와 `"force"` 모두에서 적용되며,
`"off"`에서는 보고만 되고 우회는 적용되지 않습니다. `waf_evasion`은
(기본값 `false`) 적응형 우회를 켭니다. `waf_min_confidence`는 `[0.0, 1.0]` 범위의
탐지 신뢰도 하한입니다 (기본값 `0.3`). 이 값보다 낮은 핑거프린트는 버려집니다.

`method`, `encoders`, `remote_payloads`, `remote_wordlists`는 CLI가 허용하는 것과
같은 값으로 검사하며, 모르는 메서드·인코더·프로바이더 이름은 `400`입니다. `method`는
자동으로 대문자로 바뀝니다(`"post"` → `"POST"`).

`blind`는 비어 있거나(= 블라인드 XSS 사용 안 함) 절대 `http://` / `https://` URL이어야
하며, 그 밖의 값은 `400`입니다. 이 값을 설정하면 *저장형* 블라인드 XSS 주입이 켜집니다.
`<script src=...>` 페이로드가 모든 쿼리·바디·헤더·쿠키 파라미터에 기록되어 대상에
그대로 남습니다.

`scan_timeout`은 스캔 전체의 벽시계 시간 예산(초)입니다 (기본값 `0` = 무제한).
요청당 `timeout`과는 구별됩니다. 예산에 도달하면 스캔이 중단되고, 그때까지 수집한
부분 탐지 결과를 유지하며, `scan_timeout`을 언급하는 `error_message`와 함께
`cancelled` 상태로 끝납니다 (그래서 타임아웃인지 클라이언트가 건 취소인지 구별할 수
있습니다). 서버 전역 `--scan-timeout` 플래그는 `--rate-limit`과 마찬가지로 제출된 모든
스캔에 동일하게 상한을 적용합니다.

### GET /scan 쿼리 파라미터

`GET /scan`은 같은 옵션 이름을 쿼리 파라미터로 받습니다. `target` 대신 `url`도
받지만, MCP 별칭(`workers`, `headers`, `cookies`, `blind_callback_url`)은 읽지
않습니다. JSON 본문과 달리 모르는 쿼리 파라미터는 거부하지 않고 무시하므로 철자를
확인하세요. 리스트 옵션(`encoders`,
`param`, `remote_payloads`, `remote_wordlists`)은 쉼표로 구분합니다. `header`는 여러
헤더를 한 값에 담으며, 새 `Name:`이 시작되는 쉼표에서만 나눕니다. 그래서
`Accept: text/html,application/xhtml+xml`처럼 값 안에 든 쉼표는 그대로 남습니다.
불리언은 `1`, `true`, `yes`, `on`(대소문자 무관)을 참으로, 그 밖의 값은 거짓으로
읽습니다. 값은 있는데 숫자로 해석할 수 없으면 `400`입니다. `method`의 기본값은 `GET`,
`encoders`의 기본값은 `url,html`입니다.

### 완료 웹훅

`callback_url`을 설정하면, 스캔이 어떻게 끝나든(시작 전에 취소된 경우 포함) 서버가
JSON 본문 하나를 POST 합니다. 실행 중에 취소한 스캔은 `DELETE` 시점이 아니라 워커가
정리를 마친 뒤에 POST가 나갑니다:

```json
{ "scan_id": "9f2c…", "status": "done", "url": "https://target.app?q=test", "results": [] }
```

`status`는 `done`, `error`, `cancelled` 중 하나로, `GET /scan/{id}`가 보고하는 값과
같습니다. 여기서는 대상이 `target`이 아니라 `url` 아래에 있습니다. 이 POST는 스캔 자신의
프록시·TLS 설정을 따르며, 10초 뒤 타임아웃되고, 재시도하지 않습니다.

### 설정해 둘 만한 서버 플래그

- `--rate-limit <rps>` — 모든 스캔의 아웃바운드 요청 속도를 제한합니다 (대상을 보호).
- `--scan-timeout <secs>` — 스캔당 강제 벽시계 시간 예산. 길거나 `deep_scan`인
  작업을 제한하여 하나의 대상이 워커를 무한정 점유하지 못하게 합니다.
- `--max-concurrent-scans <n>` — `n`개의 스캔이 큐에 있거나 실행 중이면 새 제출을
  `503`으로 거부합니다 (기본값 `100`, `0` = 무제한). 제출 폭주에 대비해 메모리와
  블로킹 풀을 제한합니다. 취소한 스캔은 워커가 실제로 멈출 때까지(최대 5분) 자리를
  계속 차지하므로, 취소한다고 곧바로 여유가 생기지는 않습니다.
- `--max-body-bytes <n>` — `POST /scan` 및 `/preflight`의 명시적 요청 본문 상한
  (기본값 `1048576` = 1 MiB). 크기를 초과하는 본문은 `400`
  (`invalid request body: ... length limit exceeded`)으로 거부됩니다.
- `--max-retained-scans <n>` — 메모리에 보관하는 *종료된* 스캔 수 상한 (기본값 `1000`,
  `0` = 무제한). `--max-concurrent-scans`는 활성 스캔만 세기 때문에, 이 상한이 없으면
  짧은 스캔이 몰릴 때 모든 결과가(`include_response`를 켰다면 응답 본문까지) 1시간
  보존 TTL이 만료될 때까지 유지됩니다. 상한에 도달하면 가장 오래된 종료 스캔부터
  제거되며, 큐에 있거나 실행 중인 스캔은 절대 제거되지 않습니다.
- `--allowed-hosts <names>` — 요청 `Host` 헤더에서 추가로 허용할 호스트명. 바인딩
  호스트, `localhost`, 모든 IP 리터럴은 기본으로 허용됩니다. 리버스 프록시가 공개
  호스트명을 전달할 때 필요합니다. [브라우저 요청](#브라우저-요청) 참고.

## 작업(job) 수명 주기

```
queued → running → done
                 ↘ error
                 ↘ cancelled
queued → cancelled
```

종료 상태(`done`, `error`, `cancelled`)는 고정되어 변하지 않습니다. 대기 중인 스캔은
시작 전에 취소될 수 있습니다. 작업은 메모리에만 존재합니다. 종료된 스캔은 1시간 동안(또는
`--max-retained-scans`가 밀어낼 때까지) 보관되며, 재시작하면 아무것도 남지 않습니다.

스캔 하나가 테스트하는 파라미터는 최대 512개입니다. 그보다 많은 파라미터를 드러내는
대상에서는 발견한 목록이 잘리고 스캔은 그대로 `done`으로 끝나며, 흔적은 서버 로그의
`discovered params capped to 512` 경고 한 줄뿐입니다. 모든 파라미터가 중요하다면
`param`으로 나눠서 스캔하세요.

연결할 수 없는 대상(DNS 실패, 연결 거부, TLS 오류, 타임아웃)은
`target unreachable: connection failed (CONNECTION_FAILED)`라는 `error_message`와
함께 `error`로 종료됩니다 — 탐지 결과가 0건인 `done`이 아니므로 "스캔했으나 아무것도
찾지 못함"과 "호스트에 도달하지 못함"을 구별할 수 있습니다. 스캔을 실행하지 않고
도달 가능성만 확인하려면 먼저 `POST /preflight`를 쓰세요. `target`은 `http://`나
`https://`로 시작해야 하며, 그 외 스킴은 `400`으로 거부됩니다 (`/preflight`와 동일).

**끊어진 세션**도 같은 규칙을 따릅니다. 스캔 요청이 자격증명(`cookie`, 또는 `header`의
`Cookie` / `Authorization` 항목)을 담고 있으면, Dalfox는 스캔 전에 인증된 응답의 지문을
잡아 두고 스캔이 끝날 때 다시 확인합니다. 그 사이에 세션이 만료됐다면 (이후 모든 요청이
로그인 페이지를 받고 아무것도 반사되지 않는 상태) 탐지 결과 0건의 `done`이 아니라
`SESSION_LOST:`로 시작하는 `error_message`와 함께 `error`로 종료됩니다. 부분 탐지
결과는 그대로 유지됩니다. 자격증명이 없는 스캔에서는 모니터링이 꺼져 있으며 비용도
들지 않습니다.

## systemd에서 실행하기

```ini
# /etc/systemd/system/dalfox.service
[Unit]
Description=Dalfox scanner service
After=network.target

[Service]
ExecStart=/usr/local/bin/dalfox server --port 6664 --host 127.0.0.1 --log-file /var/log/dalfox.log
Environment=DALFOX_API_KEY=8f2b1c6d4a9e7053b8c1f4d2e6a09b73
Restart=on-failure
User=dalfox

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now dalfox
```

## 보안 참고 사항

- **로컬호스트에 바인딩하세요.** 원격 접근이 꼭 필요할 때만 예외입니다. 다만 이것은
  *네트워크*를 막는 조치일 뿐 보안 경계가 아닙니다. 사용자가 방문한 웹페이지는 본인의
  브라우저를 통해 루프백 API에 도달할 수 있으며, 이를 막는 것이
  [브라우저 요청](#브라우저-요청)의 크로스사이트·`Host` 게이트입니다.
- **원격 바인딩에는 항상 `--api-key`를 설정하세요.**
- **API 키를 로그에 남기지 마세요.** Dalfox는 키를 기록하지 않지만, 리버스 프록시는 기록할 수 있습니다.
- **네트워크로 노출한다면 TLS 뒤에 두세요** (nginx, Caddy, Traefik).
- **`callback_url`과 스캔 대상은 서버 측 요청입니다.** Dalfox는 URL 스캐너입니다.
  제출한 대상이 무엇이든 접속하며, 완료 시 결과 JSON을 `callback_url`로 POST 합니다.
  `http(s)` 스킴만 접속하지만 *호스트*는 필터링되지 않습니다 — 루프백, 링크 로컬
  (예: `169.254.169.254`의 클라우드 메타데이터), 사설 주소가 모두 도달 가능합니다.
  인증 없는 바인딩에서는 스캔을 제출할 수 있는 누구에게나 이것이 서버 측 요청 위조 +
  데이터 유출 프리미티브가 되므로, 신뢰할 수 없는 호출자에게 API를 노출할 때는
  `--api-key`를 설정하고 아웃바운드 트래픽을 제한하세요.
- **`--jsonp`는 `GET` 엔드포인트를 `<script>`로 교차 출처에서 읽을 수 있게 만들며**,
  이는 CORS 허용 목록의 적용을 받지 않습니다. 또한 스크립트 로드에는 검증할 `Origin`이
  없으므로 크로스사이트 게이트도 함께 꺼집니다. 의도한 경우에만 켜고,
  `--api-key`와 함께 쓰세요.
- **`--scan-timeout`으로 스캔 실행 시간을 제한하세요.** 요청당 `timeout`은 단일 HTTP
  요청만 제한합니다. 파라미터와 페이로드가 많은 스캔(또는 `deep_scan`)은 여전히 오랫동안
  실행될 수 있습니다. `--scan-timeout <secs>`를 설정하여 제출된 모든 스캔에 강제 벽시계
  시간 예산을 두면, 느린 대상 하나가 워커를 무한정 묶어 둘 수 없게 됩니다.
