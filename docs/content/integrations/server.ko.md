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
# listens on http://127.0.0.1:6664 by default
```

자주 쓰는 옵션:

```bash
dalfox server \
  --port 6664 \
  --host 0.0.0.0 \
  --api-key "change-me" \
  --log-file /var/log/dalfox.log
```

### 인증

`--api-key`가 설정되어 있거나 (`DALFOX_API_KEY`가 export 되어 있으면) 모든 요청은 다음을 포함해야 합니다:

```
X-API-KEY: change-me
```

API 키를 설정하지 않으면 서버는 인증되지 않은 요청을 수락합니다. 그런 경우에는 `127.0.0.1`에 바인딩하십시오.

### CORS

```bash
dalfox server \
  --allowed-origins "https://app.example.com,https://admin.example.com" \
  --cors-allow-methods "GET,POST,OPTIONS,DELETE" \
  --cors-allow-headers "Content-Type,X-API-KEY,Authorization"
```

`*`는 와일드카드로 허용됩니다. 정규식은 `regex:^https://.*\.example\.com$` 형태로 지원됩니다.

### JSONP

커스텀 헤더를 설정할 수 없는 브라우저 클라이언트를 위해:

```bash
dalfox server --jsonp --callback-param-name callback
# then GET /scan?target=...&callback=myFunction
```

## 엔드포인트

| 메서드 | 경로 | 기능 |
|--------|------|--------------|
| `POST` | `/scan` | 새 스캔 제출 (JSON 본문) |
| `GET` | `/scan?target=...` | 새 스캔 제출 (쿼리 문자열) |
| `GET` | `/scan/:id` | 스캔 상태 및 결과 조회 |
| `DELETE` | `/scan/:id` | 큐에 있거나 실행 중인 스캔 취소 |
| `GET` | `/scans` | 모든 스캔 목록 조회 (선택적 `?status=`) |
| `GET` | `/result/:id` | `/scan/:id`의 별칭 |
| `POST` | `/preflight` | 페이로드를 보내지 않고 파라미터 탐색 |
| `GET` | `/health` | 서버 정보 + 기능 목록 |

### 스캔 제출

```bash
curl -X POST http://127.0.0.1:6664/scan \
  -H "X-API-KEY: change-me" \
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

스캔 대상 필드는 `target`입니다 (MCP `scan_with_dalfox` 도구 및 응답 페이로드와 동일). 레거시 필드명 `url`도 여전히 별칭으로 수락되며 — JSON 본문과 `?target=` / `?url=` 쿼리 문자열 모두에서 — 기존 클라이언트가 계속 동작합니다.

응답:

```json
{
  "code": 200,
  "msg": "queued",
  "data": {
    "scan_id": "9f2c…",
    "target": "https://target.app?q=test"
  }
}
```

### 상태 폴링

```bash
curl -H "X-API-KEY: change-me" http://127.0.0.1:6664/scan/9f2c…
```

응답 (실행 중):

```json
{
  "code": 200,
  "msg": "running",
  "data": {
    "target": "https://target.app?q=test",
    "status": "running",
    "results": [],
    "progress": {
      "params_total": 12,
      "params_tested": 5,
      "requests_sent": 234,
      "findings_so_far": 1,
      "estimated_completion_pct": 41,
      "suggested_poll_interval_ms": 3000
    }
  }
}
```

완료되면 `status`는 `done`이 되고 `results`가 채워집니다.

### 스캔 목록 조회

```bash
curl -H "X-API-KEY: change-me" 'http://127.0.0.1:6664/scans?status=running'
```

### 스캔 취소

```bash
curl -X DELETE -H "X-API-KEY: change-me" http://127.0.0.1:6664/scan/9f2c…
```

### 프리플라이트 (공격 없음)

```bash
curl -X POST http://127.0.0.1:6664/preflight \
  -H "X-API-KEY: change-me" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://target.app"}'
```

응답에는 `params_discovered`, `estimated_total_requests`, 그리고 파라미터 목록이 포함되어 있어 실제 스캔에 착수하기 전에 범위를 정할 수 있습니다.

### 헬스

```bash
curl http://127.0.0.1:6664/health
```

버전, `auth_required`, 지원되는 엔드포인트 목록을 반환합니다. 가동 상태 확인에 유용합니다.

## ScanOptions 참조 (요청 본문)

```jsonc
{
  "url": "https://target.app",
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
    "detect_outdated_libs": false
  }
}
```

필드는 CLI 플래그와 대응됩니다. 의미와 기본값은 [CLI 참조](../../reference/cli/)를 확인하십시오.
`detect_outdated_libs`는 옵트인 방식입니다 (기본값 `false`). `true`로 설정하면
오래되었거나 알려진 취약점이 있는 JS 라이브러리도 정보성 `[I]` 탐지 결과로
보고합니다 (CWE-1104, 추가 요청 0건). 같은 키를 `GET /scan` 쿼리 파라미터로도 사용할 수 있습니다.
`insecure`는 기본값이 `true`입니다 (CLI 스캐너 기본값과 동일하게 TLS 인증서 검증을
건너뜁니다). 인증서 검증을 강제하려면 `"insecure": false` (또는 `GET /scan`에서
`?insecure=false`)를 보내십시오.

`rate_limit`은 스캔의 초당 아웃바운드 요청 수를 제한합니다 (`0` = 무제한, 기본값).
모든 워커 태스크에 걸쳐 적용됩니다. 서버 전역 `--rate-limit` 플래그는 상한선입니다.
요청은 더 낮은 속도를 지정할 수는 있으나 이를 초과하거나 비활성화할 수는 없습니다.

`scan_timeout`은 스캔 전체의 벽시계 시간 예산(초)입니다 (기본값 `0` = 무제한).
요청당 `timeout`과는 구별됩니다. 예산에 도달하면 스캔이 중단되고, 그때까지 수집한
부분 탐지 결과를 유지하며, `scan_timeout`을 언급하는 `error_message`와 함께
`cancelled` 상태로 정착합니다 (따라서 타임아웃과 클라이언트가 발행한 취소를 구별할 수
있습니다). 서버 전역 `--scan-timeout` 플래그는 `--rate-limit`과 마찬가지로 제출된 모든
스캔에 동일하게 상한을 적용합니다.

### 설정해 둘 만한 서버 플래그

- `--rate-limit <rps>` — 모든 스캔의 아웃바운드 요청 속도를 제한합니다 (대상을 보호).
- `--scan-timeout <secs>` — 스캔당 강제 벽시계 시간 예산. 길거나 `deep_scan`인
  작업을 제한하여 하나의 대상이 워커를 무한정 점유하지 못하게 합니다.
- `--max-concurrent-scans <n>` — `n`개의 스캔이 큐에 있거나 실행 중이면 새 제출을
  `503`으로 거부합니다 (기본값 `100`, `0` = 무제한). 제출 폭주에 대비해 메모리와
  블로킹 풀을 제한합니다.
- `--max-body-bytes <n>` — `POST /scan` 및 `/preflight`의 명시적 요청 본문 상한
  (기본값 `1048576` = 1 MiB). 크기를 초과하는 본문은 `413`을 받습니다.

## 작업(job) 수명 주기

```
queued → running → done
                 ↘ error
                 ↘ cancelled
```

종료 상태(`done`, `error`, `cancelled`)는 고정되어 변하지 않습니다.

연결할 수 없는 대상(DNS 실패, 연결 거부, TLS 오류, 타임아웃)은
`target unreachable: connection failed (CONNECTION_FAILED)`라는 `error_message`와
함께 `error`로 종료됩니다 — 탐지 결과가 0건인 `done`이 아니므로 "스캔했으나 아무것도
찾지 못함"과 "호스트에 도달하지 못함"을 구별할 수 있습니다. 스캔을 실행하지 않고
도달 가능성만 확인하려면 먼저 `POST /preflight`를 사용하십시오. `url`은 `http://` 또는
`https://`로 시작해야 하며, 그 외 스킴은 `400`으로 거부됩니다 (`/preflight`와 동일).

## systemd에서 실행하기

```ini
# /etc/systemd/system/dalfox.service
[Unit]
Description=Dalfox scanner service
After=network.target

[Service]
ExecStart=/usr/local/bin/dalfox server --port 6664 --host 127.0.0.1 --log-file /var/log/dalfox.log
Environment=DALFOX_API_KEY=change-me
Restart=on-failure
User=dalfox

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now dalfox
```

## 보안 참고 사항

- **로컬호스트에 바인딩하십시오.** 원격 접근이 반드시 필요한 경우가 아니라면 그렇게 하십시오.
- **원격 바인딩에는 항상 `--api-key`를 설정하십시오.**
- **API 키를 로그에 남기지 마십시오.** Dalfox는 키를 기록하지 않지만, 리버스 프록시는 기록할 수 있습니다.
- **네트워크로 노출한다면 TLS 뒤에 두십시오** (nginx, Caddy, Traefik).
- **`callback_url`과 스캔 대상은 서버 측 요청입니다.** Dalfox는 URL 스캐너입니다.
  제출한 대상이 무엇이든 접속하며, 완료 시 결과 JSON을 `callback_url`로 POST 합니다.
  `http(s)` 스킴만 접속하지만 *호스트*는 필터링되지 않습니다 — 루프백, 링크 로컬
  (예: `169.254.169.254`의 클라우드 메타데이터), 사설 주소가 모두 도달 가능합니다.
  인증되지 않은 바인딩에서는 스캔을 제출할 수 있는 누구에게나 이것이 서버 측 요청 위조 +
  데이터 유출 프리미티브가 되므로, 신뢰할 수 없는 호출자에게 API를 노출할 때는
  `--api-key`를 설정하고 아웃바운드 트래픽을 제한하십시오.
- **`--jsonp`는 `GET` 엔드포인트를 `<script>`를 통해 교차 출처로 읽을 수 있게 만들며**,
  이는 CORS 허용 목록의 적용을 받지 않습니다. 의도한 경우에만 활성화하고,
  `--api-key`와 함께 사용하십시오.
- **`--scan-timeout`으로 스캔 실행 시간을 제한하십시오.** 요청당 `timeout`은 단일 HTTP
  요청만 제한합니다. 파라미터와 페이로드가 많은 스캔(또는 `deep_scan`)은 여전히 오랫동안
  실행될 수 있습니다. `--scan-timeout <secs>`를 설정하여 제출된 모든 스캔에 강제 벽시계
  시간 예산을 두면, 느린 대상 하나가 워커를 무한정 묶어 둘 수 없게 됩니다.
