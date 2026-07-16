+++
title = "MCP 서버"
description = "Dalfox를 Claude 및 기타 MCP 클라이언트에 스캐너 도구(tool) 모음으로 노출합니다."
weight = 2
toc = true
+++

**Model Context Protocol**(MCP)은 AI 클라이언트가 외부 도구(tool)와 통신할 수 있게 해주는 개방형 표준입니다. `dalfox mcp`는 stdio 기반 MCP 서버를 실행하여 Claude Desktop, Claude Code, Cursor를 비롯한 모든 MCP 호환 클라이언트가 Dalfox 스캔을 직접 구동할 수 있게 합니다.

## 서버 시작하기

```bash
dalfox mcp
```

이 서버는 `stdin`/`stdout`을 통해 MCP로 통신합니다. 클라이언트에서 실행하세요. 터미널에서 직접 실행하지 않습니다.

## Claude Desktop 설정

Claude Desktop MCP 설정(`claude_desktop_config.json`)에 Dalfox를 추가합니다:

```json
{
  "mcpServers": {
    "dalfox": {
      "command": "dalfox",
      "args": ["mcp"]
    }
  }
}
```

Claude Desktop을 재시작합니다. Dalfox가 `dalfox`라는 이름의 도구 제공자(tool-provider)로 나타납니다.

## Claude Code(및 기타 CLI)

```bash
claude mcp add dalfox -- dalfox mcp
```

## 사용 가능한 도구(tool)

여섯 개의 도구(tool)가 노출됩니다. 모두 비동기이며 논블로킹입니다. 스캔을 제출하고, 결과를 폴링한 뒤, 다음 작업으로 넘어갑니다.

### `scan_with_dalfox`

스캔을 제출합니다. 즉시 반환합니다.

```json
{
  "target": "https://example.com/search?q=test",
  "method": "GET",
  "param": ["q"],
  "headers": ["Authorization: Bearer token"],
  "encoders": ["url", "html"],
  "timeout": 10,
  "scan_timeout": 0,
  "workers": 50,
  "rate_limit": 0,
  "insecure": true,
  "blind_callback_url": "https://callback.example",
  "deep_scan": false,
  "skip_ast_analysis": false,
  "analyze_external_js": false,
  "detect_outdated_libs": false
}
```

`encoders`는 구현된 페이로드 인코더의 어떤 조합이든 받습니다:
`url`, `html`, `htmlpad`, `2url`, `3url`, `4url`, `base64`, `unicode`,
`zwsp`. 위 예시는 `["url", "html"]`을 보여줍니다. 변형(mutation) 커버리지를
높이려면 더 추가하세요. 순서는 중요하지 않습니다 — 스캐너는 인코더를
고정된 우선순위 순서(`url` → `html` → `htmlpad` → `2url` → `3url`
→ `4url` → `base64` → `unicode` → `zwsp`)로 적용하고 출력을 중복
제거합니다. 인코딩을 완전히 비활성화하려면 `["none"]`을 사용하세요.
`--encoders` / `-e` CLI 플래그와 대응됩니다.

`insecure`는 TLS 인증서 검증을 제어합니다(기본값 `true`, 스캐너 친화적).
인증서 검증을 강제하고 자체 서명되었거나 만료된 인증서를 거부하려면 `false`로
설정하세요. `--insecure` CLI 플래그와 대응됩니다.

`analyze_external_js`는 옵트인 방식입니다(기본값 `false`). 프리플라이트
시점에 동일 출처의 `<script src>` 번들을 가져와 AST DOM-XSS 분석을
실행하려면 `true`로 설정하세요. 모든 싱크(sink) 로직이 외부 번들에 있고
페이지에 서버 측 반사가 없는 SPA에 유용합니다. 제한: 파일 16개,
파일당 512 KiB. `include_url`/`exclude_url` 필터를 따릅니다.

`detect_outdated_libs`는 옵트인 방식입니다(기본값 `false`). 오래되었거나
알려진 취약점이 있는 JS 라이브러리에 대해 정보성 `[I]` 탐지 결과도
내보내려면 `true`로 설정하세요(CWE-1104, 추가 요청 0건). 꺼두면 스캔은 XSS만
보고합니다.

`rate_limit`은 스캔의 아웃바운드 초당 요청 수를 제한합니다(`0` = 무제한,
기본값). 이제 모든 워커 태스크에 걸쳐 적용됩니다 — 취약한 대상을 부드럽게
다루거나 WAF 임계값 아래로 유지하는 데 사용하세요.

`scan_timeout`은 전체 스캔의 실제 경과 시간 예산으로 초 단위입니다(기본값 `0` =
무제한). 요청별 `timeout`과는 구별됩니다. 시간이 초과되면 스캔이 중단되고
부분 탐지 결과를 유지하며 `scan_timeout`을 언급하는 `error_message`와 함께
`cancelled` 상태로 정리됩니다. 길거나 `deep_scan` 실행에 한도를 두어
에이전트의 폴링 루프가 반드시 종료되도록 설정하세요.

응답:

```json
{ "scan_id": "9f2c…", "target": "https://example.com/search?q=test", "status": "queued" }
```

### `get_results_dalfox`

스캔을 폴링합니다. 준비되면 상태, 진행률, 결과를 반환합니다.

```json
{ "scan_id": "9f2c…" }
```

응답(진행 중):

```json
{
  "scan_id": "9f2c…",
  "target": "…",
  "status": "running",
  "progress": {
    "params_total": 10,
    "params_tested": 4,
    "requests_sent": 215,
    "findings_so_far": 1,
    "estimated_completion_pct": 40,
    "suggested_poll_interval_ms": 3000
  }
}
```

응답(완료):

```json
{
  "scan_id": "9f2c…",
  "status": "done",
  "results": [
    {
      "type": "V",
      "type_description": "Verified",
      "inject_type": "inHTML",
      "method": "GET",
      "param": "q",
      "payload": "<svg/onload=alert(1)>",
      "evidence": "payload reflected and DOM element verified",
      "cwe": "CWE-79",
      "severity": "High"
    }
  ]
}
```

`progress.estimated_completion_pct`와 `params_tested`는 발견된 각 파라미터가
완료될 때마다 실시간으로 증가합니다(더 이상 스캔이 끝날 때까지 0에 머무르지
않습니다). 따라서 폴링 간격을 조절하는 데 사용할 수 있습니다 —
`suggested_poll_interval_ms`를 따르세요.

대상에 도달할 수 없으면(DNS 실패, 연결 거부, TLS 오류, 타임아웃) 스캔은 빈
`results`와 함께 `done`으로 끝나는 대신 `CONNECTION_FAILED`를 포함하는
`error_message`와 함께 `status: "error"`로 끝납니다 — `preflight_dalfox`가
`reachable: false`로 보고하는 것과 동일한 구분입니다. `target`은
`http://` 또는 `https://`로 시작해야 합니다.

### `list_scans_dalfox`

추적 중인 모든 스캔을 나열합니다. 선택적 필터:

```json
{ "status": "running" }
```

`total`, `scans: [{scan_id, target, status, result_count}]`을 반환합니다.

### `cancel_scan_dalfox`

대기 중이거나 실행 중인 스캔을 중단합니다:

```json
{ "scan_id": "9f2c…" }
```

### `delete_scan_dalfox`

추적 중인 스캔을 메모리에서 영구적으로 제거합니다. 종료된 스캔(`done`, `error`, `cancelled`)만 삭제할 수 있습니다. 실행 중이거나 대기 중인 스캔은 먼저 취소해야 합니다. 종료된 스캔은 1시간 후 자동으로 정리되기도 합니다.

```json
{ "scan_id": "9f2c…" }
```

`{scan_id, deleted: true, previous_status}`를 반환합니다.

### `preflight_dalfox`

페이로드를 보내지 **않고** 대상을 분석합니다. 스캔을 확정하기 전에 범위를 정하는 데 유용합니다.

```json
{
  "target": "https://example.com",
  "method": "GET",
  "skip_discovery": false,
  "skip_mining": false
}
```

도달 가능 여부, 발견된 파라미터, 예상 요청 수를 반환합니다.

## 일반적인 에이전트 흐름

1. 에이전트가 `preflight_dalfox`를 호출하여 대상을 확인하고 파라미터 수를 셉니다.
2. 에이전트가 `scan_with_dalfox`를 호출하여 `scan_id`를 받습니다.
3. 에이전트가 진행률 객체의 `suggested_poll_interval_ms`를 사용하여 `get_results_dalfox`를 폴링합니다.
4. `status == "done"`이 되면 에이전트가 탐지 결과를 요약하여 사용자에게 다시 보고합니다.

모든 도구(tool)가 비동기이므로 에이전트는 응답성을 유지합니다. 오래 실행되는 도구(tool) 호출이 대화를 차단하지 않습니다.

## 권한 및 안전

MCP 서버는 CLI와 동일한 규칙을 적용합니다: **테스트 권한이 있는 대상만 스캔하세요.** 에이전트의 시스템 프롬프트에서 "모든 스캔 전에 범위를 확인하세요"와 같은 명시적 사용자 확인 단계 뒤에 Dalfox MCP 호출을 두는 것을 고려하세요.

## 문제 해결

- **도구(tool)가 표시되지 않나요?** MCP 클라이언트가 사용하는 PATH에 `dalfox` 바이너리가 있는지 확인하세요. macOS의 Claude Desktop에서는 대개 `/usr/local/bin` 또는 `/opt/homebrew/bin`입니다.
- **결과가 비어 있나요?** 다시 폴링하세요. 스캔은 비동기입니다. `suggested_poll_interval_ms`를 폴링 주기로 사용하세요.
- **로그를 보고 싶나요?** 설정하는 동안 `dalfox mcp --debug`를 실행하세요. 디버그 라인은 stderr로 가므로 MCP 채널을 오염시키지 않습니다.
