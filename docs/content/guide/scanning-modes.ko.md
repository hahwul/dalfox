+++
title = "스캔 모드"
description = "단일 URL, 파일 배치, 파이프라인, 저장형 XSS, 서버, MCP까지. 워크플로에 맞는 모드를 선택하세요."
weight = 1
toc = true
+++

Dalfox는 여러 형태의 대상을 받아들입니다. 모든 모드는 동일한 탐색, 페이로드, 검증 엔진을 공유하며, URL을 입력하는 방식과 결과가 어디로 가는지만 다릅니다.

내부적으로는 네 개의 서브커맨드가 있습니다: `scan`(스캐너), `server`(장시간 유지되는 REST API), `payload`(페이로드 유틸리티), `mcp`(Model Context Protocol stdio 서버). 아래에서 "URL / File / Pipe / Raw HTTP / HAR / SXSS"로 표시된 것은 모두 `scan` 서브커맨드가 `--input-type`을 통해 처리하는 *입력 형태*이며, 독립적인 서브커맨드가 아닙니다.

> 팬아웃 입력 형태(`file`, `pipe`, `raw-http`, `har`)는 `scan` 전용입니다. 각각 하나의 입력을 여러 대상으로 확장합니다. `server`와 `mcp` 인터페이스는 호출당 단일 대상을 다룹니다. 하나의 URL에 명시적인 메서드/헤더/쿠키/본문(HAR 항목 하나가 담는 것과 동일한 충실도)을 더해서 받으므로, 캡처한 세션을 재생하려면 요청마다 한 번씩 호출하면 됩니다.

## Auto (기본값)

Dalfox에 URL만 넘겨주세요. 나머지는 알아서 판단합니다.

```bash
dalfox https://target.app/search?q=test
```

내부적으로 Dalfox는 `--input-type auto`와 함께 `scan` 서브커맨드를 사용합니다. 인자가 URL인지, 파일 경로인지, `stdin`의 스트림인지 자동으로 감지합니다.

## URL 모드

URL 파싱을 강제합니다(거의 필요하지 않지만 스크립트에서 유용합니다):

```bash
dalfox scan --input-type url https://target.app
```

## File 모드

URL 목록을 한 줄에 하나씩 스캔합니다:

```bash
# urls.txt
# https://target.app/search?q=1
# https://target.app/profile?id=2
dalfox scan urls.txt
# or, explicit:
dalfox scan --input-type file urls.txt
```

주석(`#`)과 빈 줄은 무시됩니다. 각 URL은 전체 파이프라인을 거칩니다.

## Pipe 모드

`stdin`에서 읽습니다. 정찰 도구를 체이닝할 때 흔히 쓰이는 방식입니다:

```bash
cat urls.txt | dalfox scan
waybackurls example.com | gf xss | dalfox scan
hakrawler -url https://target.app | dalfox scan
```

Dalfox는 입력을 버퍼링하고 중복을 제거한 뒤 모든 줄을 대상으로 스캔합니다.

### 명령줄 대상과 함께 파이프하기

대상을 인자로 주면서 동시에 파이프로도 넘기면 두 목록이 병합됩니다:

```bash
cat urls.txt | dalfox scan https://target.app/one
# [info] Merged 12 target(s) from stdin and 1 target(s) from arguments
```

이 경우 명령줄 대상만으로도 이미 스캔이 가능하므로, Dalfox는 `stdin`의 첫 바이트를 약 500ms만 기다립니다. 래퍼나 CI 잡, 잡 러너가 열어둔 채 아무것도 쓰지 않는 파이프는 실행을 막지 않고 경고와 함께 건너뜁니다. 일단 스트림이 데이터를 보내기 시작하면 끝까지 읽으므로, 길거나 천천히 쓰이는 목록이 잘리는 일은 없습니다.

이 동작을 조정하려면 `DALFOX_STDIN_WAIT_MS`로 대기 시간을 늘리거나 `0`으로 병합을 끌 수 있습니다([Environment](../../reference/environment/) 참고). `stdin`이 곧 입력이며 얼마가 걸리든 기다려야 한다면 `--input-type pipe`를 사용하세요.

### 거의 같은 URL 묶기

기본값(`--dedup-urls exact`)에서 Dalfox는 완전히 같은 타깃만 버립니다. 쿼리 값까지 포함한 전체 URL과 메서드가 모두 일치해야 합니다. 그런데 `gau` / `katana` / `waybackurls` 결과는 그런 모양이 아닙니다. 보통은 엔드포인트 몇 개에 값만 수천 개가 붙어 있고, 결국 `?id=1` … `?id=9999`가 인젝션 지점 하나를 9999번 풀스캔하게 됩니다.

`--dedup-urls signature`는 이것을 하나로 묶습니다. 키는 메서드, 스킴, 호스트, 포트, 경로, 그리고 *정렬된 파라미터 이름 집합*입니다. 쿼리는 물론 본문(form, JSON, multipart) 파라미터도 같은 자격으로 포함됩니다. 값은 키에서 제외되므로 값만 다른 URL 무리는 목록에서 가장 먼저 나온 하나로 대표됩니다. 무엇을 버렸는지는 로그로 남고, 그 개수는 스캔 메타데이터(`dedup_mode`, `targets_deduplicated`)에도 실리므로 축소된 실행이 목록 전체를 커버한 것처럼 보이지 않습니다.

```bash
gau target.app | dalfox scan --dedup-urls signature
# INF dedup (signature): 8214 duplicate target(s) collapsed, 37 remaining — dropped e.g. …
```

언제 안전할까요? 입력이 어디로 흘러가는지를 파라미터 *이름*이 결정하는 경우, 즉 대부분의 경우입니다. 반대로 값이 코드 경로를 고르는 경우에는 **안전하지 않습니다.** 같은 경로에서 다른 핸들러로 분기하는 `action=` / `mode=` / `template=` 같은 판별자, 라우팅 토큰, 렌더링 템플릿을 바꾸는 로케일 값이 그렇습니다. 이런 곳에서는 한 분기만 스캔하고 전체를 보고하게 되므로, `signature`는 옵트인으로 남겨 두었습니다.

모든 줄을 입력 그대로 스캔해야 하는 드문 경우에는 `--dedup-urls off`로 중복 제거를 완전히 끌 수 있습니다.

## Raw HTTP 모드

Burp, Caido, ZAP에서 캡처한 요청을 파일로 저장한 뒤 Dalfox에 넘겨줍니다:

```bash
dalfox scan --input-type raw-http request.txt
```

이 파일은 표준 raw HTTP 요청(메서드 + 경로 + 헤더 + 빈 줄 + 본문)입니다. Dalfox는 모든 헤더, 쿠키, 본문 파라미터를 보존합니다.

실시간 프록시 워크플로(특히 Caido Active Workflows)에 대해서는 전용 [Caido 연동 가이드](../integrations/caido/)를 참고하세요. 정확한 셸 패턴, If/Else 노드에서의 Caido 불리언 함정, 그리고 결과를 자동으로 Findings로 전환하는 방법을 다룹니다.

## HAR 모드

전체 [HAR](http://www.softwareishard.com/blog/har-12-spec/)(HTTP Archive) 익스포트 — 브라우저 DevTools와 가로채기 프록시(Burp, Caido, ZAP, Charles, mitmproxy)가 생성하는 JSON 캡처 — 를 Dalfox에 넘겨주면, 그 안의 모든 요청을 각각의 URL, 메서드, 헤더, 쿠키, 본문을 보존한 채로 스캔합니다:

```bash
# Auto-detected from the file content:
dalfox scan capture.har
# or explicit:
dalfox scan --input-type har capture.har
# or piped from another tool:
mitmdump -nr flows -w /dev/stdout --set hardump=- | dalfox scan -i har
```

HAR을 단순 URL 목록으로 평탄화하는 것(메서드, 헤더, 쿠키, 본문을 버리는 방식)과 달리, HAR 모드는 캡처된 각 요청의 전체 형태를 유지하므로 JSON 본문을 가진 POST나 인증된 세션도 충실하게 재생됩니다. 각 `log.entries[].request`는 하나의 대상이 되며, 요청은 URL + 메서드로 중복 제거되고 다른 모든 모드와 동일한 스코프 필터를 거칩니다. `http(s)`가 아닌 항목(`data:`, `blob:`, WebSocket, 브라우저 확장 URL)은 자동으로 건너뜁니다.

이는 Go v2.x 라인이 가졌으나 v3 재작성에서 처음에 빠졌던 기능을 복원한 것입니다. CLI 요청 플래그는 그 위에 그대로 적용됩니다. 예를 들어 `-H "Authorization: Bearer …"` 는 모든 항목에 추가되고, `--include-url` / `--out-of-scope` 는 대상 집합을 좁힙니다.

## 저장형 XSS 모드 (SXSS)

전형적인 "폼 A에 주입하면 페이지 B에 페이로드가 나타난다" 패턴을 테스트합니다:

```bash
dalfox scan https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox는 첫 번째 URL에 주입한 다음, 두 번째 URL을 가져와 페이로드가 도달했는지 확인합니다. 전체 흐름은 [저장형 XSS 가이드](../stored-xss/)를 참고하세요.

## 서버 모드

Dalfox를 장시간 유지되는 HTTP 서비스로 실행합니다. REST를 통해 스캔을 제출하고, 결과를 폴링하고, 실행 중인 작업을 취소합니다:

```bash
dalfox server --port 6664 --api-key "$DALFOX_API_KEY"
```

엔드포인트와 요청 형태는 [REST API Server](../../integrations/server/)를 참고하세요.

## MCP 모드

Dalfox를 [Model Context Protocol](https://modelcontextprotocol.io) 서버로 노출하여 AI 에이전트와 IDE(예: Claude)가 스캔을 구동할 수 있게 합니다:

```bash
dalfox mcp
```

도구(`scan_with_dalfox`, `get_results_dalfox`, `list_scans_dalfox`, `cancel_scan_dalfox`, `delete_scan_dalfox`, `preflight_dalfox`)는 [MCP Server](../../integrations/mcp/)에 설명되어 있습니다.

## Payload 모드 (유틸리티)

스캔 모드는 아니지만 함께 유용합니다. 스캔을 실행하지 않고 페이로드를 출력하거나 가져옵니다.

```bash
dalfox payload event-handlers    # list DOM event handlers
dalfox payload useful-tags       # list useful HTML tags
dalfox payload portswigger       # fetch PortSwigger XSS cheatsheet
dalfox payload payloadbox        # fetch PayloadBox XSS list
dalfox payload uri-scheme        # print javascript:/data: payloads
```

## 모드 선택하기

| 원하는 작업 | 사용할 모드 |
|--------------|-----|
| URL 하나 테스트 | Auto / URL |
| 크롤러가 만든 목록 스캔 | File 또는 Pipe |
| 특정 요청 재생 | Raw HTTP |
| 캡처한 세션 전체 재생(프록시/DevTools 익스포트) | HAR |
| 다른 페이지에 기록하는 폼 테스트 | SXSS |
| 대시보드나 CI에서 여러 스캔 실행 | Server |
| AI 에이전트가 스캔을 구동하게 하기 | MCP |
| Dalfox가 보낼 페이로드만 확인 | Payload 유틸리티 또는 `--dry-run` |
