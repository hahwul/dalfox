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

`--dedup-urls signature`는 이것을 하나로 묶습니다. 키는 메서드, 스킴, 호스트, 포트, 경로, 그리고 *정렬된 파라미터 이름 집합*입니다. 쿼리는 물론 본문(form, JSON, multipart) 파라미터도 같은 자격으로 포함됩니다. 값은 키에서 제외되므로 값만 다른 URL 무리는 타깃 하나로 묶입니다. 무엇을 버렸는지는 로그로 남고, 그 개수는 스캔 메타데이터(`dedup_mode`, `targets_deduplicated`)에도 실리므로 축소된 실행이 목록 전체를 커버한 것처럼 보이지 않습니다.

대표로 남는 것은 목록에서 가장 먼저 나온 URL입니다. 단, 값이 비어 있는 앞쪽 URL보다 모든 파라미터에 값이 채워진 뒤쪽 URL이 우선합니다. 정찰 결과에는 `?id=42`보다 `?id=`가 먼저 오는 경우가 많은데, 값이 빈 URL은 404가 되기 쉬워서 그것이 대표가 되면 무리 전체를 깨끗한 것으로 잘못 보고하게 되기 때문입니다. 스코프 필터(`--include-url`, `--exclude-url`, `--out-of-scope`)는 중복 제거보다 *먼저* 적용되므로, 필터가 항상 먼저 구성원을 걸러낼 기회를 갖습니다.

```bash
gau target.app | dalfox scan --dedup-urls signature
# INF dedup (signature): 8214 duplicate target(s) collapsed, 37 remaining — dropped e.g. …
```

언제 안전할까요? 입력이 어디로 흘러가는지를 파라미터 *이름*이 결정하는 경우, 즉 대부분의 경우입니다. 반대로 값이 코드 경로를 고르는 경우에는 **안전하지 않습니다.** 같은 경로에서 다른 핸들러로 분기하는 `action=` / `mode=` / `template=` 같은 판별자, 라우팅 토큰, 렌더링 템플릿을 바꾸는 로케일 값이 그렇습니다. 이런 곳에서는 한 분기만 스캔하고 전체를 보고하게 되므로, `signature`는 옵트인으로 남겨 두었습니다.

모든 줄을 입력 그대로 스캔해야 하는 드문 경우에는 `--dedup-urls off`로 중복 제거를 완전히 끌 수 있습니다. 다만 대상별 리포팅은 URL을 키로 삼으므로, 같은 URL이 여러 번 나와도 `target_summary` 항목은 하나로 합쳐집니다.

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

## 세션 모니터링

정적 자격증명(`--cookies`, `-H 'Cookie: …'`, `--cookie-from-raw`)은 모든 요청에 그대로 붙을 뿐 유효성을 다시 확인하지 않습니다. 긴 스캔 도중 한 시간쯤 지나 세션이 만료되면 이후 모든 요청은 로그인 페이지를 받고, 아무것도 반사되지 않으며, Dalfox는 빈 리포트와 함께 `0`으로 종료합니다 — 진짜로 안전한 대상과 구분할 수 없습니다.

세션 모니터링이 이 간극을 메웁니다. 프리플라이트 단계에서 인증된 랜딩 응답의 지문(상태 코드, 리다이렉트 후 최종 도착지, 로그인 폼이 이미 있었는지)을 **추가 요청 없이** 확보합니다 — 프리플라이트가 이미 가져온 본문을 재사용합니다. 이후 각 대상의 주입 단계가 끝난 직후에 다시 조회하고, 기준 지문이 30초 이상 지났다면 디스패치 경계에서도 한 번 더 조회해 비교합니다. (짧거나 단일 대상 실행에서는 사후 조회만 발생합니다. 방금 잡은 기준을 다시 확인해 봐야 알 수 있는 것이 없기 때문입니다.)

```bash
# 별도 설정이 필요 없습니다. 자격증명이 있으면 자동으로 켜집니다.
dalfox scan https://app.example.com/dashboard?q=1 --cookies "sid=$SESSION"
```

다음 중 하나라도 감지되면 세션이 끊어진 것으로 보고합니다:

| 신호 | 예시 |
|--------|---------|
| 상태 코드가 `401` / `403`으로 바뀜 | 앱이 쿠키를 거부하기 시작 |
| 요청이 로그인 형태의 URL로 도착 | `302 → /users/sign_in` |
| 기준에는 없던 비밀번호 입력 필드가 등장 | 앱이 로그인 화면을 인라인으로 렌더링 |

`403`은 오리진이나 WAF가 스캐너를 차단하기 시작했을 때도 반환됩니다. 해당 대상에서 이미 WAF가 탐지된 경우 `403` 신호는 아예 무시합니다 — 만료된 세션보다 차단이 더 그럴듯한 설명이고, 이를 로그아웃으로 판단하면 WAF 규칙 하나 때문에 호스트 전체를 중단하게 되기 때문입니다. WAF 뒤에 있는 오리진에서 `403`을 만료 신호로 쓰려면 `--session-check`를 사용하세요.

### 정확하게 지정하기

휴리스틱은 의도적으로 좁게 잡혀 있습니다 — 기본 동작이 중단(abort)이므로 오탐 하나가 스캔 전체를 날립니다. 인증된 응답이 어떤 모습인지 정확히 안다면 그것을 지정하세요. 그러면 휴리스틱은 완전히 물러납니다:

```bash
dalfox scan https://app.example.com/dashboard?q=1 \
  --cookies "sid=$SESSION" \
  --session-check 'Signed in as' \
  --session-check-url https://app.example.com/api/me
```

스캔 대상이 무겁거나, 페이지네이션이 있거나, 그 자체로 공개 페이지라면 `--session-check-url`로 가벼운 인증 엔드포인트를 따로 지정하는 편이 좋습니다. 이 경우 기준 지문도 해당 엔드포인트에서 잡습니다(플래그를 지정했을 때만, 대상당 프리플라이트 요청 1건 추가). 덕분에 `/auth/session`처럼 로그인 형태의 프로브 경로도 스캔 대상이 아니라 자기 자신의 인증된 응답과 비교됩니다.

### 세션이 끊어졌을 때

`--on-session-loss abort`(기본값)는 해당 대상을 중단하고 같은 호스트의 남은 대상도 건너뜁니다. 로그인 페이지를 상대로 요청 예산을 계속 쓰는 것은 아무 이득이 없기 때문입니다. `--on-session-loss continue`는 휴리스틱이 오탐하는 대상을 위해 스캔을 계속합니다.

어느 쪽이든 실행 결과는 이 사실을 숨기지 않습니다:

- **stderr**에 `SESSION LOST` 한 줄 — 구조화된 stdout은 그대로 파싱 가능
- 해당 대상은 `incomplete`(또는 `skipped`) 상태에 `error_code: SESSION_LOST`, 그리고 어떤 신호가 감지됐는지 `error_message`에 기록
- [스캔 메타데이터 봉투](../output/)의 `meta.incomplete: true`
- 탐지 결과가 없는 실행에 한해 `abort`에서 종료 코드 `2` — 따라서 로그아웃된 상태에서 `dalfox scan … && echo "no XSS found"`가 그 줄을 출력할 수 없습니다. 탐지 결과가 *있었다면* 여전히 `1`로 종료합니다. 발견된 취약점은 어쨌든 실재하고, 불완전하다는 사실은 `meta.incomplete`가 전달하기 때문입니다. `continue`는 종료 코드를 전혀 바꾸지 않습니다

**프리플라이트** 응답부터 이미 미인증으로 보이거나, `--session-check` 마커가 기준 응답에 애초에 없었던 경우(오타이거나 다른 페이지에 있는 마커)도 표시합니다. 두 경우 모두 단순 로그가 아니라 `SESSION_LOST`로 보고합니다: 그런 기준에서는 이후 어떤 조회도 *변화*를 감지할 수 없으므로, 만료된 자격증명이 조용하고 완벽하게 "깨끗한" 실행을 만들어 내기 때문입니다. 대상 스캔 자체는 그대로 진행되며, 결과를 정직하게 만드는 것은 이 표시와 종료 코드입니다.

"이미 미인증으로 보인다"는 것은 로그인 페이지 그 자체를 뜻합니다 — `401`, 페이지에 직접 렌더링된 비밀번호 입력란, 또는 `/login`, `/signin`, `/users/sign_in`으로의 리다이렉트입니다. 단지 인증*처럼 생긴* 경로로 리다이렉트되는 것만으로는 부족합니다. 인증된 홈을 `/auth/home`이나 `/sso/dashboard`에서 서빙하는 앱이 많고, 그걸 끊어진 세션으로 판정하면 멀쩡한 세션의 스캔을 실패시키게 됩니다. 이 경우 dalfox는 대신 `SESSION?` 참고 메시지를 출력합니다 — 눈에는 보이지만 `SESSION_LOST` 항목도, `meta.incomplete`도, 종료 코드 변화도 없습니다. 여러분의 앱이 여기 해당하는데도 검사를 정확히 하고 싶다면 `--session-check`로 확정하세요.

자격증명이 없고 `--session-check` 계열 플래그도 지정하지 않으면 모니터링은 꺼져 있으며 비용도 들지 않습니다. 자동 로그인은 범위 밖입니다. 이 기능은 감지만 담당합니다.

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
