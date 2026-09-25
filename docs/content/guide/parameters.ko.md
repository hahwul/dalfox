+++
title = "파라미터와 탐색"
description = "Dalfox가 중요한 입력값을 찾아내는 방식과 탐색 단계를 제어하는 방법을 설명합니다."
weight = 2
toc = true
+++

XSS를 찾는 일은 올바른 파라미터를 찾는 데서 시작합니다. Dalfox의 탐색 엔진은 여러 단계로 이루어진 파이프라인입니다. 전체를 이해할 필요는 거의 없지만, 각 구성 요소를 알아두면 스캔을 튜닝하고 싶을 때 도움이 됩니다.

## 파이프라인 개요

1. **Discovery(탐색):** 요청에 이미 들어 있는 입력을 프로빙합니다. 쿼리 값(과 쿼리 파라미터 *이름*), 헤더, 쿠키, 경로 세그먼트, 페이지에서 찾은 폼의 필드가 대상입니다. URL 프래그먼트 키도 기록하지만, AST 결과와 연결하기 위한 용도일 뿐입니다. 프래그먼트는 서버에 전달되지 않으므로 퍼징하지 않습니다.
2. **Mining(마이닝):** `-d` 본문의 파라미터(form, JSON, GraphQL 변수, XML, multipart)를 프로빙한 뒤, 요청에 없는 이름을 찾습니다. 사전 워드리스트와 응답 속 `<input>` 요소의 `id`/`name`이 그 출처입니다.
3. **Active probing(능동 프로빙):** 각 파라미터에 프로브를 보내 어떤 특수 문자가 살아남는지 파악하고, 주입 컨텍스트를 다듬고, URL 디코딩을 여러 번 하는 서버를 찾아냅니다.
4. **Payload generation(페이로드 생성):** 컨텍스트를 인식하는 페이로드 세트(HTML, JS, 속성, CSS)를 만듭니다. 파라미터의 페이로드를 보내기 전에 **빠른 프로브(fast probe)** 가 샌드위치 마커 요청을 한 번 보냅니다(영문자를 제거하는 필터를 잡기 위한 숫자 전용 대체 프로브 포함). 아무것도 반사되지 않으면 `--deep-scan`이 아닌 한 해당 파라미터의 무거운 페이로드 루프를 건너뜁니다. 능동 프로빙에서 이미 마커가 돌아온 것을 봤다면, 빠른 프로브는 요청을 따로 보내지 않고 그 결과를 재사용합니다.
5. **Reflection check(반사 확인):** 페이로드를 보낸 뒤 그것이 돌아오는지 확인합니다.
6. **DOM verification(DOM 검증):** 응답을 파싱하여 페이로드가 실행 가능한 위치에 도달했는지 확인합니다. AST 기반 DOM-XSS 분석은 먼저 랜딩 페이지 자체에 대해 한 번 실행되고, 이어서 파라미터당 한 번 빠른 프로브의 응답(빠른 프로브를 건너뛴 경우에는 첫 반사 응답)으로 실행됩니다.

## 특정 파라미터 지정하기

테스트할 파라미터를 Dalfox에 정확히 지정합니다:

```bash
dalfox scan https://target.app/api \
  -p q \
  -p id:query \
  -p auth:header \
  -p token:cookie
```

위치(Location): `query`, `body`, `json`, `multipart`, `cookie`, `header`, `graphql`, `xml`. 주입 지점이 쿼리 문자열이 아니라면 `name:location` 형식을 쓰세요. `graphql`과 `xml`은 요청 본문에서 자동으로 탐지됩니다([GraphQL 및 XML 본문 주입](#graphql-및-xml-본문-주입) 참조). 힌트는 이미 발견된 파라미터를 필터링할 수는 있지만, 이름만으로 새 본문을 합성하지는 못합니다. `path`와 `fragment`도 같은 방식으로 필터로만 동작합니다. 경로 세그먼트는 위치로 이름이 붙습니다(`-p path_segment_0:path`).

위치 힌트가 없는 경우(`-p q`만 지정):

1. 탐색/마이닝이 이미 해당 이름의 파라미터를 찾았다면, 그대로 유지합니다(필터).
2. 그렇지 않으면 Dalfox가 이를 **합성(synthesize)** 합니다. 위치는 요청에서 추론하며(URL 쿼리 → 본문 → 쿠키 → 헤더), 기본값은 `query`입니다.

즉, `-p q --skip-discovery --skip-mining` 같은 조합도 아무것도 스캔하지 않고 조용히 지나가는 대신 `q`를 그대로 테스트합니다.

## 워드리스트로 마이닝하기

URL에 파라미터가 없더라도 Dalfox는 흔히 쓰이는 이름을 시도해 볼 수 있습니다:

```bash
# 로컬 워드리스트
dalfox scan https://target.app -W ./params.txt

# 원격 워드리스트(첫 조회 이후 캐시됨)
dalfox scan https://target.app --remote-wordlists burp,assetnote
```

스캔당 목록은 하나만 사용합니다. `--remote-wordlists`를 불러오는 데 성공하면 그것이 우선하고 `-W`는 무시됩니다. `-W`는 원격 조회가 실패했을 때의 대체 수단입니다. 마이닝한 이름은 쿼리 파라미터로 테스트합니다.

사전과 DOM 후보는 이름마다 요청을 하나씩 보내지 않고, 요청 하나에 최대 64개 이름을 담은 버킷으로 검사합니다(요청 라인은 약 8 KiB 이하로 유지). canary가 반사된 이름은 그 응답 하나로 식별됩니다. 아무것도 반사되지 않았는데 응답이 달라진 버킷은 같은 크기의 control 요청과 비교한 뒤, 버킷을 나눠 어떤 이름이 변화를 일으켰는지 찾습니다. 추가 요청은 이런 모호한 버킷에만 쓰므로 큰 워드리스트도 저렴하게 확인할 수 있습니다.

같은 요청에도 본문이 매번 달라지는 페이지(순환 위젯, 타임스탬프 등)에서는 상태 코드 변화만 응답 변화로 인정합니다. 요청이 실패했거나 서버가 크기 때문에 거부한 버킷(예: 쿼리 길이 제한)은 버리지 않고 나눠서 다시 보냅니다.

사용자 지정 또는 원격 워드리스트를 선택하지 않으면 기존 XSS 중심 이름을
유지하면서 API, 인증, 페이지네이션, feature flag, 미디어, 운영 관련 이름을
넓힌 Param Miner 시드가 기본 목록에 추가됩니다.

### 자동 축소(Auto-collapse)

반사가 매우 심한 사이트(예: 모든 것을 그대로 되돌려주는 검색 페이지)는 워드리스트 마이닝을 폭발적으로 늘릴 수 있습니다. Dalfox는 두 가지 방법으로 이를 방어합니다:

- **Sentinel 사전 프로브(pre-probe):** 워드리스트를 순회하기 전에, 실제 필드와 절대 충돌하지 않을 무작위 파라미터 이름 세 개를 테스트합니다. 세 개가 모두 반사되면 그 페이지는 거울(mirror)이므로 마이닝을 건너뛰고 단일 합성 `any` Query 파라미터로 대체합니다. 비용 상한: 워드리스트 크기와 무관하게 3개 요청. 사전 프로브가 이득이 될 만큼 워드리스트가 충분히 클 때(>15개 항목)만 실행됩니다.
- **EWMA 축소:** 버킷 처리가 끝난 뒤 Dalfox는 이동 반사 비율(rolling reflection ratio)을 관찰합니다. 최소 15개 후보 이름 이후에도 그 값이 ≥85%이면 작은 목록에 대해 확인 프로브를 수행합니다. sentinel도 반사되면 마이닝한 Query 파라미터를 `any` 플레이스홀더 하나로 접고, 반사되지 않으면 확인된 후보를 모두 유지합니다. 따라서 큰 워드리스트의 나머지 커버리지가 sentinel 결과만으로 잘리지 않습니다.

sentinel이 확인된 경로는 합성 Query 주입 지점 하나를 만듭니다. sentinel이 부정되면 개별 반사 이름을 유지하면서도 버킷 요청의 효율은 그대로 얻습니다.

## 노이즈 정리하기

특정 파라미터 무시:

```bash
dalfox scan https://target.app --ignore-param csrf --ignore-param __RequestVerificationToken
```

URL 패턴으로 범위 지정:

```bash
dalfox scan urls.txt \
  --include-url '^https://api\.target\.app/' \
  --exclude-url '/static/|/health'
```

범위 밖(out-of-scope) 도메인 목록:

```bash
dalfox scan urls.txt --out-of-scope-file scope-block.txt
# 또는 와일드카드를 사용해 인라인으로(플래그를 반복하고, 플래그 하나에 패턴 하나)
dalfox scan urls.txt --out-of-scope '*.google.com' --out-of-scope '*.cdn.cloudflare.net'
```

`--out-of-scope`는 쉼표로 나누지 않습니다. `'*.google.com,*.cdn.cloudflare.net'`은 패턴 하나로 읽히고 아무것과도 일치하지 않습니다.

## 탐색만 하고 공격하지 않기

두 모드 모두 같은 탐색, 마이닝, 능동 프로빙 요청을 실행하고 스캔 단계 전에 멈추므로, XSS 페이로드는 보내지 않습니다. 차이는 무엇을 출력하느냐입니다.

Dry-run은 공격 계획을 출력합니다. 대상 수, 대상별로 찾은 파라미터, 실제 스캔이 보낼 요청 수의 하한 추정치입니다. WAF 유도 프로브(`<script>` 페이로드를 담은 요청 1건)도 건너뛰므로, 공격 형태의 요청을 하나도 보내면 안 될 때는 이쪽을 쓰세요.

```bash
dalfox scan https://target.app --dry-run
```

Discovery-only는 탐색된 파라미터마다 한 줄(URL, 이름, 위치)을 출력합니다:

```bash
dalfox scan https://target.app --only-discovery
```

두 모드 모두 범위 지정과 CI 사전 점검에 도움이 됩니다.

## 단계 건너뛰기

더 빠르게 진행하거나 불안정한 대상을 우회하려면 파이프라인의 일부를 건너뛰세요:

| 플래그 | 건너뛰는 대상 |
|------|-------|
| `--skip-discovery` | 탐색 단계 전체(쿼리, 헤더, 쿠키, 경로, 폼, 프래그먼트) |
| `--skip-mining` | 모든 워드리스트/DOM 마이닝 |
| `--skip-mining-dict` | 사전 마이닝만 |
| `--skip-mining-dom` | `<input>`의 `id`/`name` 속성에서 파라미터 이름을 수집하는 마이닝만 |
| `--skip-reflection-header` | 내장된 공통 헤더 스윕. `-H`로 넘긴 헤더는 여전히 프로빙됩니다 |
| `--skip-reflection-cookie` | 요청에 담긴 쿠키 프로빙 |
| `--skip-reflection-path` | 경로 세그먼트 반사 확인 |

명시적으로 지정한 것은 이 플래그들의 영향을 받지 않습니다. `-d` 본문 파라미터는 `--skip-mining`에서도 프로빙되고, `-p name:header`나 `-p name:cookie`는 해당 `--skip-reflection-*` 플래그가 있어도 프로빙됩니다. 페이로드 쪽 건너뛰기 플래그(`--skip-xss-scanning`, `--skip-ast-analysis`, `--skip-waf-probe`)는 [CLI 레퍼런스](../../reference/cli/)에 있습니다.

> `--skip-mining-dom`은 응답 HTML에서 파라미터 *이름*을 수집하는 동작만 멈춥니다. DOM-XSS 탐지 자체를 끄지는 **않습니다**: 인라인 `<script>` 블록을 정적 분석해 `location.hash` → `innerHTML` 같은 source→sink 흐름을 찾아 `[A]`(AST 탐지) 결과를 내는 패스는 [`--skip-ast-analysis`](../payloads/)가 제어하는 별개의 단계입니다. 결과에서 해당 항목만 걸러내려면 `--only-poc v,r`을 사용하세요. 두 서브시스템의 차이와 각 증거 등급의 의미는 [탐지 모델](../detection-model/) 문서를 참고하세요.

## 주입 마커(Injection markers)

주입 지점을 이미 알고 있다면 `--inject-marker`로 표시하세요:

```bash
dalfox scan https://target.app/api \
  --inject-marker FUZZ \
  -d '{"filter":"FUZZ"}'
```

마커를 지정하면 탐색, 마이닝, 능동 프로빙을 건너뜁니다. `FUZZ`를 포함한 쿼리 값, form 본문 값, 최상위 JSON 문자열 값, 헤더 값, 쿠키 값이 각각 파라미터가 되고, 각 페이로드는 그 값 전체를 대체합니다. 그 밖의 위치(경로 세그먼트, 중첩된 JSON 필드)에 둔 마커는 인식하지 않습니다.

쿼리 파라미터나 헤더를 직접 지정할 수도 있습니다:

```bash
# 쿼리 파라미터
dalfox scan 'https://example.com/?q=FUZZ&page=1' --inject-marker FUZZ

# 헤더
dalfox scan https://example.com -H 'X-Search: FUZZ' --inject-marker FUZZ
```

## 자동 사전 인코딩(Auto pre-encoding)

일부 엔드포인트는 페이로드를 원시 텍스트로 받아들이지 않습니다. 이들은 어떤 구조적 인코딩(base64, JSON, JWT 등)으로 감싸진 형태를 기대합니다. 쿼리 탐색 중 어떤 파라미터에서 일반 마커가 돌아오지 않으면, Dalfox는 아래의 래핑 형태를 시도하고 마커가 반사된 래핑을 유지합니다. 이후 그 파라미터의 페이로드는 같은 래핑을 거쳐 전송됩니다. 설정할 것은 없습니다. 쿼리 파라미터에 적용됩니다.

단일 단계 인코딩은 마커를 미리 인코딩해 보내는 방식으로 찾습니다:

| 탐지된 형태 | 페이로드 인코딩 방식 |
|----------|-------------------|
| `base64` | `BASE64(payload)` |
| `2base64` | `BASE64(BASE64(payload))` |
| `2url` / `3url` | 2회 또는 3회 URL 인코딩 |

능동 프로빙도 `<`가 필터링되는 쿼리·경로 파라미터에 `2url` / `3url`을 시도해, URL 디코딩을 여러 번 하는 서버를 잡아냅니다.

조합 가능한 파이프라인은 파라미터의 기존 값에서 추론합니다. 값이 구조화된 래퍼로 디코딩되면, Dalfox는 모든 리프(leaf) 문자열 필드를 각각 별도의 가상 하위 파라미터로 프로빙하고, 마커가 반사된 리프를 유지합니다:

| 래퍼 형태 | 파이프라인 |
|---------------|----------|
| Base64로 감싼 JSON `?qs=eyJ…` | `JsonField(/leaf) → Base64` |
| Base64URL로 감싼 JSON | `JsonField(/leaf) → Base64Url` |
| 순수 URL 인코딩된 JSON `?blob=%7B…%7D` | `JsonField(/leaf)` |
| JWT/JWS `?token=h.p.s` | `JsonField(/leaf) → Base64Url → JwtAssemble` |

각 리프는 대괄호 스타일 표시 이름으로 각각 별도의 Param에 등록됩니다. `qs`의 `move_url` 필드에 있는 페이로드는 `qs[move_url]`로 표시되고, 배열 요소는 `qs[items][0]`으로 나타납니다. 와이어 수준의 치환은 여전히 원래 부모 파라미터(`qs`)를 대상으로 하므로, 요청은 서버에 정상적으로 보입니다.

JWT의 경우 원래 헤더와 서명 세그먼트는 그대로(verbatim) 보존됩니다. 서명은 수정된 페이로드와 일치하지 않으므로, 이는 토큰을 검증하지 않는 엔드포인트에서만 발동합니다. 올바르게 서명된 JWT는 탐지 결과를 반환하지 않습니다. 이는 놓친 것이 아니라 의도된 동작입니다.

대상이 Dalfox가 자동 탐지하지 못하는 래핑을 쓴다면, `--inject-marker`(위 참조)로 주입 지점을 고정할 수는 있지만 페이로드는 래핑 없이 그대로 전송됩니다.

## GraphQL 및 XML 본문 주입

요청 본문(`-d`, 또는 캡처된 `raw-http` / `har` 요청)이 GraphQL이나 XML 문서라면, Dalfox는 본문 전체를 하나의 불투명한 덩어리로 테스트하는 대신 그 안의 값들을 주입 지점으로 다룹니다.

**GraphQL**(JSON 본문. content type이 아니라 본문의 형태로 판별합니다): GraphQL 오퍼레이션(값이 `query`/`mutation`/`subscription` 또는 익명 `{ … }` 축약형으로 시작하는 `query`/`mutation` 필드)과 `variables` 오브젝트를 **둘 다** 가진 본문은, `variables` 안의 모든 문자열 leaf를 프로빙하고 반사되는 것마다 각각 `graphql` 파라미터(이름은 `variables.<경로>`)로 등록합니다. 각 페이로드는 요청 전체를 재구성하며(오퍼레이션과 다른 변수들은 그대로 함께 전송) 서버는 항상 유효하고 파싱 가능한 GraphQL 요청을 받습니다.

```bash
dalfox scan https://target.app/graphql \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{"query":"query($q:String!){ search(term:$q){ id } }","variables":{"q":"seed"}}'
# → variables.q 가 `graphql` 파라미터로 주입됩니다
```

단지 `query`라는 이름의 필드만 있는 평범한 REST 엔드포인트(검색창, `{"query":"laptop"}`)는 GraphQL로 **취급되지 않습니다** — `variables` 오브젝트와 오퍼레이션 형태의 값이 모두 필요하므로, 일반 JSON 본문은 그대로 `json` 경로에 남습니다.

**XML / SOAP**(`text/xml`, `application/xml`, `application/soap+xml`, 또는 `<?xml …?>` 프롤로그가 있는 본문): 각 엘리먼트 텍스트 노드와 속성 값을 프로빙하고, 반사되는 것마다 `xml` 파라미터가 됩니다. byte-range splice가 페이로드를 제자리에 주입하며, 문서의 다른 모든 바이트 — 네임스페이스, 형제 엘리먼트, SOAP 엔벨로프 — 는 그대로 유지되고 요청의 XML content-type도 보존됩니다.

```bash
dalfox scan https://target.app/soap \
  -X POST \
  -H 'Content-Type: application/soap+xml' \
  -d '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><search><term>seed</term></search></soap:Body></soap:Envelope>'
# → <term> 텍스트 노드가 `xml` 파라미터로 주입됩니다
```

모든 반사 결과와 마찬가지로, 값은 응답이 브라우저가 마크업으로 렌더링할 문서일 때만 `[V]`로 등급이 매겨집니다([탐지 모델](../detection-model/#응답-content-type이-허용하는-것) 참고) — `application/json`으로 응답하는 GraphQL API나 이스케이프된 값을 되돌려주는 XML 서비스는 올바르게 무해(inert)로 보고됩니다. 실제로 위험한 곳은 반사된 값을 마크업으로 렌더링하는 관리자 화면, 리포트, 에러 페이지입니다.

## 반사 프로브 형태

모든 탐색 및 마이닝 프로브는 단일 토큰 대신 샌드위치 마커(`OPEN + INNER + CLOSE`)를 보냅니다. 그런 다음 응답은 네 가지 경우 중 하나로 분류됩니다:

| 반사 | 의미 |
|------------|---------|
| **Full** | 완전한 `OPEN+INNER+CLOSE`가 살아남음. 표준 반사. |
| **PrefixOnly** | `OPEN+INNER`는 존재하고 `CLOSE`가 제거됨. 접미사 제거 필터를 시사. |
| **SuffixOnly** | `INNER+CLOSE`는 존재하고 `OPEN`이 제거됨. 접두사 제거 필터를 시사. |
| **InnerOnly** | `INNER`만 살아남음. 정규식 추출이거나 양쪽 래핑이 모두 제거됐음을 시사. |

네 가지 모두 "반사됨"으로 취급됩니다. 탐색은 해당 파라미터를 기록하고 스캔이 진행됩니다. 단순한 단일 토큰 확인이었다면 *Full*을 제외한 모든 경우를 놓쳐, 접두사/접미사를 제거하는 엔드포인트를 탐지하지 못했을 것입니다. 마커 토큰은 스캔마다 고유합니다(`dlx`/`dlxmid`/`xld` 접두사에 스캔당 8자리 16진수가 붙음). 따라서 HTML에서 우연히 충돌할 가능성은 무시할 만합니다.

## 탐지 결과가 "검증됨"이 되는 기준

| 결과 | 확인 방식 |
|--------|--------------------|
| **V** (Vulnerable, 취약) | Dalfox가 응답 DOM을 파싱해 페이로드가 실행될 수 있는 위치에 있음을 확인합니다. 브라우저 실행이 아니라 실제 응답을 정적으로 파싱한 결과입니다. [탐지 모델](../detection-model/) 참고. `evidence` 필드는 이를 입증한 경로를 태깅합니다: DOM 마커(CSS 셀렉터 적중), 실행 가능한 URL(위험한 속성 안의 `javascript:`/`data:`), HTML 구조적 증거(값이 싱크 호출인 `on*` 핸들러를 가진 주입된 요소), JS 컨텍스트 AST(파싱된 AST가 페이로드의 바이트 범위에 포함됨을 보여주는 `<script>` 내부의 싱크 호출), 인라인 핸들러 브레이크아웃(기존 `on*` 속성 안의 JS 문자열을 페이로드가 닫음). |
| **A** (AST-detected, AST 탐지) | 정적 JavaScript 분석이 사용자 제어 소스를 위험한 싱크로 추적함(예: `innerHTML = location.hash`). |
| **R** (Reflected, 반사됨) | 페이로드 텍스트가 응답 본문에 나타났지만 아직 DOM 증거는 없음. 여전히 수동으로 조사할 가치가 있음. |

`V`와 `A`는 신호입니다. `R`은 힌트입니다.

## 안전한 컨텍스트

반사된 위치가 모두 `<textarea>`, `<title>`, `<noscript>`, `<xmp>`, `<plaintext>` 내부라면 보고하지 않습니다. 그곳의 콘텐츠는 텍스트로 렌더링되므로 오탐(false positive)만 발생시킬 뿐입니다. 파라미터 자체는 계속 스캔하므로, 먼저 해당 요소를 닫는 페이로드(`</textarea><svg onload=…>`)는 여전히 찾을 수 있습니다.

같은 게이트가 무해한 형태 몇 가지를 더 걸러냅니다. `<script>` 안에만 반사되었고 파싱한 자바스크립트상 싱크 호출이 생기지 않는 경우, URL 값 속성 밖에서 서버가 이스케이프(퍼센트 또는 엔티티 인코딩)해서 되돌려준 경우, 그리고 `javascript:` / `data:` 페이로드가 URL 값 속성의 맨 앞에 한 번도 오지 않는 경우입니다. 브라우저가 마크업으로 렌더링하지 않는 응답(JSON, `text/plain` 등)은 [content type](../detection-model/#응답-content-type이-허용하는-것) 기준으로 따로 걸러냅니다.

## 다음 단계

- 페이로드가 어떻게 구성되는지는 [페이로드와 인코딩](../payloads/)에서 확인하세요.
- WAF를 상대하고 있나요? [WAF 우회](../waf-bypass/)로 넘어가세요.
