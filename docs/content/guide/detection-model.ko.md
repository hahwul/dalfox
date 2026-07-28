+++
title = "탐지 모델"
description = "Dalfox 결과의 세 축 — 신뢰도, 방식, 영향도 — 그리고 각 증거 등급이 실제로 무엇을 증명하는지."
weight = 7
toc = true
+++

Dalfox의 모든 결과는 서로 다른 세 질문에 답합니다. 이 셋을 하나의 척도로 읽는 것이 출력에 대한 오해의 가장 큰 원인이라, 별도 필드로 분리되어 있습니다.

| 축 | 필드 | 답하는 질문 |
|------|-------|----------|
| **신뢰도** | `type` — `V` / `R` | 이것을 취약점이라고 말할 수 있나? |
| **방식** | `detection_method` | 어떻게 찾았나? |
| **영향도** | `severity` | 악용되면 얼마나 나쁜가? |

셋 중 둘은 서로 독립적으로 움직입니다. **`severity`는 아직 아닙니다.** XSS
결과에서 severity는 현재 티어를 다시 말한 값이라(`V` → `High`, `A` →
`Medium`, `R` → `Info`), 여기에 필터나 정렬을 걸어도 `type`이 주지 않는 정보는
없습니다. 실제 정보를 담는 건 라이브러리 권고에서 값을 가져오는 `I`뿐입니다.
severity가 스스로 영향도를 판정하기 전까지는 표시용 편의로 보세요.

`[A]`는 이 분리보다 먼저 만들어졌습니다. `type` 필드에 앉아 있으면서 *방식* 질문에 답하기 때문에, 코드를 포함해 누구도 이것이 신뢰도 척도에서 어디에 속하는지 말할 수 없었습니다. 아래 **이관** 절에 따라 흡수될 예정입니다.

이 페이지는 그 구분이 출력만 봐서는 드러나지 않기 때문에 존재합니다. [이슈 #1238](https://github.com/hahwul/dalfox/issues/1238)에서 [@OSTARA711](https://github.com/OSTARA711)과 정리한 내용을 토대로 작성했습니다.

## 신뢰도: `type`의 의미

| 태그 | 이름 | 의미 |
|-----|------|-------|
| `V` | **Vulnerable(취약)** | Dalfox가 이 입력이 악용 가능하다고 판단합니다. 조치하세요. |
| `R` | **Reflected(반사됨)** | 페이로드가 응답에 돌아왔지만 실행 가능한 위치인지는 확인되지 않았습니다. 주장이 아니라 신호이므로 직접 확인하세요. |
| `A` | AST 탐지 | 과도기 — 방식 라벨입니다. 아래 이관 절 참고. |
| `I` | 정보성 | XSS 주장이 아닙니다 (예: 알려진 취약 JS 라이브러리, CWE-1104). |

`--only-poc`로 필터링합니다 (예: `--only-poc v`, `--only-poc v,a`, `--only-poc i`).

### `V`가 뜻하지 않는 것

`V`는 브라우저 실행이 **아닙니다.** Dalfox는 브라우저를 구동하지 않고 CDP도 쓰지 않습니다. 페이지를 렌더링하거나 `alert()`가 뜨는 것을 관찰하지 않습니다. 요청 기반 방식에서 `V`는 페이로드가 *실제 HTTP 응답으로 파싱한 DOM 트리*에서 발견됐다는 뜻입니다. 여전히 정적 분석이며, `R`의 단순 문자열 매칭보다 강한 증거일 뿐입니다.

Dalfox가 실제 실행을 관측하는 방식은 정확히 하나입니다 — **대역외 콜백**(blind XSS). 주입된 `<script src=…>`가 콜백을 보내오면, 실제 브라우저가 그것을 파싱하고 가져간 것입니다. 이건 경험적 증거이며 Dalfox가 만들어내는 가장 강한 증거입니다. 다만 Dalfox가 제어하는 브라우저가 아니라 다른 누군가의 브라우저에서 옵니다.

## 방식: `detection_method`의 의미

| 값 | 무엇을 읽는가 | 페이로드 전송? |
|-------|-------|------------------|
| `reflection` | 응답 본문에서 페이로드 바이트 | 예 |
| `dom-verification` | HTML로 파싱한 응답에서 실행 가능한 위치 | 예 |
| `ast` | 응답에 담긴 자바스크립트에서 소스→싱크 흐름 | 아니오 |
| `oob` | 실제 브라우저가 보낸 대역외 콜백 | 예 |
| `library` | `<script>` 태그에서 알려진 취약 버전 | 아니오 |

**AST 결과를 선택할 때는 `type == "A"`가 아니라 `detection_method == "ast"`를 쓰세요.** 방식 필드는 안정적이고, 티어는 그렇지 않습니다.

### 실제로 나오는 조합

티어와 방식은 따로 정해지므로 `V`가 곧 `dom-verification`을 뜻하지 않습니다.
Dalfox가 내보내는 결과는 다음 중 하나입니다.

| `type` | `detection_method` | `confidence` | `severity` | 산출 경로 |
|--------|--------------------|--------------|------------|-------------|
| `V` | `dom-verification` | `high` | High | 전용 DOM 검증 요청 |
| `V` | `reflection` | `high` | High | 반사 단계에서, 반사 응답 자체가 *이미* 실행 가능한 위치로 파싱되는 경우 |
| `V` | `oob` | `high` | High | 대역외 콜백 |
| `V` | `ast` | `high` **또는** `low` | High | 레거시 AST 승격 두 곳 — 아래 이관 절이 다루는 바로 그 불일치 |
| `A` | `ast` | `high` **또는** `low` | Medium | 그 외 모든 소스→싱크 흐름 |
| `R` | `reflection` | `low` | Info | 실행 가능 위치가 확인되지 않은 반사. `--hpp`의 중복 파라미터 반사(`inject_type: inHTML-HPP`) 포함 |
| `I` | `library` | *(없음)* | Low / Medium / High | `--detect-outdated-libs` |

의외로 받아들여지는 건 `V` + `reflection` 행입니다. `reflection`은 증거가 얼마나
약한지가 아니라 *어느 요청에서 증거가 나왔는지*를 가리킵니다. 이 행도
`dom-verification` 행과 똑같은 DOM을 파싱했고, 다만 요청을 하나 더 쓰는 대신 이미
받아둔 응답에서 했을 뿐입니다.

### `dom-verification`의 증거

페이로드가 실행 가능한 위치에 도달했음을 증명하는 다섯 경로: CSS 셀렉터로 매칭된 Dalfox 마커, 위험한 속성에 들어간 실행 가능 스킴(`javascript:`, `data:text/html`), 싱크를 호출하는 핸들러를 가진 주입된 엘리먼트, 페이로드의 범위를 포함하는 `<script>` 내부 싱크 호출, 그리고 페이로드가 감싸는 JS 문자열을 종료시킨 인라인 핸들러 브레이크아웃. 어느 것이 발동했는지는 `evidence` 필드가 알려줍니다.

### `ast`와 DOM-XSS의 천장

AST 패스는 응답에 담긴 자바스크립트를 파싱해, 위험한 소스(`location.hash`, `location.search`, `document.referrer`, `postMessage` 등)에서 온 데이터가 살균 없이 위험한 싱크(`innerHTML`, `document.write`, `eval` 등)에 도달하는지 추적합니다. 각 `<script>` 블록을 한 번 읽고 발견한 모든 흐름을 보고하므로, 명령줄에 넘기지 않은 입력이 결과에 등장할 수 있습니다 — 서버로 전송조차 되지 않는 URL 프래그먼트도 포함됩니다. `-p`로 좁혀지지 않는데, `-p`는 어떤 파라미터를 *요청*할지를 정하는 옵션이고 이 패스는 아무것도 보내지 않기 때문입니다.

이것으로 결함처럼 보이지만 아닌 결과도 설명됩니다. **순수 클라이언트 사이드 DOM-XSS**에서는 페이로드를 런타임에 자바스크립트가 페이지에 써 넣으므로 서버 응답에는 절대 나타나지 않고, 응답을 파싱하는 방식들이 찾을 대상 자체가 없습니다. `location.hash → innerHTML`만 취약한 정적 페이지라면 `--only-poc v`가 아무것도 반환하지 않는 것이 정상입니다. 브라우저에서 devtools를 켜고 POC URL을 열어 확인하세요 — Dalfox는 모든 AST 결과에 완성된 POC URL을 출력하며, URL에 담을 수 없는 소스(`window.name`, `document.referrer`, 쿠키, `postMessage` 등)에는 `[manual POC: …]` 재현 힌트를 붙입니다.

| 플래그 | 효과 |
|------|--------|
| `--skip-ast-analysis` | 소스→싱크 분석을 끕니다 |
| `--analyze-external-js` | 동일 출처 `<script src>` 번들도 가져와 분석합니다 |

`--skip-mining-dom`은 이 패스에 영향을 주지 **않습니다** — 그쪽은 HTML `id`/`name` 속성에서 파라미터 *이름*을 수집하는 작업입니다. [파라미터와 탐색](../parameters/)을 참고하세요.

## `confidence`: 주장의 근거 등급

모든 XSS 결과는 `high` 또는 `low`의 `confidence`와, 판단 신호를 나열한 `confidence_reason`을 함께 가집니다. 요청 기반 방식은 증거를 그대로 따르고, AST 결과는 흐름의 형태로 판정합니다.

`high`는 다음을 **모두** 만족해야 합니다.

- **링크만으로 공격자가 도달할 수 있는 소스** — `location.*`, `document.URL`, `URLSearchParams`는 페이로드를 URL에 직접 싣습니다. 원래라면 공격자가 제어하는 구동 페이지가 필요한 소스(`window.name`, `document.referrer`, `postMessage`, 스토리지, `history.state`)는 `low`입니다. 다만 **페이지가 그 소스를 쿼리 파라미터에서 스스로 채워 넣는 경우는 예외**로, 이때는 링크만으로도 구동되므로 `high`가 되고 근거에 `non-URL source seeded from a query parameter by the page`가 붙습니다.
- **페이지 CSP가 실행을 허용하는 페이로드** — 인라인 스크립트가 허용되거나, 싱크가 스크립트를 직접 실행해서(`eval`, `Function`, `document.write`, `<script>` 텍스트) 인라인 핸들러 권한에 의존하지 않는 경우입니다. report-only CSP는 아무것도 강제하지 않으므로 등급을 낮추지 않습니다.
- **Trusted Types에 가로막히지 않음** — `require-trusted-types-for 'script'`와 TrustedHTML 계열 싱크의 조합은 `low`입니다.

살균 함수는 판정 신호가 아닙니다. 이미 *필터*로 작동하기 때문입니다 — 분석기가 살균 함수를 taint clearer로 처리하므로, 결과가 존재한다는 것 자체가 경로에 인식된 살균이 없었다는 뜻입니다.

`confidence_reason`은 두 방향을 섞지 않습니다. `high`면 판단을 뒷받침한 신호를, `low`면 **가로막은 것만** 나열하므로 성립했던 신호는 표시되지 않습니다. 어느 쪽이든 정보성으로만 붙는 근거가 하나 있습니다 — `flow sits inside a conditional branch`는 흐름이 조건 분기 안에 있다는 기록일 뿐, 그 자체로 등급을 바꾸지 않습니다.

### 등급이 보이는 곳과 보이지 않는 곳

`confidence`는 `json`, `jsonl`, `toml`, `markdown`, `sarif`가 실어 나릅니다.
기본 `plain` 출력에는 **표시되지 않으므로**, 아래 트리아지 안내는 기계 판독
포맷을 전제로 합니다. 아직 이 값에 반응하는 동작도 없습니다 — `--only-poc`,
`--limit-result-type`, 중복 제거 순위, 종료 코드는 전부 `type`을 읽습니다.
등급은 이관의 미리보기이지 아직 제어 수단이 아닙니다.

## 이관

등급이 아직 아무것도 결정하지 않는다는 것이 핵심입니다 — 무엇이 움직이기 전에 각 결과가 어디로 갈지 미리 볼 수 있습니다.

1. **현재** — `type` 그대로. `detection_method`와 `confidence`가 추가됩니다. 선택자로서의 `type == "A"`는 deprecate되며, `detection_method == "ast"`를 쓰세요.
2. **다음** — `--tier-model confidence` opt-in.
3. **그 다음** — 그것이 기본값이 되고, `--tier-model legacy`가 탈출구로 남습니다. `A`는 은퇴합니다. `high`로 판정된 AST 결과는 `V`, 나머지는 `R`로 갑니다 — `R`이 원래 그 자리였습니다. `R`의 이름도 이때 함께 바뀝니다. 그 시점부터 반사형 외의 결과도 담게 되므로, 정확히 그 순간 단어가 맞지 않게 됩니다.

`--only-poc a`는 계속 동작합니다. 티어가 사라진 뒤에는 `detection_method == "ast"`를 선택합니다. 플래그 값은 절대 제거되지 않습니다.

과도기에는 `type`과 `confidence`가 어긋날 수 있습니다 — `type=V, confidence=low`인 결과가 나올 수 있습니다. 레거시 경로 두 곳이 근거가 부족한 상태로 AST 결과를 `V`로 승격시키기 때문입니다. 등급은 Dalfox가 실제로 주장할 수 있는 것을, 티어는 지금까지 출력해 온 것을 보고합니다. 이 불일치는 버그가 아니라 미리보기 신호입니다.

티어가 등급에서 파생되기 시작하면 티어를 읽는 모든 것이 함께 움직입니다. 같은 `--only-poc v`가 다른 집합을 고르고, 종료 코드도 다른 집합에서 뒤집히며, 중복 제거의 우선순위도 달라집니다. 이는 우회해야 할 부작용이 아니라 의도된 효과입니다.

## 여러 방식이 섞인 출력 읽기

```
INF found reflected 0 params
WRN XSS found 0 XSS (+3 A)
[POC][A][GET][DOM-XSS] https://target.app/?q=%3Cimg+src%3Dx+onerror%3D…
  ├── Issue: DOM-based XSS via URLSearchParams.get(q) to innerHTML (needs runtime confirmation)
  └── Payload: q=<img src=x onerror=alert(1) class=dlx1944740c>
```

- `found reflected 0 params` — **reflection** 방식이 서버 측 반사를 찾지 못했다는 뜻입니다. 정적 사이트에서는 당연한 결과입니다.
- `XSS found 0 XSS` — 대표 숫자는 `V`만 셉니다. `(+3 A)`가 아래에 출력될 나머지 등급을 알려줍니다.
- `[A]` 블록은 위 두 줄과 무관하게 **ast** 방식에서 나옵니다.

DOM-XSS 대상에서 요약 줄만 읽고 멈추면 보고서의 모든 결과를 놓치게 됩니다.

### 티어 합계가 발견 수와 다른 이유

출력 전에 후처리가 두 번 돌기 때문에, 티어별 개수는 스캔 중 기록된 결과 수와
같지 않습니다.

- **중복 `R` 붕괴** — 같은 대상에서 같은 `(param, inject_type)`에 `V`가 있으면
  `R`은 제거됩니다. 둘 다 남기면 같은 입력이 서로 다른 강도로 두 번 나열되기
  때문입니다. `V`와 `A`는 제거되지 않습니다.
- **AST 중복 제거** — 같은 소스→싱크 흐름을 프리플라이트, 프로브, 반사 루프가
  각각 찾을 수 있습니다. 지문당 하나만 남으며, 기준은 `type` 다음 `severity`
  입니다. `confidence`는 여기에 관여하지 않으므로 등급이 없는 `V`가 여전히
  `high`인 `A`보다 앞섭니다.

`--stream-findings`는 결과가 기록되는 즉시 내보내는데, 이는 붕괴 *이전*입니다.
따라서 스트림에 보였던 `R`이 최종 보고서에는 없을 수 있습니다. 둘이 다르면 최종
보고서가 정답입니다.

### 티어 선택: `--only-poc`와 `--limit-result-type`

둘 다 `v` / `r` / `a` / `i`를 받지만 하는 일이 다릅니다.

| 플래그 | 효과 |
|------|--------|
| `--only-poc` | **출력을 필터링합니다.** 다른 티어는 버려집니다 |
| `--limit-result-type` | **`--limit` 카운트 대상만 정합니다.** 다른 티어도 그대로 보고되며, 한도만 소모하지 않습니다 |

`--limit 2 --limit-result-type v`는 "`V` 두 개가 쌓일 때까지 스캔하고, 그 과정에서
찾은 것은 전부 보여줘"라는 뜻입니다. 나머지를 실제로 숨기려면 `--only-poc v`를
함께 주세요.

### 종료 코드

`0`은 결과 없음, `1`은 **티어와 무관하게** 결과가 하나라도 있음(`--only-poc`와 위
붕괴를 적용한 뒤 기준), `2`는 하드 에러(잘못된 입력, 모든 대상 도달 불가,
`--output` 기록 실패)입니다. `R` 하나나 `--detect-outdated-libs`가 만든 `I` 하나도
`V`와 똑같이 `1`을 냅니다. Dalfox가 악용 가능하다고 판단한 것에만 CI를 실패시키려면
`--only-poc v`를 쓰세요.

## 목적별 플래그 선택

| 목적 | 플래그 |
|------|-------|
| Dalfox가 악용 가능하다고 판단한 것만 보기 | `--only-poc v` |
| 운영 중인 대상에서 정적 분석 노이즈 억제 | `--skip-ast-analysis` |
| 이름 수집만 끄고 DOM-XSS 탐지는 유지 | `--skip-mining-dom` |
| 파라미터 하나만 테스트하되 모든 DOM 싱크는 확인 | `-p q` (`[A]`는 `-p` 범위를 따르지 않습니다) |
| 대량의 AST 결과 트리아지 | `-f json`으로 받아 `confidence`로 정렬한 뒤 `confidence_reason` 읽기 |
| 악용 가능 판단에만 CI 실패시키기 | `--only-poc v` (그렇지 않으면 어떤 티어든 `1`) |
