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

`[A]`는 이 분리보다 먼저 만들어졌습니다. `type` 필드에 앉아 있으면서 *방식* 질문에 답하기 때문에, 코드를 포함해 누구도 이것이 신뢰도 척도에서 어디에 속하는지 말할 수 없었습니다. 아래 **이관** 절에 따라 흡수될 예정입니다.

이 페이지는 그 구분이 출력만 봐서는 드러나지 않기 때문에 존재합니다. [이슈 #1238](https://github.com/hahwul/dalfox/issues/1238)에서 [@OSTARA711](https://github.com/OSTARA711)과 정리한 내용을 토대로 작성했습니다.

## 신뢰도: `type`의 의미

| 태그 | 이름 | 의미 |
|-----|------|-------|
| `V` | **Vulnerable(취약)** | Dalfox가 이 입력이 악용 가능하다고 판단합니다. 조치하세요. |
| `R` | **Review(검토 필요)** | 취약점이라고 주장할 수준에는 이르지 못한 신호입니다. 직접 확인하세요. |
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

- **URL에 실리는 소스** — `location.*`, `document.URL`, `URLSearchParams`. 링크 하나로 발동합니다. 공격자가 제어하는 구동 페이지가 필요한 소스(`window.name`, `document.referrer`, `postMessage`, 스토리지, `history.state`)는 `low`입니다. 실재하지만 URL 전송만으로는 도달할 수 없습니다.
- **페이지 CSP가 실행을 허용하는 페이로드** — 인라인 스크립트가 허용되거나, 싱크가 스크립트를 직접 실행해서(`eval`, `Function`, `document.write`, `<script>` 텍스트) 인라인 핸들러 권한에 의존하지 않는 경우입니다. report-only CSP는 아무것도 강제하지 않으므로 등급을 낮추지 않습니다.
- **Trusted Types에 가로막히지 않음** — `require-trusted-types-for 'script'`와 TrustedHTML 계열 싱크의 조합은 `low`입니다.

살균 함수는 판정 신호가 아닙니다. 이미 *필터*로 작동하기 때문입니다 — 분석기가 살균 함수를 taint clearer로 처리하므로, 결과가 존재한다는 것 자체가 경로에 인식된 살균이 없었다는 뜻입니다.

## 이관

`confidence`는 지금 보고되지만 아직 `type`을 결정하지 않습니다. 그게 핵심입니다 — 아무것도 움직이기 전에 각 결과가 어디로 갈지 미리 볼 수 있습니다.

1. **현재** — `type` 그대로. `detection_method`와 `confidence`가 추가됩니다. 선택자로서의 `type == "A"`는 deprecate되며, `detection_method == "ast"`를 쓰세요.
2. **다음** — `--tier-model confidence` opt-in.
3. **그 다음** — 그것이 기본값이 되고, `--tier-model legacy`가 탈출구로 남습니다. `A`는 은퇴합니다. `high`로 판정된 AST 결과는 `V`, 나머지는 `R`로 갑니다 — `R`이 원래 그 자리였습니다.

`--only-poc a`는 계속 동작합니다. 티어가 사라진 뒤에는 `detection_method == "ast"`를 선택합니다. 플래그 값은 절대 제거되지 않습니다.

과도기에는 `type`과 `confidence`가 어긋날 수 있습니다 — `type=V, confidence=low`인 결과가 나올 수 있습니다. 레거시 경로 두 곳이 근거가 부족한 상태로 AST 결과를 `V`로 승격시키기 때문입니다. 등급은 Dalfox가 실제로 주장할 수 있는 것을, 티어는 지금까지 출력해 온 것을 보고합니다. 이 불일치는 버그가 아니라 미리보기 신호입니다.

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

## 목적별 플래그 선택

| 목적 | 플래그 |
|------|-------|
| Dalfox가 악용 가능하다고 판단한 것만 보기 | `--only-poc v` |
| 운영 중인 대상에서 정적 분석 노이즈 억제 | `--skip-ast-analysis` |
| 이름 수집만 끄고 DOM-XSS 탐지는 유지 | `--skip-mining-dom` |
| 파라미터 하나만 테스트하되 모든 DOM 싱크는 확인 | `-p q` (`[A]`는 `-p` 범위를 따르지 않습니다) |
| 대량의 AST 결과 트리아지 | `confidence`로 정렬한 뒤 `confidence_reason` 읽기 |
