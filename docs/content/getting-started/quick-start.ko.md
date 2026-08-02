+++
title = "빠른 시작"
description = "5분 만에 첫 Dalfox 스캔을 실행합니다."
weight = 3
toc = true
+++

이 페이지는 설치부터 검증된 탐지 결과까지 단계별로 안내합니다. 실제 출력을 확인할 수 있도록 의도적으로 취약하게 만든 데모 대상을 사용합니다.

{{ alert(type="warning", body="테스트 권한이 있는 대상만 스캔하세요. Dalfox는 실제 XSS 페이로드를 전송합니다.") }}

## 1. 단일 URL 스캔

```bash
dalfox https://xss-game.appspot.com/level1/frame?query=test
```

첫 번째 인자가 대상입니다. Dalfox는 이것이 URL임을 알아보고 `scan` 서브커맨드를 자동으로 붙여 실행합니다. 실행하면 이런 것들이 보입니다.

- 버전이 적힌 배너.
- 파라미터를 찾고 컨텍스트를 살피는 동안 찍히는 `INFO` 라인.
- 결과마다 붙는 `[V]`(취약), `[R]`(반사됨) 라인과 실제로 통한 페이로드.

## 2. 파일에서 스캔

크롤러가 뽑아둔 URL 목록을 그대로 넘기세요.

```bash
# urls.txt, one target per line
dalfox scan urls.txt
```

URL마다 같은 파이프라인을 거칩니다. 결과는 찾는 즉시 흘러나옵니다.

## 3. 파이프라인에서 스캔

파이프로 입력하면 Dalfox는 `stdin`에서 읽습니다.

```bash
cat urls.txt | dalfox
# or combined with your recon tools:
waybackurls example.com | gf xss | dalfox
```

## 4. JSON 출력 얻기

`jq`나 대시보드, CI에 그대로 물려 쓰세요.

```bash
dalfox https://target.app/search?q=test -f json -o report.json
```

기계 판독 형식(`json`, `jsonl`, `sarif`, `toml`)은 배너를 자동으로 끄기 때문에 파일이 깔끔하게 남습니다.

## 5. 인증이 필요한 스캔

쿠키나 헤더, 커스텀 메서드를 함께 넘기면 됩니다.

```bash
dalfox https://api.target.app/v1/users \
  -X POST \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}' \
  --cookies "session=abc123"
```

프록시로 잡아둔 **raw HTTP 요청** 파일을 그대로 물려도 됩니다.

```bash
dalfox scan --input-type raw-http request.txt
```

브라우저 DevTools나 프록시에서 뽑은 **HAR** 전체를 다시 흘려보낼 수도 있습니다. Dalfox는 그 안의 모든 요청을 스캔하며, 각 요청의 메서드, 헤더, 쿠키, 본문을 그대로 살립니다.

```bash
dalfox scan capture.har            # auto-detected
dalfox scan --input-type har capture.har
```

## 6. Blind XSS 탐지

대역외 콜백(Interactsh, Burp Collaborator, XSS Hunter 등)을 씁니다.

```bash
dalfox https://target.app \
  -b https://your-callback.interact.sh
```

Dalfox는 찾아낸 모든 파라미터에 blind-XSS 페이로드를 심습니다. 나중에 관리자 패널에서 페이로드가 터지면 콜백 서버가 그것을 기록합니다.

[interactsh](https://github.com/projectdiscovery/interactsh)(OAST) 서버 관리를 Dalfox에 맡길 수도 있습니다. 세션을 등록하고, 콜백을 원본 페이로드와 연결 짓고, 알아서 폴링합니다.

```bash
dalfox https://target.app --blind-oob                  # public interactsh mesh
dalfox https://target.app --blind-oob=oast.fun         # pick servers
```

자체 호스팅 서버라면 `--blind-oob-secret`을 쓰고, 스캔이 끝난 뒤 폴링을 얼마나 더 이어갈지는 `--blind-oob-wait`으로 정합니다.

## 7. 먼저 Dry-run 실행

`--dry-run`으로 Dalfox가 무엇을 스캔할지 미리 봅니다.

```bash
dalfox https://target.app --dry-run
```

페이로드는 하나도 쏘지 않은 채 파라미터를 찾고 요청량만 가늠합니다.

## 출력 읽기

각 탐지 결과에는 태그가 붙습니다.

| 태그 | 의미 |
|-----|---------|
| `[V]` | **취약(Vulnerable)**: 파싱된 응답에서 페이로드가 실제 DOM 요소로 확인됨(Dalfox 마커에 대한 CSS 셀렉터 매칭) |
| `[A]` | **AST 탐지(AST-detected)**: 정적 JS 분석에서 source→sink 흐름을 발견함 |
| `[R]` | **반사됨(Reflected)**: 페이로드가 응답에 나타났으나 DOM 증거는 없음 |

`V`와 `A`는 바로 조치할 수 있는 결과입니다. `R`은 한 번 볼 만하지만 이후 단계에서 더 걸러질 수 있습니다.

`[V]`는 브라우저 실행이 아닙니다. Dalfox는 설계상 브라우저를 구동하지 않습니다. 순수 클라이언트 사이드 DOM-XSS는 지금은 `[A]`로 보고되니 브라우저에서 직접 확인해 보세요. 각 결과에는 `detection_method`(어떻게 찾았는지)와 `confidence`(취약점이라고 주장할 수 있는지)도 함께 실립니다 — [탐지 모델](../../guide/detection-model/) 문서를 참고하세요.

## 다음 단계

- 다양한 [스캐닝 모드](../../guide/scanning-modes/)를 알아보세요.
- [파라미터가 어떻게 탐색되는지](../../guide/parameters/) 이해하세요.
- 까다로운 대상을 위해 [페이로드와 인코더](../../guide/payloads/)를 조정하세요.
- 즐겨 쓰는 플래그를 [설정 파일](../configuration/)에 저장하세요.
