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

첫 번째 인자가 대상입니다. Dalfox는 이것이 URL임을 자동으로 감지하여 `scan` 서브커맨드를 암묵적으로 실행합니다. 다음과 같은 내용이 표시됩니다.

- 버전이 포함된 배너.
- Dalfox가 파라미터를 탐색하고 컨텍스트를 탐지하는 과정의 `INFO` 라인.
- 각 탐지 결과에 대한 `[V]`(검증됨) 및 `[R]`(반사형) 라인과, 동작한 정확한 페이로드.

## 2. 파일에서 스캔

크롤러가 수집한 URL 목록을 입력합니다.

```bash
# urls.txt, one target per line
dalfox scan urls.txt
```

각 URL은 동일한 파이프라인을 거칩니다. 결과는 발견되는 대로 스트리밍됩니다.

## 3. 파이프라인에서 스캔

파이프로 입력하면 Dalfox는 `stdin`에서 읽습니다.

```bash
cat urls.txt | dalfox
# or combined with your recon tools:
waybackurls example.com | gf xss | dalfox
```

## 4. JSON 출력 얻기

Dalfox를 `jq`, 대시보드 또는 CI와 함께 사용합니다.

```bash
dalfox https://target.app/search?q=test -f json -o report.json
```

기계가 읽을 수 있는 형식(`json`, `jsonl`, `sarif`, `toml`)은 배너를 자동으로 억제하여 파일이 깔끔하게 유지됩니다.

## 5. 인증이 필요한 스캔

쿠키, 헤더 또는 커스텀 메서드를 전달합니다.

```bash
dalfox https://api.target.app/v1/users \
  -X POST \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}' \
  --cookies "session=abc123"
```

또는 프록시에서 캡처한 **raw HTTP 요청** 파일을 Dalfox에 지정할 수 있습니다.

```bash
dalfox scan --input-type raw-http request.txt
```

또는 전체 **HAR** 내보내기(브라우저 DevTools 또는 프록시에서 생성)를 재생할 수 있습니다. Dalfox는 그 안의 모든 요청을 스캔하며, 각 요청의 메서드, 헤더, 쿠키, 본문을 그대로 보존합니다.

```bash
dalfox scan capture.har            # auto-detected
dalfox scan --input-type har capture.har
```

## 6. Blind XSS 탐지

아웃오브밴드 콜백(Interactsh, Burp Collaborator, XSS Hunter 등)을 사용합니다.

```bash
dalfox https://target.app \
  -b https://your-callback.interact.sh
```

Dalfox는 탐색된 모든 파라미터에 blind-XSS 페이로드를 전송합니다. 나중에 관리자 패널에서 페이로드가 실행되면, 콜백 서버가 이를 기록합니다.

또는 Dalfox가 [interactsh](https://github.com/projectdiscovery/interactsh)(OAST) 서버를 대신 관리하도록 할 수 있습니다. 세션을 등록하고, 콜백을 원본 페이로드와 연관 짓고, 자동으로 폴링합니다.

```bash
dalfox https://target.app --blind-oob                  # public interactsh mesh
dalfox https://target.app --blind-oob=oast.fun         # pick servers
```

자체 호스팅 서버에는 `--blind-oob-secret`을 사용하고, 스캔 완료 후 Dalfox가 폴링을 계속하는 시간을 제어하려면 `--blind-oob-wait`을 사용합니다.

## 7. 먼저 Dry-run 실행

`--dry-run`을 사용하여 Dalfox가 무엇을 스캔할지 미리 확인합니다.

```bash
dalfox https://target.app --dry-run
```

페이로드를 전혀 전송하지 않고 파라미터를 탐색하고 요청량을 추정합니다.

## 출력 읽기

각 탐지 결과에는 태그가 붙습니다.

| 태그 | 의미 |
|-----|---------|
| `[V]` | **검증됨(Verified)**: 페이로드가 실제 DOM 요소를 생성함(AST/CSS 셀렉터 매칭을 통해) |
| `[A]` | **AST 탐지(AST-detected)**: 정적 JS 분석에서 source→sink 흐름을 발견함 |
| `[R]` | **반사형(Reflected)**: 페이로드가 응답에 나타났으나 DOM 증거는 없음 |

`V` 및 `A` 탐지 결과는 실질적으로 조치가 가능합니다. `R` 탐지 결과는 살펴볼 가치가 있으나 이후 단계에서 추가로 필터링될 수 있습니다.

## 다음 단계

- 다양한 [스캐닝 모드](../../guide/scanning-modes/)를 알아보세요.
- [파라미터가 어떻게 탐색되는지](../../guide/parameters/) 이해하세요.
- 까다로운 대상을 위해 [페이로드와 인코더](../../guide/payloads/)를 조정하세요.
- 즐겨 쓰는 플래그를 [설정 파일](../configuration/)에 저장하세요.
