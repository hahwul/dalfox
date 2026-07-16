+++
title = "파라미터와 탐색"
description = "Dalfox가 중요한 입력값을 찾아내는 방식과 탐색 단계를 제어하는 방법을 설명합니다."
weight = 2
toc = true
+++

XSS를 찾는 일은 올바른 파라미터를 찾는 데서 시작합니다. Dalfox의 탐색 엔진은 여러 단계로 이루어진 파이프라인입니다. 전체를 이해할 필요는 거의 없지만, 각 구성 요소를 알아두면 스캔을 튜닝하고 싶을 때 도움이 됩니다.

## 파이프라인 개요

1. **Discovery(탐색):** URL, 본문, 헤더, 쿠키, 경로, 프래그먼트, 폼 필드에서 파라미터를 추출합니다.
2. **Mining(마이닝):** DOM 분석(JS에 내장된 파라미터 이름), 사전 워드리스트, 프레임워크별 패턴으로 확장합니다.
3. **Active probing(능동 프로빙):** 각 파라미터마다 프로브를 발사하여 어떤 특수 문자가 살아남는지 파악합니다.
4. **Fast probe(빠른 프로브):** 탐색된 파라미터마다 샌드위치 마커 요청을 한 번씩 보냅니다. 부분 반사도 전체 반사도 나타나지 않으면 해당 파라미터에 대한 무거운 페이로드 루프를 건너뜁니다.
5. **Payload generation(페이로드 생성):** 컨텍스트를 인식하는 페이로드(HTML, JS, 속성, CSS)를 생성합니다.
6. **Reflection check(반사 확인):** 페이로드를 보낸 뒤 그것이 돌아오는지 확인합니다.
7. **DOM verification(DOM 검증):** 응답을 파싱하여 페이로드가 실제 요소를 형성하는지 확인합니다. AST 기반 DOM-XSS 분석은 빠른 프로브 중에 캡처한 응답을 사용해 병렬로 실행됩니다.

## 특정 파라미터 지정하기

테스트할 파라미터를 Dalfox에 정확히 지정합니다:

```bash
dalfox https://target.app/api \
  -p q \
  -p id:query \
  -p auth:header \
  -p token:cookie
```

위치(Location): `query`, `body`, `json`, `multipart`, `cookie`, `header`. 주입 지점이 쿼리 문자열이 아닌 경우 `name:location` 형식을 사용하는 것이 좋습니다.

위치 힌트가 없는 경우(`-p q` 만 지정):

1. 탐색/마이닝이 이미 해당 이름의 파라미터를 찾았다면, 그대로 유지합니다(필터).
2. 그렇지 않으면 Dalfox가 이를 **합성(synthesize)** 합니다. 위치는 요청에서 추론하며(URL 쿼리 → 본문 → 쿠키 → 헤더), 기본값은 `query` 입니다.

즉, `-p q --skip-discovery --skip-mining` 같은 레시피도 아무것도 스캔하지 않고 조용히 지나가는 대신 여전히 `q` 를 테스트합니다.

## 워드리스트로 마이닝하기

URL에 파라미터가 없더라도 Dalfox는 흔히 쓰이는 이름을 시도해 볼 수 있습니다:

```bash
# 로컬 워드리스트
dalfox https://target.app -W ./params.txt

# 원격 워드리스트(첫 조회 이후 캐시됨)
dalfox https://target.app --remote-wordlists burp,assetnote
```

### 자동 축소(Auto-collapse)

반사가 매우 심한 사이트(예: 모든 것을 그대로 되돌려주는 검색 페이지)는 워드리스트 마이닝을 폭발적으로 늘릴 수 있습니다. Dalfox는 두 가지 방법으로 이를 방어합니다:

- **Sentinel 사전 프로브(pre-probe):** 워드리스트를 순회하기 전에, 실제 필드와 절대 충돌하지 않을 무작위 파라미터 이름 세 개를 테스트합니다. 세 개가 모두 반사되면 그 페이지는 거울(mirror)이므로 마이닝을 건너뛰고 단일 합성 `any` Query 파라미터로 대체합니다. 비용 상한: 워드리스트 크기와 무관하게 3개 요청. 사전 프로브가 이득이 될 만큼 워드리스트가 충분히 클 때(>15개 항목)만 실행됩니다.
- **EWMA 축소:** 순회하는 동안 Dalfox는 이동 반사 비율(rolling reflection ratio)을 관찰합니다. 최소 15회 시도 이후에도 그 값이 ≥85%로 유지되면 마이닝을 중단하고, 이미 수집된 Query 파라미터들을 동일한 `any` 플레이스홀더로 접어 넣습니다.

두 경로 모두 동일한 다운스트림 상태를 만듭니다. 어느 트리거가 발동했든 5~7단계에서는 하나의 Query 주입 지점만 보게 됩니다.

## 노이즈 정리하기

특정 파라미터 무시:

```bash
dalfox https://target.app --ignore-param csrf --ignore-param __RequestVerificationToken
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
# 또는 와일드카드를 사용해 인라인으로
dalfox scan urls.txt --out-of-scope '*.google.com,*.cdn.cloudflare.net'
```

## 탐색만 하고 공격하지 않기

Dry-run 모드는 페이로드를 보내지 않고 공격 계획을 탐색하여 출력합니다:

```bash
dalfox https://target.app --dry-run
```

Discovery-only 모드는 이와 비슷하지만 프로빙 단계까지 완료합니다:

```bash
dalfox https://target.app --only-discovery
```

두 모드 모두 범위 지정과 CI 사전 점검에 도움이 됩니다.

## 단계 건너뛰기

더 빠르게 진행하거나 취약한 대상을 우회하려면 파이프라인의 일부를 건너뛰세요:

| 플래그 | 건너뛰는 대상 |
|------|-------|
| `--skip-discovery` | 탐색 단계 전체 |
| `--skip-mining` | 모든 워드리스트/DOM 마이닝 |
| `--skip-mining-dict` | 사전 마이닝만 |
| `--skip-mining-dom` | DOM 마이닝만 |
| `--skip-reflection-header` | 헤더 반사 확인 |
| `--skip-reflection-cookie` | 쿠키 반사 확인 |
| `--skip-reflection-path` | 경로 반사 확인 |

## 주입 마커(Injection markers)

일부 엔드포인트는 페이로드가 특정 위치(예: JWT 내부)에 있어야 합니다. `--inject-marker` 를 사용하세요:

```bash
dalfox https://target.app/api \
  --inject-marker FUZZ \
  -d '{"filter":"FUZZ"}'
```

Dalfox는 모든 `FUZZ` 를 각 페이로드로 치환하여 요청을 보냅니다.

## 자동 사전 인코딩(Auto pre-encoding)

일부 엔드포인트는 페이로드를 원시 텍스트로 받아들이지 않습니다. 이들은 어떤 구조적 인코딩(base64, JSON, JWT 등)으로 감싸진 형태를 기대합니다. Dalfox는 탐색 중 각 파라미터의 기존 값을 검사하고, 구조를 인식하면 페이로드가 동일한 래핑을 통해 왕복(round-trip)하도록 투명한 인코딩 파이프라인을 구성합니다. 설정할 것은 없습니다. 디버그 출력에서 `pre_encoding` 또는 `pre_encoding_pipeline` 을 찾아보세요.

단일 단계 인코딩은 기존 파라미터 값에서 탐지됩니다:

| 탐지된 형태 | 페이로드 인코딩 방식 |
|----------|-------------------|
| `base64` | `BASE64(payload)` |
| `2base64` | `BASE64(BASE64(payload))` |
| `2url` / `3url` | 2회 또는 3회 URL 인코딩 |

조합 가능한 파이프라인은 값의 구조를 변환 체인으로 바꿉니다. 기존 값이 구조화된 래퍼로 디코딩되면, Dalfox는 모든 리프(leaf) 문자열 필드를 각각 별도의 가상 하위 파라미터로 열거합니다:

| 래퍼 형태 | 파이프라인 |
|---------------|----------|
| Base64로 감싼 JSON `?qs=eyJ…` | `JsonField(/leaf) → Base64` |
| Base64URL로 감싼 JSON | `JsonField(/leaf) → Base64Url` |
| 순수 URL 인코딩된 JSON `?blob=%7B…%7D` | `JsonField(/leaf)` |
| JWT/JWS `?token=h.p.s` | `JsonField(/leaf) → Base64Url → JwtAssemble` |

각 리프는 대괄호 스타일의 표시 이름을 사용해 별도의 Param으로 등록됩니다. `qs` 의 `move_url` 필드에 있는 페이로드는 `qs[move_url]` 로 표시되고, 배열 요소는 `qs[items][0]` 로 나타납니다. 와이어 수준의 치환은 여전히 원래 부모 파라미터(`qs`)를 대상으로 하므로, 요청은 서버에 정상적으로 보입니다.

JWT의 경우 원래 헤더와 서명 세그먼트는 그대로(verbatim) 보존됩니다. 서명은 수정된 페이로드와 일치하지 않으므로, 이는 토큰을 검증하지 않는 엔드포인트에서만 발동합니다. 올바르게 서명된 JWT는 탐지 결과를 반환하지 않습니다. 이는 놓친 것이 아니라 의도된 동작입니다.

대상이 Dalfox가 자동 탐지하지 못하는 래핑을 사용한다면, `--inject-marker` 로 주입 지점을 강제로 지정할 수 있습니다(아래 참조).

## 반사 프로브 형태

모든 탐색 및 마이닝 프로브는 단일 토큰 대신 샌드위치 마커(`OPEN + INNER + CLOSE`)를 보냅니다. 그런 다음 응답은 네 가지 경우 중 하나로 분류됩니다:

| 반사 | 의미 |
|------------|---------|
| **Full** | 완전한 `OPEN+INNER+CLOSE` 가 살아남음. 표준 반사. |
| **PrefixOnly** | `OPEN+INNER` 는 존재하고 `CLOSE` 가 제거됨. 접미사 제거 필터를 시사. |
| **SuffixOnly** | `INNER+CLOSE` 는 존재하고 `OPEN` 이 제거됨. 접두사 제거 필터를 시사. |
| **InnerOnly** | `INNER` 만 살아남음. 정규식 추출 또는 양쪽 래핑 모두 제거를 시사. |

네 가지 모두 "반사됨"으로 취급됩니다. 탐색은 해당 파라미터를 기록하고 스캔이 진행됩니다. 단순한 단일 토큰 확인이었다면 *Full* 을 제외한 모든 경우를 놓쳐, 접두사/접미사를 제거하는 엔드포인트를 탐지하지 못했을 것입니다. 마커 토큰은 스캔마다 고유합니다(`dlx`/`dlxmid`/`xld` 접두사에 스캔당 8자리 16진수가 붙음). 따라서 HTML에서 우연히 충돌할 가능성은 무시할 만합니다.

## 탐지 결과가 "검증됨"이 되는 기준

| 결과 | 확인 방식 |
|--------|--------------------|
| **V** (Verified, 검증됨) | Dalfox가 응답 DOM을 파싱하여 실행에 대한 직접적인 증거를 찾습니다. `evidence` 필드는 이를 입증한 경로를 태깅합니다: DOM 마커(CSS 셀렉터 적중), 실행 가능한 URL(위험한 속성 내의 `javascript:`/`data:`), HTML 구조적 증거(값이 싱크 호출인 `on*` 핸들러를 가진 주입된 요소), 또는 JS 컨텍스트 AST(파싱된 AST가 페이로드의 바이트 범위에 포함됨을 보여주는 `<script>` 내부의 싱크 호출). |
| **A** (AST-detected, AST 탐지) | 정적 JavaScript 분석이 사용자 제어 소스를 위험한 싱크로 추적함(예: `innerHTML = location.hash`). |
| **R** (Reflected, 반사됨) | 페이로드 텍스트가 응답 본문에 나타났지만 아직 DOM 증거는 없음. 여전히 수동으로 조사할 가치가 있음. |

`V` 와 `A` 는 신호입니다. `R` 은 힌트입니다.

## 안전한 컨텍스트

Dalfox는 `<textarea>`, `<title>`, `<noscript>`, `<style>`, `<xmp>`, `<plaintext>` 내부의 반사를 무시합니다. 그곳의 콘텐츠는 실행되지 않으므로, 오탐(false positive)만 발생시킬 뿐입니다.

## 다음 단계

- 페이로드가 어떻게 구성되는지는 [Payloads &amp; Encoding](../payloads/)에서 확인하세요.
- WAF를 상대하고 있나요? [WAF Bypass](../waf-bypass/)로 이동하세요.
