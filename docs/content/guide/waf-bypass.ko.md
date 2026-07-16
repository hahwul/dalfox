+++
title = "WAF 우회"
description = "WAF를 자동으로 탐지하고 WAF별 회피 전략을 적용합니다."
weight = 4
toc = true
+++

대부분의 실제 대상은 WAF 뒤에 있습니다. Dalfox는 WAF를 핑거프린트한 뒤, 회피 전략을 자동으로 선택합니다. 해당 WAF의 규칙에 맞춰 조정된 추가 인코더와 페이로드 변형이 그것입니다.

## 동작 방식

1. Dalfox는 대상에 소수의 **핑거프린트 프로브**를 보냅니다.
2. 알려진 WAF 시그니처가 나타나면(`cf-ray` 같은 헤더, "Attention required!" 같은 본문 마커, 또는 429/403 형태), Dalfox는 해당 WAF와 그 신뢰도를 기록합니다.
3. 스캐너는 WAF의 **추가 인코더**를 여러분의 인코더 목록에 병합하고, WAF의 **변형 목록**을 페이로드 생성기에 추가합니다.
4. 페이로드 변형은 상한이 있습니다(기본 페이로드당 4개 변형). 요청량이 과도해지지 않도록 하기 위함입니다. 이 상한은 WAF가 탐지된 후에만 적용되므로, 추가 노력이 정확히 그것을 필요로 하는 스캔에만 투입됩니다.

이 모든 것은 기본적으로 켜져 있습니다. 비활성화하거나 방향을 조정하고 싶을 때만 플래그를 건드리면 됩니다.

## 지원하는 WAF

- Cloudflare
- AWS WAF
- Akamai
- Imperva / Incapsula
- ModSecurity
- OWASP CRS
- Sucuri
- F5 BIG-IP
- Barracuda
- FortiWeb
- Azure WAF
- Google Cloud Armor
- Fastly
- Wordfence

인식되지 않는 WAF는 일반 폴백 전략을 발동시킵니다.

## 동작 조정하기

### Auto (기본값)

```bash
dalfox https://target.app
# equivalent to:
dalfox https://target.app --waf-bypass auto
```

### 특정 WAF 강제 지정

핑거프린팅을 건너뛰고 선택한 WAF의 전략을 직접 적용합니다:

```bash
dalfox https://target.app \
  --waf-bypass force \
  --force-waf cloudflare
```

WAF가 자신의 헤더를 감추거나 CDN 뒤에 있을 때 유용합니다.

### WAF 로직 비활성화

```bash
dalfox https://target.app --waf-bypass off
```

추가 인코더도, 변형도 없습니다. 여러분이 설정한 페이로드만 사용합니다.

### 프로브 건너뛰기

```bash
dalfox https://target.app --skip-waf-probe
```

헤더 기반 수동 탐지는 여전히 사용하지만, 도발성 요청은 보내지 않습니다. 대상이 불안정하고 프로브에 rate limit을 소모하고 싶지 않을 때 사용하세요.

### 회피 스로틀

WAF가 탐지되면 `--waf-evasion`은 Dalfox를 무딘 감속 대신 **적응형 타이밍**으로 전환합니다. 요청 간 간격을 무작위화(지터)하여 그 주기를 핑거프린트할 수 없게 만들고, 차단된 응답(403/406/429/503)이 무리 지어 나타날 때마다 쿨다운 정지를 점증시킵니다. WAF별 페이싱 힌트도 탐지 시 자동으로 적용되며, 이 플래그가 없어도 마찬가지입니다.

```bash
dalfox https://target.app --waf-evasion
```

요청 속도에 대한 확고한 상한 — WAF 탐지와 무관하며 **모든** 워커와 대상에 걸쳐 공유되는 — 을 원한다면 `--rate-limit`(초당 요청 수)과 결합하세요. `--delay`는 단일 워커의 간격만 벌리므로, 공유 IP 뒤에서 스캔하거나 전역 임계값을 가진 엣지 WAF를 상대할 때 바로 이 손잡이가 적합합니다:

```bash
# At most 15 requests/second across the whole scan, with adaptive evasion
dalfox https://target.app --rate-limit 15 --waf-evasion
```

일시적 실패(5xx, 타임아웃, 연결 리셋)는 `--retries` / `--retry-delay`로 재시도할 수 있습니다. HTTP 429는 항상 재시도되며 `Retry-After`가 반영됩니다.

### 약한 핑거프린트 걸러내기

각 핑거프린트는 신뢰도 점수(0.0–1.0)를 가집니다. `Request blocked`(0.3)나 `Server: Google Frontend`(0.15) 같은 일반적인 마커는 때때로 무해한 오리진에서 오탐을 냅니다. `--waf-min-confidence`를 사용해 임계값 미만의 항목을 모두 버리세요:

```bash
# Keep only confident matches (drops 0.3/0.15 noise)
dalfox https://target.app --waf-min-confidence 0.7
```

기본값은 `0.3`입니다(`Server: Google Frontend` 같은 약하거나 일반적인 매치를 억제합니다). `--waf-min-confidence 0.0`을 넘기면 모든 매치를 유지하며, 잡음이 많은 수동 탐지가 Dalfox를 잘못된 회피 전략으로 몰고 간다고 의심될 때는 값을 높이세요.

## 변형 전술 (내부 동작)

WAF마다 각기 다른 수법에 무너집니다. 작은 샘플을 소개합니다:

| 변형 | 예시 | 효과적인 대상 |
|----------|---------|---------------|
| **HTML 주석 분할** | `<scr<!---->ipt>` | 시그니처 정규식 |
| **JS 주석 분할** | `al/**/ert(1)` | 키워드 필터 |
| **백틱 호출** | `` alert`1` `` | `alert(` 정규식 |
| **생성자 체인** | `[].constructor.constructor('alert(1)')()` | 강력한 키워드 차단 |
| **유니코드 JS 이스케이프** | `alert(1)` | JS 토큰 필터 |
| **슬래시 구분자** | `<svg/onload=alert(1)/class=x>` | CRS 941160 |
| **SVG animate** | `<svg><animate onbegin=alert(1) attributeName=x>` | CRS 941110 |
| **HTML 엔티티 괄호** | `alert&#40;1&#41;` | CRS 941370 |
| **이색적인 공백** | 폼 피드 / 수직 탭 | CRS 941320 |
| **대소문자 교대** | `<ScRiPt>` | 대소문자 구분 규칙 |
| **zwsp 삽입** | `al​ert(1)` | 렉서 기반 탐지 |
| **키워드 엔티티 인코딩** | `onerror=&#97;lert(1)` | `alert`/핸들러 키워드 정규식(속성 디코딩됨) |
| **멀티 슬래시** | `<img/src=x/onerror=alert(1)>` | 이후 속성 사이의 `\s`에 고정된 정규식 |
| **스킴 분리** | `href=java&#9;script:alert(1)` | 리터럴 `javascript:` 스킴 정규식(URL 파서가 TAB을 제거) |
| **엔티티 스킴** | `href=&#106;avascript:alert(1)` | 리터럴 `javascript:` 스킴 정규식(속성 디코딩됨) |

마지막 네 가지는 HTML 토크나이저가 URL 파서나 이벤트 핸들러 JS 컴파일러가 보기 전에 **속성 값 안의** 문자 참조를 디코딩한다는 점을 악용합니다. 이들은 속성 / 이벤트 핸들러 / `javascript:`-URL 컨텍스트에서만 발동하며, 엔티티 디코딩이 일어나지 않는 순수 본문 텍스트와 `<script>`/`<style>` 페이로드에서는 건너뜁니다.

이들을 직접 설정하지는 않습니다. WAF별로 자동으로 선택됩니다. 무슨 일이 벌어지는지 확인하려면 `--debug`로 실행하세요.

## 검사 윈도우 오버플로

일부 WAF(예: AWS WAF 스타일 설정)는 파라미터 값의 **첫 N바이트**만 검사합니다. 값의 시작 부분에 있는 벡터는 차단을 유발하지만, 동일한 벡터가 검사 윈도우를 넘어서 밀려나면 손대지 않은 채로 반사됩니다.

능동 프로빙 중에 파라미터의 특수 문자 프로브가 완전히 차단된 채로 돌아오면, Dalfox는 긴 무해한 필러 접두어 뒤에 그것을 다시 시도합니다. 이제 문자가 반사되면, 값이 크기 제한된 검사 윈도우 뒤에 있다고 결론짓고 해당 파라미터의 모든 페이로드 앞에 그 필러를 자동으로 붙입니다. 그러면 실제 벡터가 항상 윈도우 너머에 도달합니다. 보고되는 PoC URL에는 필러가 포함되므로 그대로 재현됩니다. 이것은 자동이며 설정할 것이 없습니다.

## 인코더와 결합하기

여러분의 `--encoders` 목록과 WAF의 추가 인코더가 병합됩니다. 예를 들면:

```bash
dalfox https://target.app -e url,base64
# Cloudflare detected → extra encoders: unicode, zwsp
# Effective: url, base64, unicode, zwsp
```

중복을 자동으로 제거하고 순서를 보존합니다.

## Rate 제한 & 백오프

Dalfox는 연속된 WAF 차단을 추적하고 영구 차단을 피하기 위해 지수적 슬립으로 자동 백오프합니다. 취약한 대상에 대해서는 `--delay`(요청당 밀리초)와 더 작은 `--workers`로 도울 수 있습니다.

```bash
dalfox https://target.app --delay 500 --workers 10
```

## 디버깅

디버그 스트림을 켜서 핑거프린트 판단과 활성 전략을 확인하세요:

```bash
dalfox --debug https://target.app 2>&1 | grep -i waf
```

## 다음

- [저장형 XSS](../stored-xss/)는 여기서-주입-저기서-검증 패턴을 다루며, 이는 종종 WAF와 상호작용합니다.
- [출력 & 리포트](../output/)는 탐지 결과를 파이프라인에 통합하는 방법을 다룹니다.
