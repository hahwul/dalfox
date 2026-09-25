+++
title = "WAF 우회"
description = "WAF를 자동으로 탐지하고 WAF별 회피 전략을 적용합니다."
weight = 4
toc = true
+++

대부분의 실제 대상은 WAF 뒤에 있습니다. Dalfox는 WAF를 핑거프린트한 뒤, 회피 전략을 자동으로 선택합니다. 해당 WAF의 규칙에 맞춰 조정된 추가 인코더와 페이로드 변형이 그것입니다.

## 동작 방식

1. Dalfox는 프리플라이트 응답의 헤더와 본문을 핑거프린트 규칙과 대조한 뒤(추가 요청 없음), **자극 프로브** 하나를 보냅니다. 대상의 원래 요청에 `dalfox_waf_probe=<script>alert(1)</script>`를 쿼리로 덧붙인 것입니다.
2. 알려진 WAF 시그니처가 나타나면(`cf-ray` 같은 헤더, "Attention required!" 같은 본문 마커), Dalfox는 해당 WAF와 그 신뢰도를 기록합니다. 프로브가 알아볼 만한 시그니처 없이 403/406/429/503으로 응답하면 알 수 없는 WAF로 기록합니다. 단, 평범한 프리플라이트 요청도 이미 같은 상태 코드를 받았거나(인증 벽, 점검 페이지) 429에 `Retry-After`가 붙어 있으면(단순 rate limit) 제외합니다.
3. 스캐너는 WAF의 **추가 인코더**를 인코더 목록에 병합하고, WAF의 **변형 목록**을 페이로드 생성기에 추가합니다.
4. 페이로드 변형은 상한이 있습니다(기본 페이로드당 4개 변형). 요청량이 과도해지지 않도록 하기 위함입니다. 이 상한은 WAF가 탐지된 뒤에만 적용되므로, 추가 비용은 정말 필요한 스캔에만 들어갑니다.

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
- Citrix NetScaler
- Wallarm
- NAXSI
- SafeLine

Wallarm, NAXSI, SafeLine은 핑거프린트는 되지만 전용 전략이 없으며, 인식되지 않는 WAF와 마찬가지로 범용 폴백 전략을 적용합니다.

## 동작 조정하기

### Auto (기본값)

```bash
dalfox scan https://target.app
# 다음과 같음:
dalfox scan https://target.app --waf-bypass auto
```

### 특정 WAF 강제 지정

핑거프린팅 결과를 선택한 WAF(신뢰도 `1.0`)로 대체하고 그 전략을 적용합니다:

```bash
dalfox scan https://target.app \
  --waf-bypass force \
  --force-waf cloudflare
```

WAF가 자신의 헤더를 감추거나 CDN 뒤에 있을 때 유용합니다. WAF를 고르는 것은 `--force-waf`입니다. `auto`에서도 적용되며, `--force-waf` 없이 `--waf-bypass force`만 주면 `auto`와 똑같이 동작합니다. `--skip-waf-probe`를 함께 주지 않으면 자극 프로브는 여전히 전송됩니다.

허용되는 이름(대소문자 무시): `cloudflare`/`cf`, `aws`/`awswaf`/`aws-waf`, `akamai`, `imperva`/`incapsula`, `modsecurity`/`modsec`, `owasp-crs`/`owaspcrs`/`crs`, `sucuri`, `f5`/`bigip`/`f5-bigip`, `barracuda`, `fortiweb`/`forti`, `azure`/`azurewaf`/`azure-waf`, `cloudarmor`/`cloud-armor`/`gcp`, `fastly`, `wordfence`, `citrix`/`netscaler`. 그 밖의 값은 거부됩니다.

### WAF 로직 비활성화

```bash
dalfox scan https://target.app --waf-bypass off
```

추가 인코더, 변형, WAF별 페이싱, 자극 프로브가 모두 없습니다. 직접 설정한 페이로드만 사용합니다. 프리플라이트 응답에 대한 패시브 탐지는 여전히 실행되므로, 탐지된 WAF는 `target_summary`에 그대로 보고됩니다.

### 프로브 건너뛰기

```bash
dalfox scan https://target.app --skip-waf-probe
```

프리플라이트 응답의 헤더와 본문에 대한 패시브 탐지는 여전히 사용하지만, WAF를 자극하는 요청은 보내지 않습니다. 대상이 불안정하고 프로브에 rate limit을 소모하고 싶지 않을 때 사용하세요.

### 회피 스로틀

`--waf-evasion`은 Dalfox를 단순한 감속 대신 **적응형 타이밍**으로 전환합니다. 요청 간 간격을 무작위화(지터)하여 그 주기를 핑거프린트할 수 없게 만들고, 차단된 응답(403/406/429/503)이 무리 지어 나타날 때마다 쿨다운 대기 시간을 늘려 갑니다. 지터는 WAF 탐지 여부와 관계없이 적용됩니다. `--delay`도 WAF 페이싱 힌트도 없으면 대기 시간은 매번 75~225 ms 사이가 됩니다. 이 플래그를 주면 각 파라미터의 페이로드도 동시에 보내지 않고 하나씩 보냅니다. WAF별 페이싱 힌트(예: Cloudflare는 요청당 100 ms, 429/503 프로브 응답만으로 WAF를 추정한 경우 1.5 s)는 탐지 시 자동으로 적용되며, 이 플래그가 없어도 마찬가지입니다.

```bash
dalfox scan https://target.app --waf-evasion
```

WAF 탐지와 무관하게 **모든** 워커와 대상에 걸쳐 공유되는 절대적인 요청 속도 상한을 원한다면 `--rate-limit`(초당 요청 수)과 결합하세요. `--delay`는 단일 워커의 간격만 벌리므로, 공유 IP 뒤에서 스캔하거나 전역 임계값을 가진 엣지 WAF를 상대할 때 바로 이 옵션이 적합합니다:

```bash
# 스캔 전체에서 초당 최대 15건, 적응형 회피 사용
dalfox scan https://target.app --rate-limit 15 --waf-evasion
```

일시적 실패(5xx, 타임아웃, 연결 리셋)는 `--retries` / `--retry-delay`로 재시도할 수 있습니다. HTTP 429는 항상 재시도되며 `Retry-After`가 반영됩니다.

### 약한 핑거프린트 걸러내기

각 핑거프린트는 신뢰도 점수(0.0–1.0)를 가집니다. `Request blocked`(0.3)나 `Server: Google Frontend`(0.15) 같은 일반적인 마커는 때때로 무해한 오리진에서 오탐을 냅니다. `--waf-min-confidence`를 사용해 임계값 미만의 항목을 모두 버리세요:

```bash
# 신뢰도 높은 매치만 유지(0.3/0.15 잡음 제거)
dalfox scan https://target.app --waf-min-confidence 0.7
```

기본값은 `0.3`입니다(`Server: Google Frontend` 같은 약하거나 일반적인 매치를 억제합니다). `--waf-min-confidence 0.0`을 넘기면 모든 매치를 유지하며, 잡음이 많은 패시브 탐지가 Dalfox를 잘못된 회피 전략으로 몰고 간다고 의심될 때는 값을 높이세요.

## 변형 전술 (내부 동작)

WAF마다 통하는 수법이 다릅니다. 몇 가지 예를 들면:

| 변형 | 예시 | 효과적인 대상 |
|----------|---------|---------------|
| **HTML 주석 분할** | `<scr<!---->ipt>` | 시그니처 정규식 |
| **백틱 호출** | `` alert`1` `` | `alert(` 정규식 |
| **생성자 체인** | `[].constructor.constructor('alert(1)')()` | 광범위한 키워드 차단 |
| **유니코드 JS 이스케이프** | `\u0061lert(1)` | JS 토큰 필터 |
| **슬래시 구분자** | `<svg/onload=alert(1) class=x>` | CRS 941160 |
| **SVG animate** | `<svg><animate onbegin=alert(1) attributeName=x>` | CRS 941110 |
| **HTML 엔티티 괄호** | `alert&#40;1&#41;` | CRS 941370 |
| **특수 공백 문자** | 폼 피드 / 수직 탭 | CRS 941320 |
| **대소문자 섞기** | `<ScRiPt>` | 대소문자 구분 규칙 |
| **zwsp 삽입** (인코더) | `<` `>` `"` `'` `(` `)` `/` `;` 뒤에 U+200B | 렉서 기반 탐지 |
| **키워드 엔티티 인코딩** | `onerror=&#97;lert(1)` | `alert`/핸들러 키워드 정규식(속성 디코딩됨) |
| **멀티 슬래시** | `<img/src="x"/onerror="alert(1)"/class=x>` | 이후 속성 사이의 `\s`에 고정된 정규식 |
| **스킴 분리** | `href=java&#9;script:alert(1)` | 리터럴 `javascript:` 스킴 정규식(URL 파서가 TAB을 제거) |
| **엔티티 스킴** | `href=&#106;avascript:alert(1)` | 리터럴 `javascript:` 스킴 정규식(속성 디코딩됨) |

슬래시 구분자는 HTML 토크나이저가 새 속성을 시작하는 위치에서만 생성됩니다. 따옴표 없는 값 뒤의 슬래시는 그 값의 일부가 되므로 해당 구분자의 공백을 유지합니다. 키워드 엔티티 인코딩, 스킴 분리, 엔티티 스킴은 URL 파서나 이벤트 핸들러 JS 컴파일러가 보기 전에 HTML 토크나이저가 **속성 값 안의** 문자 참조를 디코딩한다는 점을 악용합니다. Dalfox는 이 엔티티 변형을 속성, 이벤트 핸들러, `javascript:`-URL 위치에서만 사용하며, 엔티티 디코딩이 일어나지 않는 순수 본문 텍스트와 `<script>`/`<style>` 페이로드에서는 건너뜁니다.

JavaScript 주석은 식별자를 이어 붙이지 않고 토큰 경계로 처리되므로, Dalfox는 `al/**/ert`처럼 식별자 안에 주석을 넣지 않습니다. 해당 형태로는 `alert`를 호출할 수 없어 낭비되는 변형을 건너뜁니다.

이들을 직접 설정하지는 않습니다. WAF별로 자동으로 선택됩니다. 무슨 일이 벌어지는지 확인하려면 `--debug`로 실행하세요.

## 검사 윈도우 오버플로

일부 WAF(예: AWS WAF 스타일 설정)는 파라미터 값의 **첫 N바이트**만 검사합니다. 값의 시작 부분에 있는 벡터는 차단을 유발하지만, 같은 벡터라도 검사 윈도우 너머로 밀어내면 그대로 반사됩니다.

능동 프로빙 중에 파라미터의 특수 문자 프로브가 완전히 차단된 채로 돌아오면, Dalfox는 길고 무해한 필러 접두어를 앞에 붙여 다시 시도합니다. 이제 문자가 반사되면, 값이 크기 제한된 검사 윈도우 뒤에 있다고 결론짓고 해당 파라미터의 모든 페이로드 앞에 그 필러를 자동으로 붙입니다. 그러면 실제 벡터가 항상 윈도우 너머에 도달합니다. 보고되는 PoC URL에는 필러가 포함되므로 그대로 재현됩니다. 이것은 자동이며 설정할 것이 없습니다.

## 인코더와 결합하기

WAF의 추가 인코더는 `--encoders` 목록 위에 더해집니다.

```bash
dalfox scan https://target.app -e url,base64
# Cloudflare 탐지 → 추가 인코더: unicode, 4url, zwsp
# 실제 적용: url, base64, 그 위에 unicode, 4url, zwsp
```

추가 인코더는 사용자 인코더가 이미 만든 목록 전체에 적용되므로, url 인코딩 변형과 base64 변형에도 `unicode` / `4url` / `zwsp` 형태가 생깁니다. 중복은 제거됩니다. 구조 변형은 그대로 보냅니다. 변형한 페이로드를 WAF 인코더에 다시 통과시키지 않으므로, 이 두 종류의 변형은 곱해지지 않고 더해집니다.

## 요청 속도 제한과 백오프

Dalfox는 파라미터별로 연속된 차단 응답(403/406/429/503)을 추적합니다. 연속 차단이 세 번째에 이른 시점부터 429나 503이 올 때마다 영구 차단을 피하기 위해 지수적으로 대기합니다(2 s에서 시작해 두 배씩, 최대 30 s). 403이나 406은 그 페이로드 하나에 대한 차단으로 보고 바로 다음 페이로드로 넘어가며, 같은 쿨다운은 `--waf-evasion`일 때만 적용합니다. 불안정한 대상이라면 `--delay`(요청당 밀리초)를 주고 `--workers`를 줄이면 도움이 됩니다. `--delay`가 0보다 크면 각 파라미터의 페이로드도 하나씩 차례로 보냅니다.

```bash
dalfox scan https://target.app --delay 500 --workers 10
```

## 디버깅

디버그 스트림을 켜서 핑거프린트 판단과 활성 전략을 확인하세요:

```bash
dalfox scan --debug https://target.app 2>&1 | grep -i waf
```

## 다음 단계

- [저장형 XSS](../stored-xss/)는 한 곳에 주입하고 다른 곳에서 검증하는 패턴을 다루며, WAF와 얽히는 경우가 많습니다.
- [출력과 리포트](../output/)는 탐지 결과를 파이프라인에 통합하는 방법을 다룹니다.
