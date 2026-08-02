+++
title = "출력과 리포트"
description = "Plain, JSON, JSONL, Markdown, SARIF, TOML 형식과 탐지 결과를 파이프라인에 통합하는 방법을 다룹니다."
weight = 6
toc = true
+++

모든 스캔은 동일한 내부 결과 구조를 만듭니다. Dalfox는 이를 선택한 형식으로 렌더링합니다. 기계 판독 형식은 배너를 자동으로 빼므로 파일이 깔끔하게 유지됩니다.

## 형식 선택

```bash
dalfox https://target.app -f json -o report.json
```

| 형식 | 플래그 | 기계 판독 가능 | 적합한 용도 |
|--------|------|------------------|----------|
| `plain` | `-f plain` (기본값) | 아니오 | 사람이 읽는 터미널 출력 |
| `json` | `-f json` | 예 | 단일 JSON 문서, 대시보드, `jq` |
| `jsonl` | `-f jsonl` | 예 | 스트리밍, 로그 파이프라인 |
| `markdown` | `-f markdown` | 아니오 | 리포트, 풀 리퀘스트 코멘트 |
| `sarif` | `-f sarif` | 예 | GitHub 코드 스캐닝, SARIF 소비자 |
| `toml` | `-f toml` | 예 | 사람 + 파이프라인 |

## 파일로 저장하기

```bash
dalfox https://target.app -f jsonl -o findings.jsonl
```

`-o`가 없으면 출력은 `stdout`으로 나갑니다.

## 결과 필드

모든 탐지 결과에는 다음이 포함됩니다.

| 필드 | 예시 | 의미 |
|-------|---------|---------|
| `type` | `V`, `A`, `R`, `I` | 신뢰도: Vulnerable / AST 탐지 / Reflected / Informational |
| `type_description` | `"Vulnerable - dalfox asserts this input is exploitable; act on it"` | 사람이 읽는 라벨(한 단어가 아니라 문장 전체) |
| `detection_method` | `"ast"` | 어떻게 찾았는지: `reflection`, `dom-verification`, `ast`, `oob`, `library` |
| `confidence` | `"high"` | 취약점이라고 주장할 수 있는지 (`high` / `low`). `I`에는 없음 |
| `confidence_reason` | `"URL-carried source; inline script permitted"` | 판단 근거 신호 |
| `inject_type` | `"inHTML"` | 컨텍스트 (`inHTML`, `inAttr`, `inJS`, …) |
| `method` | `"GET"` | HTTP 메서드 |
| `param` | `"q"` | 공격에 사용된 파라미터 |
| `payload` | `<svg/onload=alert(1)>` | 정확한 페이로드 |
| `evidence` | `"payload reflected in response"` | Dalfox가 그렇게 판단한 근거 |
| `cwe` | `"CWE-79"` | 표준 CWE |
| `severity` | `"High"` | High / Medium / Low / Info |
| `message_str` | `"XSS found"` | 짧은 메시지 |

각 등급이 실제로 어떤 증거인지, 그리고 순수 클라이언트 사이드 DOM-XSS가 왜 `V`에
도달하지 못하는지는 [탐지 모델](../detection-model/) 문서에서 다룹니다.

`V` / `A` / `R`은 XSS 탐지 결과입니다. `I`(**Informational**)는 공격에 사용할 수 없는
관찰 항목으로, 현재는 **오래되었거나 알려진 취약점이 있는 JS 라이브러리**
(`inject_type: "OutdatedComponent"`, `CWE-1104`)만 해당하며, 페이로드나 파라미터가 없는 간결한
`[INF]` 라인으로 렌더링됩니다. 이 항목은 **명시적 활성화 방식**입니다. Dalfox는 기본적으로
검증된 XSS에 집중하므로, `--detect-outdated-libs`를 전달하지 않는 한 라이브러리 리포팅은 꺼져 있습니다
(추가 요청은 **0건**이며, 프리플라이트 응답의 `<script>` 태그를 검사합니다). `--only-poc v,a,r`로 걸러낼 수 있습니다.

선택적으로 전체 요청/응답을 포함할 수 있습니다.

```bash
dalfox https://target.app -f json --include-all -o report.json
# 또는 세부적으로:
dalfox ... --include-request
dalfox ... --include-response
```

## 스캔 메타데이터 엔벨로프

JSON, JSONL, SARIF, TOML, Markdown 출력은 이제 모두 동일한 스캔 수준 메타데이터 엔벨로프를 담습니다(이전에는 JSON/JSONL만 해당, [#1093](https://github.com/hahwul/dalfox/issues/1093) 참조).

- `dalfox_version`
- `targets` (입력 대상)
- `scan_duration_ms`
- `total_requests`
- `findings_count`
- `target_summary[]` — 대상별 상태, 탐지 결과 수, error_code(건너뛴 경우), 그리고 탐지된 경우 WAF/우회 세부 정보
- `dedup_mode` / `targets_deduplicated` — 적용된 [`--dedup-urls`](../scanning-modes/) 모드와 그것이 병합한 타깃 수. 축소된 입력 목록이 리포트에 드러나도록 합니다(Markdown은 실제로 병합이 있었을 때만 행을 표시합니다)
- `baseline` — `--baseline`을 쓴 경우에만 포함됩니다. [베이스라인](#베이스라인-새로-생긴-것만-보고하기) 참고
- `incomplete` — 하나 이상의 대상이 **완전히 테스트되지 않았을 때** `true`입니다. 현재는 스캔 도중 인증 세션이 끊어진 경우를 뜻합니다([세션 모니터링](../scanning-modes/) 참고). `target_summary` 항목을 전부 훑는 대신 이 필드 하나만 보세요. `"findings_count": 0`과 `"incomplete": true`가 함께 있다면 안전하다는 뜻이 *아닙니다*

세션이 끊어진 대상은 `"status": "incomplete"`(아예 실행되지 않았다면 `"skipped"`)에 `"error_code": "SESSION_LOST"`, 그리고 감지된 신호가 `"error_message"`에 담겨 보고됩니다. 절대 `"clean"`으로는 표시되지 않습니다.

**SARIF**에서는 엔벨로프가 `runs[0].properties`와 `runs[0].tool.driver.properties` 아래에 중복으로 실려, GitHub 코드 스캐닝을 비롯한 소비 도구가 컨텍스트를 잃지 않습니다.

**TOML**에서는 최상위 `[meta]` 테이블로 나타납니다(탐지 결과는 `[[results]]` 아래).

**Markdown**에서는 탐지 결과 요약 위에 사람이 읽을 수 있는 테이블(`## Scan Metadata` + `### Target Summary`)로 렌더링됩니다.

Plain 텍스트 출력은 여전히 탐지 결과에만 집중합니다.

## 사일런스 모드

로그 없이 `stdout`에 **탐지 결과만** 내보냅니다.

```bash
dalfox https://target.app --silence
# 탐지 결과를 다른 도구로 파이프:
cat urls.txt | dalfox --silence -f jsonl | jq 'select(.severity=="High")'
```

셸 파이프라인과 cron 작업에 유용합니다.

## 긴 스캔 중 탐지 결과 스트리밍

기본적으로 plain 렌더러는 각 탐지 결과 블록(POC + Issue /
Payload / Line)을 스캔 종료 시점의 `WRN XSS found N XSS` 요약 **이후에** 출력하므로,
로그는 자연스러운 순서(시작 → 진행 → 요약 → 세부 정보)로 읽힙니다.

대상이 크고 스캔이 길어질 때는 `--stream-findings`로 스캔 도중 출력으로 전환할 수 있습니다.
각 탐지 결과는 검증되는 즉시 진행 표시줄 위에 출력됩니다.

```bash
dalfox https://target.app --stream-findings
```

`--stream-findings`는 `plain` 형식에만 영향을 미칩니다. 스캔 종료 시점에 스트리머가 그대로
반영할 수 없는 필터(`--output`, `--limit`, `--only-poc`)를 적용해야 하면 자동으로
비활성화됩니다.

## POC 스타일

개념 증명(proof-of-concept)을 다양한 클라이언트 형태로 다시 렌더링합니다.

```bash
dalfox https://target.app --poc-type curl      # curl 명령
dalfox https://target.app --poc-type httpie    # HTTPie
dalfox https://target.app --poc-type http-request  # 원시 HTTP
```

기본값은 `plain`입니다. 티켓 등록에 적합합니다.

## 필터링

특정 결과 유형만 표시합니다.

```bash
dalfox https://target.app --only-poc v     # 검증된 것만
dalfox https://target.app --only-poc v,a   # 검증 + AST
```

결과 수를 제한합니다.

```bash
dalfox https://target.app --limit 50
dalfox https://target.app --limit 10 --limit-result-type v
```

## 베이스라인: 새로 생긴 것만 보고하기

`--only-poc`와 `--limit`은 **형태**로 거릅니다. 이미 트리아지를 끝낸 건과 오늘 아침에 새로 나타난 건을 구분하지 못하므로, 기존 이슈가 100건인 저장소는 PR마다 똑같은 100건을 다시 보게 되고 결국 게이트는 항상 빨간불이거나 꺼두게 됩니다.

`--baseline`이 이 문제를 해결합니다. 이전 리포트를 지정하면 거기에 이미 있는 건은 억제됩니다.

```bash
dalfox scan scope.txt -f json -o baseline.json      # 최초 1회, 기존 백로그 기록
dalfox scan scope.txt --baseline baseline.json      # 이후 매 실행
```

**별도의 베이스라인 작성 명령은 없습니다.** 평범한 `-f json -o`(또는 `-f jsonl -o`) 리포트가 그대로 베이스라인입니다.

### 모드

| 모드 | 플래그 | 동작 |
|------|--------|------|
| `filter` (기본) | `--baseline-mode filter` | 이미 알려진 건을 제거합니다. 카운트, `--limit`, **종료 코드**가 모두 신규 건만 기준으로 결정됩니다 — CI 게이트용 모드입니다. |
| `annotate` | `--baseline-mode annotate` | 모든 건을 그대로 두고 각각에 `new: true` / `new: false`를 붙입니다. 전체 집합을 보되 신규 여부를 표시하고 싶은 대시보드용입니다. |

### 무엇을 "같은 건"으로 볼까

지문(fingerprint)은 그 건을 드러낸 **실행**이 아니라 취약점 자체의 정체성을 기준으로 만듭니다.

**포함:** 호스트 + 경로 · 파라미터 이름 · 파라미터 위치(query / header / cookie / body / path) · 인젝션 컨텍스트 · CWE · 탐지 티어 · 증거 계열(DOM 건의 `Source → Sink` 쌍).

**제외:** 페이로드와 그것이 들어간 쿼리 스트링, 페이로드 순서, AST의 줄/열 번호, 타임스탬프, 요청/응답 캡처.

따라서 실행마다 페이로드가 달라져도 같은 스캔은 깔끔하게 매칭되고, 번들러가 `app.js`의 줄 번호를 밀어도 이미 처리한 DOM 건이 되살아나지 않습니다. **티어**가 지문에 들어가므로, 지난주 `R`이던 건이 오늘 `V`가 되면 신규로 보고됩니다. 이런 승격이야말로 게이트가 잡아야 할 변화입니다.

### `meta.baseline` 블록

모든 구조화 형식이 diff 결과를 함께 보고합니다.

```json
"baseline": {
  "path": "baseline.json",
  "mode": "filter",
  "enabled": true,
  "baseline_findings": 100,
  "new": 2,
  "known": 98
}
```

베이스라인 파일이 없거나, 형식이 깨졌거나, 다른 메이저 버전이 쓴 것이면 **stderr에 경고를 내고 diff를 비활성화**할 뿐 스캔을 실패시키지는 않습니다. 파이프라인에 남은 낡은 경로 하나 때문에 멀쩡히 돌던 스캔이 아무것도 보고하지 못하는 빨간 빌드가 되어서는 안 되기 때문입니다. 이 상황은 엔벨로프에 `"enabled": false`와 `warning`으로 드러나므로, "신규 없음"과 "diff가 아예 돌지 않음"을 구분할 수 있습니다.

### 베이스라인 갱신

전용 명령은 없습니다. `--baseline` **없이** 다시 실행해(그래야 리포트에 신규 건만이 아니라 전체 집합이 담깁니다) 파일을 교체하면 됩니다.

```bash
dalfox scan scope.txt -f json -o baseline.json
git commit -am "chore: refresh dalfox baseline"
```

`--baseline`을 켠 채 `-o`를 같은 파일로 지정하면 `filter` 모드에서 베이스라인이 파괴됩니다. 되쓰이는 리포트에는 신규 건만 들어 있어서 다음 실행이 백로그 전체를 다시 보고하게 됩니다. 두 경로가 같으면 Dalfox가 경고합니다.

### 주의사항

- **`--limit`은 diff 이전에 셉니다.** 스캔 중 중단 조건은 수집되는 모든 건을 세므로(베이스라인에 이미 있는 건 포함), `--limit 10 --baseline b.json`으로 처음 10건이 전부 기존 건인 대상을 돌리면 나머지를 테스트하지 않은 채 조기 종료하고 "신규 0"을 보고합니다. 신규 기준으로 게이트할 때는 `--limit`을 빼세요. 둘을 함께 쓰면 Dalfox가 경고합니다.
- **`--stream-findings`는 `--baseline`이 있으면 비활성화됩니다.** `--only-poc`과 같은 이유입니다. 스트리머는 어떤 건이 이미 베이스라인에 있는지 알 수 없어서, 요약은 신규만 보고하는데 화면에는 트리아지가 끝난 백로그 전체가 흘러가게 됩니다.
- **CLI 전용입니다.** `dalfox server`와 MCP 서버는 `--baseline`을 적용하지 않습니다. 공유 config의 `scan.baseline`도 그쪽에서는 조용히 무시됩니다.

## 색상 및 TTY 동작

```bash
dalfox https://target.app --no-color
# 또는
NO_COLOR=1 dalfox https://target.app
```

Dalfox는 출력이 파일이나 비 TTY로 리다이렉트될 때도 색상을 자동으로 비활성화합니다.

## TOML

JSON과 동일한 데이터 형태이며(다른 형식과의 일관성을 위한 최상위 `[meta]` 엔벨로프 포함), TOML로 작성됩니다. 탐지 결과는 `[[results]]` 테이블 배열로 렌더링됩니다.

```toml
[meta]
dalfox_version = "3.x"
targets = ["https://target.app"]
scan_duration_ms = 1234
total_requests = 87
findings_count = 1
target_summary = [{ target = "https://target.app", status = "findings", findings_count = 1 }]

[[results]]
type = "V"
type_description = "Vulnerable - dalfox asserts this input is exploitable; act on it"
detection_method = "dom-verification"
confidence = "high"
inject_type = "inHTML"
method = "GET"
data = "https://target.app/search?q=%3Csvg%2Fonload%3Dalert%281%29%3E"
param = "q"
payload = "<svg/onload=alert(1)>"
evidence = "payload reflected and DOM element verified"
location = "Query"
cwe = "CWE-79"
severity = "High"
message_id = 606
message_str = "XSS found"
```

```bash
dalfox https://target.app -f toml -o report.toml
```

## SARIF → GitHub 코드 스캐닝

```bash
dalfox scan urls.txt -f sarif -o dalfox.sarif
```

GitHub의 `upload-sarif` 액션으로 `dalfox.sarif`를 업로드하면, 탐지 결과가 리포지토리의 **Security → Code scanning** 탭에 나타납니다.

## CI 예시

```yaml
# .github/workflows/xss-scan.yml
- name: Dalfox scan
  run: dalfox scan scope.txt -f sarif -o dalfox.sarif --silence --waf-evasion

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dalfox.sarif
```

### 신규 탐지 결과만으로 게이트하기

`baseline.json`을 스코프 파일과 함께 커밋해 두고 종료 코드로 빌드를 실패시키세요. 베이스라인에 없는 건이 나타났을 때만 빨간불이 됩니다.

```yaml
# .github/workflows/xss-scan.yml
- name: Dalfox scan (new findings gate)
  run: |
    dalfox scan scope.txt \
      --baseline .dalfox/baseline.json \
      --only-poc v \
      -f json -o dalfox.json --silence

- name: Upload report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: dalfox-report
    path: dalfox.json
```

트리아지 후 베이스라인을 갱신하려면 `--baseline` **없이** 실행하고 `-o`를 베이스라인 파일로 지정하세요.

```bash
dalfox scan scope.txt --only-poc v -f json -o .dalfox/baseline.json
```

위 게이트 명령을 그대로 두고 `-o .dalfox/baseline.json`만 붙이면 *신규* 건만 담긴 리포트가 파일을 덮어써서 기록해둔 백로그가 날아갑니다. `--output`과 `--baseline`이 같은 경로로 해석되면 Dalfox가 stderr에 경고합니다.

## 종료 코드

Dalfox는 다음을 반환합니다.

| 코드 | 의미 |
|------|---------|
| `0` | 성공적으로 완료, 탐지 결과 없음 |
| `1` | 성공적으로 완료, **티어와 무관하게** 탐지 결과 하나 이상 |
| `2` | 입력/설정/런타임 오류, **또는** 기본값 `--on-session-loss abort`에서 스캔 도중 세션이 끊어졌고 *탐지 결과가 없는* 경우 (탐지 결과가 있었다면 여전히 `1`) |

`1`은 모든 티어를 포함합니다. `R` 하나나 `--detect-outdated-libs`가 만든 `I` 하나도 `V`와 똑같이 빌드를 실패시킵니다. Dalfox가 악용 가능하다고 판단한 것만 게이트로 삼으려면 `--only-poc v`를 주고 종료 코드를 그대로 쓰세요. 코드가 정해지기 전에 필터가 적용됩니다. (JSON에 `jq`로 `severity >= High`를 거는 방식도 오늘은 같은 집합을 얻습니다. severity가 현재 티어를 따라가기 때문입니다. [탐지 모델](../detection-model/) 참고.)

`--baseline`은 같은 종료 코드를 **신규 여부**로 좁힙니다. 기본 `filter` 모드에서는 억제된 건이 종료 코드 판정에 도달하지 않으므로, 백로그가 전부 베이스라인에 들어 있는 실행은 `0`으로 끝납니다. [베이스라인](#베이스라인-새로-생긴-것만-보고하기) 참고.

## 다음

- [REST API 서버](../../integrations/server/)로 스캔을 자동화하세요.
- [MCP 서버](../../integrations/mcp/)로 AI 드라이버가 처리하도록 맡기세요.
