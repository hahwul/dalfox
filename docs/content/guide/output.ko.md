+++
title = "출력과 리포트"
description = "Plain, JSON, JSONL, Markdown, SARIF, TOML 형식과 탐지 결과를 파이프라인에 통합하는 방법을 다룹니다."
weight = 6
toc = true
+++

모든 스캔은 동일한 내부 결과 구조를 생성합니다. Dalfox는 이를 여러분이 선택한 형식으로 렌더링합니다. 기계 판독 가능 형식은 배너를 자동으로 억제하므로 파일이 깔끔하게 유지됩니다.

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

`-o`가 없으면 출력은 `stdout`으로 전달됩니다.

## 결과 필드

모든 탐지 결과에는 다음이 포함됩니다.

| 필드 | 예시 | 의미 |
|-------|---------|---------|
| `type` | `V`, `A`, `R`, `I` | Verified / AST 탐지 / Reflected / Informational |
| `type_description` | `"Verified"` | 사람이 읽는 라벨 |
| `inject_type` | `"inHTML"` | 컨텍스트 (`inHTML`, `inAttr`, `inJS`, …) |
| `method` | `"GET"` | HTTP 메서드 |
| `param` | `"q"` | 공격에 사용된 파라미터 |
| `payload` | `<svg/onload=alert(1)>` | 정확한 페이로드 |
| `evidence` | `"payload reflected in response"` | Dalfox가 그렇게 판단한 근거 |
| `cwe` | `"CWE-79"` | 표준 CWE |
| `severity` | `"High"` | High / Medium / Low / Info |
| `message_str` | `"XSS found"` | 짧은 메시지 |

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

**SARIF**에서는 엔벨로프가 `runs[0].properties`와 `runs[0].tool.driver.properties` 아래에 중복되어 GitHub 코드 스캐닝과 기타 소비자가 컨텍스트를 유지하도록 합니다.

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

대규모 대상에 대한 긴 스캔의 경우, `--stream-findings`로 스캔 도중 방출로 전환할 수 있습니다.
각 탐지 결과는 검증되는 즉시 진행 표시줄 위에 출력됩니다.

```bash
dalfox https://target.app --stream-findings
```

`--stream-findings`는 `plain` 형식에만 영향을 미치며, 스캔 종료 경로가 스트리머로 깔끔하게
반영할 수 없는 필터(`--output`, `--limit`, `--only-poc`)를 적용해야 할 때는
자동으로 비활성화됩니다.

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
type_description = "Verified"
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

GitHub의 `upload-sarif` 액션을 통해 `dalfox.sarif`를 업로드하면, 탐지 결과가 리포지토리의 **Security → Code scanning** 탭에 나타납니다.

## CI 예시

```yaml
# .github/workflows/xss-scan.yml
- name: Dalfox scan
  run: dalfox scan scope.txt -f sarif -o dalfox.sarif --silence --waf-evasion

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dalfox.sarif
```

## 종료 코드

Dalfox는 다음을 반환합니다.

| 코드 | 의미 |
|------|---------|
| `0` | 성공적으로 완료, 탐지 결과 없음 |
| `1` | 성공적으로 완료, 탐지 결과 하나 이상 |
| `2` | 입력/설정/런타임 오류 |

어떤 탐지 결과라도 빌드를 실패시켜도 괜찮은 경우에만 `1`을 CI 게이트로 사용하세요. 대부분의 팀은 JSON 출력에 `jq`를 사용하여 `severity >= High`를 기준으로 게이트를 겁니다.

## 다음

- [REST API 서버](../../integrations/server/)를 통해 스캔을 자동화하세요.
- [MCP 서버](../../integrations/mcp/)로 AI 드라이버가 처리하도록 맡기세요.
