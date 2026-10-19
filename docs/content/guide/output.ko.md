+++
title = "출력과 리포트"
description = "Dalfox XSS 탐지 결과를 plain text, JSON, JSONL, Markdown, SARIF, TOML로 내보내 CI와 보안 파이프라인에 연결합니다."
weight = 6
toc = true
+++

모든 스캔은 같은 내부 결과 구조를 만들고, Dalfox는 이를 선택한 형식으로 렌더링합니다. `plain`을 제외한 모든 형식은 배너를 출력하지 않으므로, 파일로 리디렉션한 리포트에 군더더기가 섞이지 않습니다.

## 형식 선택

```bash
dalfox scan https://target.app -f json -o report.json
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
dalfox scan https://target.app -f jsonl -o findings.jsonl
```

`-o`가 없으면 출력은 `stdout`으로 나갑니다.

## 결과 필드

탐지 결과에는 다음 필드가 담깁니다.

| 필드 | 예시 | 의미 |
|-------|---------|---------|
| `type` | `V`, `A`, `R`, `I` | 탐지 티어: Vulnerable / AST 탐지 / Reflected / Informational |
| `type_description` | `"Vulnerable - dalfox asserts this input is exploitable; act on it"` | 사람이 읽는 라벨(한 단어가 아니라 문장 전체) |
| `detection_method` | `"ast"` | 어떻게 찾았는지: `reflection`, `dom-verification`, `ast`, `oob`, `library` |
| `confidence` | `"high"` | 증거가 그 주장을 얼마나 강하게 뒷받침하는지 (`high` / `low`). `I`에는 없음 |
| `confidence_reason` | `"URL-carried source; inline script permitted"` | 판단 근거 신호 |
| `inject_type` | `"inHTML"` | 탐지 라벨: 주입한 페이로드는 `inHTML`(`--sxss`에서는 `sxss-inHTML`, 조건에 맞으면 `-CSTI` 접미어나 `-VHtml` 같은 프레임워크 싱크 접미어가 붙음), `inHTML-HPP`, `DOM-XSS`(AST), `blind-oob-<location>-<protocol>`, `OutdatedComponent`(`I`) |
| `method` | `"GET"` | HTTP 메서드 |
| `data` | `"https://target.app/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx1ec4110f%3E"` | PoC URL |
| `param` | `"q"` | 공격에 사용된 파라미터 |
| `location` | `"Query"` | 파라미터가 실리는 위치: `Query`, `Body`, `JsonBody`, `MultipartBody`, `GraphqlBody`, `XmlBody`, `Header`(쿠키 포함), `Path`, `Fragment`. 알 수 없으면 생략 |
| `payload` | `<svg onload=alert(1)>` | 정확한 페이로드 |
| `evidence` | `"DOM verification successful for param q (DOM marker)"` | Dalfox가 그렇게 판단한 근거 |
| `cwe` | `"CWE-79"` | 표준 CWE |
| `severity` | `"High"` | High / Medium / Low / Info |
| `message_id` | `606` | 카탈로그 메시지 ID |
| `message_str` | `"Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx1ec4110f>"` | 짧은 메시지 |
| `filter` | `{"allowed": ["/"], "blocked": ["(", ")"], "encoded": ["<", ">"]}` | 파라미터가 프로브한 특수문자를 어떻게 처리했는지: 그대로 반사(`allowed`), HTML 엔티티나 `%HH`로만 반사(`encoded`), 제거(`blocked`), 백슬래시 이스케이프(`escaped`). `encoded` / `escaped`는 비어 있으면 생략. 반사·DOM 검증 결과에만 붙고, 프로브 판정이 없거나 AST / HPP / 저장형 / OOB 결과에는 생략. plain과 Markdown 출력은 `R` 결과에만 표시 |

다음 세 필드는 요청했을 때만 나타납니다: `new`(`--baseline-mode annotate`), `request`(`--include-request`), `response`(`--include-response`).

각 티어가 어떤 증거인지, 순수 클라이언트 사이드 DOM-XSS가 왜 `V`에
도달하지 못하는지는 [탐지 모델](../detection-model/) 문서에서 다룹니다.

`V` / `A` / `R`은 XSS 탐지 결과입니다. `I`(Informational)는 악용할 수 없는
관찰 항목입니다. 지금은 오래되었거나 알려진 취약점이 있는 JS 라이브러리
(`inject_type: "OutdatedComponent"`, `CWE-1104`)만 여기에 해당하고, 페이로드나 파라미터 없이
`[INF]` 한 줄로 출력됩니다. 이 항목은 옵트인입니다. Dalfox는 기본적으로
검증된 XSS에 집중하므로, `--detect-outdated-libs`를 주지 않으면 라이브러리 리포팅은 꺼져 있습니다.
추가 요청은 없고, 프리플라이트 응답의 `<script>` 태그만 검사합니다. `--only-poc v,a,r`로 걸러낼 수 있습니다.

전체 요청/응답을 포함하려면 다음처럼 실행합니다.

```bash
dalfox scan https://target.app -f json --include-all -o report.json
# 또는 하나씩:
dalfox scan https://target.app --include-request
dalfox scan https://target.app --include-response
```

기록되는 요청은 Dalfox가 실제로 보낸 것 그대로입니다. `-H`로 준 헤더와 쿠키가
전부 원문으로 들어갑니다. `--include-request` / `--include-all`로 만든 리포트는
공유하기 전에 내용을 확인하세요. 유닉스에서는 `-o` 파일을 `0600`으로 생성해
같은 호스트의 다른 계정이 읽지 못하게 하지만, 그 파일이 이후에 어디로 가는지는
별개의 문제입니다.

## JSON과 JSONL 형태

`-f json`은 엔벨로프를 `meta` 아래에, 탐지 결과를 `findings` 아래에 담은 문서 하나를 씁니다. 키는 알파벳 순서로 나옵니다.

```json
{
  "findings": [
    {
      "confidence": "high",
      "confidence_reason": "payload reached an executable position in the parsed response",
      "cwe": "CWE-79",
      "data": "https://target.app/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx1ec4110f%3E",
      "detection_method": "reflection",
      "evidence": "DOM verification successful for param q (DOM marker)",
      "filter": {
        "allowed": ["\"", "$", "'", "(", ")", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "[", "\\", "]", "`", "{", "|", "}"],
        "blocked": []
      },
      "inject_type": "inHTML",
      "location": "Query",
      "message_id": 606,
      "message_str": "Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx1ec4110f>",
      "method": "GET",
      "param": "q",
      "payload": "<svg onload=alert(1) class=dlx1ec4110f>",
      "severity": "High",
      "type": "V",
      "type_description": "Vulnerable - dalfox asserts this input is exploitable; act on it"
    }
  ],
  "meta": {
    "dalfox_version": "3.2.4",
    "dedup_mode": "exact",
    "failed_requests": 0,
    "findings_count": 1,
    "incomplete": false,
    "scan_duration_ms": 1234,
    "target_summary": [
      { "findings_count": 1, "method": "GET", "status": "findings", "target": "https://target.app/?q=a" }
    ],
    "targets": ["https://target.app/?q=a"],
    "targets_deduplicated": 0,
    "total_requests": 87
  }
}
```

`-f jsonl`은 같은 데이터를 한 줄에 객체 하나씩 씁니다. 첫 줄은 `{"meta": {…}}`이고, 그 뒤의 각 줄이 탐지 결과 하나입니다. 탐지 결과만 필요하다면 첫 줄을 건너뛰거나, `jq 'select(.severity=="High")'`처럼 탐지 결과 필드로 거르세요.

## 스캔 메타데이터 엔벨로프

JSON, JSONL, SARIF, TOML, Markdown 출력은 모두 같은 스캔 수준 메타데이터 엔벨로프를 담습니다.

- `dalfox_version`
- `targets`: 지정한 입력 대상(URL 또는 목록/명세 파일 경로). 파이프로 받은 목록은 `-`(stdin)로 표시됩니다.
- `scan_duration_ms`
- `total_requests`
- `failed_requests`: 재시도를 다 쓰고도 응답을 받지 못한 요청 수(리셋, 거부, 타임아웃, 본문이 도중에 끊긴 경우)와 HTTP 429로 거절된 탐색·마이닝 프로브 수. 대상에 닿지 못한 페이로드는 테스트되지 않은 것입니다.
- `findings_count`
- `target_summary[]`: 대상마다 항목 하나. 대상은 URL + 메서드 + 요청 본문으로 구분하므로 같은 URL의 `GET`과 `POST`는 항목이 따로 생깁니다. 각 항목에는 `target`, `method`, `status`(`findings`, `clean`, `skipped`, `incomplete`), `findings_count`가 있습니다. 건너뛰었거나 세션이 끊긴 대상에는 `error_code`가, 세션이 끊긴 경우에는 감지된 신호를 담은 `error_message`가 더 붙습니다. Ctrl-C, `--limit`, `--scan-timeout`으로 도중에 끊긴 대상은 `incomplete`이고, `--scan-timeout`으로 끊긴 경우에만 `error_code: SCAN_TIMEOUT`이 붙습니다. WAF가 탐지되면 `waf` 객체도 붙습니다. `type` / `confidence` / `evidence`를 담은 `detected[]`와, 추가 인코더·변형 수·우회 중 보낸/차단된 요청 수를 담은 `bypass` 블록으로 구성됩니다.
- `dedup_mode` / `targets_deduplicated`: 적용된 [`--dedup-urls`](../scanning-modes/#거의-같은-url-묶기) 모드와 그 모드가 병합한 대상 수. 입력 목록이 줄어든 사실이 리포트에 드러납니다. Markdown은 실제로 병합이 있었을 때만 이 행을 표시합니다.
- `targets_unparsable`: 대상 목록의 줄을 파싱하지 못했거나 OpenAPI / Postman 오퍼레이션을 만들지 못해 건너뛴 경우에만 포함됩니다. [File 모드](../scanning-modes/#file-모드), [OpenAPI / Postman 모드](../scanning-modes/#openapi-postman-모드) 참고.
- `baseline`: `--baseline`을 쓴 경우에만 포함됩니다. [베이스라인](#베이스라인-새로-생긴-것만-보고하기) 참고.
- `resumed`: `--state-file`을 쓴 경우에만 포함됩니다. `state_file`(경로)과 `targets_skipped_completed`(이전 실행에서 끝나 건너뛴 대상 수)를 담습니다.
- `min_confidence`: `--min-confidence`를 준 경우에만 포함됩니다. [필터링](#필터링) 참고.
- `incomplete`: 실행이 완전히 테스트되지 않았을 때 `true`입니다. 스캔 도중 대상의 인증 세션이 끊어졌거나([세션 모니터링](../scanning-modes/#세션-모니터링) 참고), 전체 요청의 10% 이상(최소 3건)이 응답을 받지 못했거나, Ctrl-C / `--limit` / `--scan-timeout`으로 모든 대상이 끝나기 전에 실행이 멈춘 경우입니다. `target_summary` 항목을 전부 훑는 대신 이 필드 하나만 보면 됩니다. `"findings_count": 0`과 `"incomplete": true`가 함께 있다면 안전하다는 뜻이 *아닙니다*.

세션이 끊어진 대상은 `"status": "incomplete"`(아예 실행되지 않았다면 `"skipped"`)와 `"error_code": "SESSION_LOST"`로 보고되고, 감지된 신호는 `"error_message"`에 담깁니다. `"clean"`으로 표시되는 일은 없습니다. Ctrl-C, `--limit`, `--scan-timeout`으로 도중에 끊긴(또는 실행이 그 전에 멈춰 도달하지 못한) 대상도 탐지 결과가 없으면 `"incomplete"`로 표시됩니다. `--scan-timeout`으로 끊긴 대상에는 탐지 결과가 있어도 `"error_code": "SCAN_TIMEOUT"`이 붙으므로, 배치 실행에서 어떤 대상을 다시 돌려야 하는지 알 수 있습니다. 나머지 경우에는 `error_code`가 없습니다.

SARIF에서는 엔벨로프가 `runs[0].properties`와 `runs[0].tool.driver.properties` 두 곳에 실려, GitHub 코드 스캐닝 같은 소비 도구도 컨텍스트를 그대로 받습니다. 각 결과의 `ruleId`는 `dalfox/cwe-<n>`(XSS는 `dalfox/cwe-79`, 오래된 라이브러리는 `dalfox/cwe-1104`)입니다. `level`은 `severity`를 따르고(High → `error`, Medium → `warning`, Low / Info → `note`), PoC URL은 location의 `uri`에 들어갑니다. `partialFingerprints["vulnIdentity/v1"]`은 코드 스캐닝이 실행 간에 같은 건을 맞춰 볼 수 있게 하는 안정적인 해시입니다. 탐지 결과 필드(`type`, `inject_type`, `param`, `payload`, `severity`, `detection_method`, `confidence` 등)는 결과의 `properties` 아래에 있고, `message.text`에는 `message_str`과 근거가 함께 담깁니다.

TOML에서는 최상위 `[meta]` 테이블로 나타납니다(탐지 결과는 `[[results]]` 아래).

Markdown에서는 탐지 결과 요약 위에 테이블(`## Scan Metadata` + `### Target Summary`)로 렌더링됩니다. 실패한 요청, incomplete, 중복 제거된 대상, 베이스라인, 재개, `--min-confidence`처럼 무슨 일이 있었을 때만 의미 있는 행은 그때만 나타납니다.

Plain 텍스트 출력은 탐지 결과만 담습니다.

## 사일런스 모드

`--silence`(`-S`)는 로그 없이 `stdout`에 탐지 결과만 내보냅니다.

```bash
dalfox scan https://target.app --silence
# 탐지 결과를 다른 도구로 파이프:
cat urls.txt | dalfox scan --silence -f jsonl | jq 'select(.severity=="High")'
```

셸 파이프라인과 cron 작업에 유용합니다.

## 긴 스캔 중 탐지 결과 스트리밍

기본적으로 plain 렌더러는 각 탐지 결과 블록(POC + Issue /
Payload / Line)을 스캔 종료 시점의 `WRN XSS found N XSS` 요약 뒤에 출력합니다.
그래서 로그가 시작 → 진행 → 요약 → 세부 정보 순서로 읽힙니다.

대상이 크고 스캔이 길어질 때는 `--stream-findings`를 주면 각 탐지 결과가
검증되는 즉시 진행 표시줄 위에 출력됩니다.

```bash
dalfox scan https://target.app --stream-findings
```

`--stream-findings`는 `plain` 형식에서만 동작합니다. 스캔 종료 시점에 스트리머가
따라 할 수 없는 처리(`--output`, `--limit`, `--only-poc`, `--baseline`)가 필요하면
자동으로 꺼집니다. 명령줄에서 `--stream-findings`를 준 경우에는 이를 끈 플래그를
알려 주는 `Warning:`이 stderr에 출력됩니다.

## POC 스타일

PoC를 다른 클라이언트 형태로 다시 렌더링합니다.

```bash
dalfox scan https://target.app --poc-type curl      # curl 명령
dalfox scan https://target.app --poc-type httpie    # HTTPie
dalfox scan https://target.app --poc-type http-request  # 원시 HTTP
```

기본값은 `plain`입니다. 티켓을 등록할 때 편합니다. `--poc-type`은 `plain` 리포트의 POC 줄만 바꿉니다. 구조화 형식은 항상 `data`에 PoC URL을 담습니다. `http-request`는 Dalfox가 그 탐지 결과에 기록한 원시 요청을 출력하며, 기록된 요청이 없으면 URL을 대신 출력합니다.

## 필터링

특정 결과 유형만 표시합니다.

```bash
dalfox scan https://target.app --only-poc v     # V(Vulnerable)만
dalfox scan https://target.app --only-poc v,a   # V + AST
```

Dalfox가 확신할 수 없는 탐지 결과(모든 `R`, 그리고 `low` 등급 AST 흐름)를 제외합니다.

```bash
dalfox scan https://target.app --min-confidence high
```

`--min-confidence high`는 티어가 아니라 `confidence` 등급으로 거르며, 가장 먼저
적용됩니다. 모든 형식의 출력, `--stream-findings`, `target_summary` 개수,
`--baseline`, `--limit`(스캔 중 조기 종료와 표시 개수 모두), 종료 코드가 걸러진
집합을 봅니다. `I`는 등급이 없으므로 유지됩니다. 기본값 `low`는 모두 유지합니다.
옵션을 주면 엔벨로프에 `meta.min_confidence: {"level": "high", "dropped": N}`이
실립니다. `N`은 대상별이 아니라 스캔 전체의 수입니다. 0이 아니면 `clean`인 대상
중 일부의 탐지 결과가 걸러졌을 수 있다는 뜻이고, 어느 대상인지는 알려 주지 않습니다.

결과 수를 제한합니다.

```bash
dalfox scan https://target.app --limit 50
dalfox scan https://target.app --limit 10 --limit-result-type v
```

## 베이스라인: 새로 생긴 것만 보고하기

`--only-poc`와 `--limit`은 *형태*로 거릅니다. 이미 트리아지를 끝낸 건과 오늘 아침에 새로 나타난 건을 구분하지 못합니다. 그래서 기존 이슈가 100건인 저장소는 PR마다 똑같은 100건을 다시 보게 되고, 게이트는 늘 빨간불이거나 꺼진 채로 남습니다.

`--baseline`이 이 문제를 해결합니다. 이전 리포트를 지정하면 거기에 이미 있는 건은 억제됩니다.

```bash
dalfox scan scope.txt -f json -o baseline.json      # 최초 1회, 기존 백로그 기록
dalfox scan scope.txt --baseline baseline.json      # 이후 매 실행
```

베이스라인을 만드는 별도 명령은 없습니다. 평범한 `-f json -o`(또는 `-f jsonl -o`) 리포트가 그대로 베이스라인입니다.

### 모드

| 모드 | 플래그 | 동작 |
|------|--------|------|
| `filter` (기본) | `--baseline-mode filter` | 이미 알려진 건을 제거합니다. 카운트, `--limit`, 종료 코드가 모두 신규 건만 기준으로 정해집니다. CI 게이트에는 이 모드를 쓰세요. |
| `annotate` | `--baseline-mode annotate` | 모든 건을 그대로 두고 각각에 `new: true` / `new: false`를 붙입니다. 전체 집합을 보되 신규 여부를 표시하고 싶은 대시보드용입니다. |

### 무엇을 "같은 건"으로 볼까

지문(fingerprint)은 그 건을 드러낸 실행이 아니라 취약점 자체의 정체성을 기준으로 만듭니다.

**포함:** 호스트 + 경로 · 파라미터 이름 · 파라미터 위치(query / header / cookie / body / path) · 인젝션 컨텍스트 · CWE · 탐지 티어 · 증거 계열(DOM 건의 `Source → Sink` 쌍).

**제외:** 페이로드와 그것이 들어간 쿼리 스트링, 페이로드 순서, AST의 줄/열 번호, 타임스탬프, 요청/응답 캡처.

그래서 실행마다 페이로드가 달라져도 같은 스캔은 깔끔하게 매칭되고, 번들러가 `app.js`의 줄 번호를 바꿔도 이미 처리한 DOM 건이 다시 올라오지 않습니다. 티어가 지문에 들어가므로, 지난주 `R`이던 건이 오늘 `V`가 되면 신규로 보고됩니다. 이런 승격이야말로 게이트가 잡아야 할 변화입니다.

### `meta.baseline` 블록

모든 구조화 형식이 diff 결과를 함께 보고합니다.

```json
"baseline": {
  "baseline_findings": 100,
  "enabled": true,
  "known": 98,
  "mode": "filter",
  "new": 2,
  "path": "baseline.json"
}
```

베이스라인 파일이 없거나, 형식이 깨졌거나, 다른 메이저 버전이 쓴 것이면 stderr에 경고를 내고 diff만 끕니다. 스캔은 그대로 진행됩니다. 파이프라인에 남은 낡은 경로 하나 때문에 멀쩡히 돌던 스캔이 아무것도 보고하지 못하는 빨간 빌드가 되면 안 되기 때문입니다. 이 경우 엔벨로프에 `"enabled": false`와 `warning`이 실리므로, "신규 없음"과 "diff가 아예 돌지 않음"을 구분할 수 있습니다.

### 베이스라인 갱신

전용 명령은 없습니다. `--baseline` 없이 다시 실행해(그래야 리포트에 신규 건만이 아니라 전체 집합이 담깁니다) 파일을 교체하면 됩니다.

```bash
dalfox scan scope.txt -f json -o baseline.json
git commit -am "chore: refresh dalfox baseline"
```

`--baseline`을 켠 채 `-o`를 같은 파일로 지정하면 `filter` 모드에서 베이스라인이 망가집니다. 다시 쓰인 리포트에는 신규 건만 들어 있어서, 다음 실행이 백로그 전체를 다시 보고합니다. 두 경로가 같으면 Dalfox가 경고합니다.

### 주의사항

- `--limit`은 diff 전에 셉니다. 스캔 중 중단 조건은 수집되는 모든 건을 세므로 베이스라인에 이미 있는 건도 포함됩니다. 그래서 처음 10건이 전부 기존 건인 대상에 `--limit 10 --baseline b.json`을 주면, 나머지를 테스트하지 않은 채 일찍 멈추고 "신규 0"을 보고합니다. 신규 건으로 게이트할 때는 `--limit`을 빼세요. 둘을 함께 쓰면 Dalfox가 경고합니다.
- `--baseline`을 주면 `--stream-findings`가 꺼집니다. `--only-poc`과 같은 이유입니다. 스트리머는 어떤 건이 이미 베이스라인에 있는지 알 수 없어서, 요약은 신규만 보고하는데 화면에는 트리아지가 끝난 백로그 전체가 흘러가게 됩니다.
- CLI 전용입니다. `dalfox server`와 MCP 서버는 `--baseline`을 적용하지 않고, 공유 config의 `scan.baseline`도 경고 없이 무시합니다.

## 색상 및 TTY 동작

```bash
dalfox scan https://target.app --no-color
# 또는
NO_COLOR=1 dalfox scan https://target.app
```

출력을 파일이나 TTY가 아닌 곳으로 리디렉션해도 Dalfox는 색상을 자동으로 끕니다.

## TOML

JSON과 같은 데이터를 TOML로 씁니다. 엔벨로프는 최상위 `[meta]` 테이블이고, 탐지 결과는 `[[results]]` 테이블 배열로 렌더링됩니다(JSON의 `findings`가 아니라 `results`입니다).

```toml
[meta]
dalfox_version = "3.2.4"
dedup_mode = "exact"
failed_requests = 0
findings_count = 1
incomplete = false
scan_duration_ms = 1234
targets = ["https://target.app/?q=a"]
targets_deduplicated = 0
total_requests = 87

[[meta.target_summary]]
findings_count = 1
method = "GET"
status = "findings"
target = "https://target.app/?q=a"

[[results]]
type = "V"
type_description = "Vulnerable - dalfox asserts this input is exploitable; act on it"
inject_type = "inHTML"
method = "GET"
data = "https://target.app/?q=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx1ec4110f%3E"
param = "q"
payload = "<svg onload=alert(1) class=dlx1ec4110f>"
evidence = "DOM verification successful for param q (DOM marker)"
cwe = "CWE-79"
severity = "High"
message_id = 606
message_str = "Triggered XSS Payload (DOM marker): q=<svg onload=alert(1) class=dlx1ec4110f>"
location = "Query"
detection_method = "reflection"
confidence = "high"
confidence_reason = "payload reached an executable position in the parsed response"

[results.filter]
allowed = ['"', "$", "'", "(", ")", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "[", '\', "]", "`", "{", "|", "}"]
blocked = []
```

```bash
dalfox scan https://target.app -f toml -o report.toml
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

트리아지 후 베이스라인을 갱신하려면 `--baseline` 없이 실행하고 `-o`를 베이스라인 파일로 지정하세요.

```bash
dalfox scan scope.txt --only-poc v -f json -o .dalfox/baseline.json
```

위 게이트 명령에 `-o .dalfox/baseline.json`만 붙여 다시 돌리면 안 됩니다. *신규* 건만 담긴 리포트가 파일을 덮어써서 기록해 둔 백로그가 사라집니다. `--output`과 `--baseline`이 같은 경로로 해석되면 Dalfox가 stderr에 경고합니다.

## 종료 코드

| 코드 | 의미 |
|------|---------|
| `0` | 정상 완료, 탐지 결과 없음 |
| `1` | 정상 완료, 티어와 무관하게 탐지 결과 하나 이상 |
| `2` | 입력/설정/런타임 오류, 또는 `-o` 파일을 쓰지 못한 경우. 탐지 결과가 없을 때는 다음도 해당: 모든 대상을 건너뜀(접속 불가, 맞지 않는 콘텐츠 타입 등. `--dry-run`과 `--only-discovery`도 마찬가지이며, 이때 JSON/JSONL에 건너뛴 대상과 `error_code`가 들어갑니다), 대상의 스캔 워커가 중단됨(`INTERNAL_ERROR`), 요청의 10% 이상(최소 3건)이 응답을 받지 못함, 기본값 `--on-session-loss abort`에서 스캔 도중 세션이 끊어짐. 이런 경우에도 탐지 결과가 있었다면 `1`로 끝납니다 |

`1`은 모든 티어를 포함합니다. `R` 하나나 `--detect-outdated-libs`가 만든 `I` 하나도 `V`와 똑같이 빌드를 실패시킵니다. Dalfox가 악용 가능하다고 판단한 것만 게이트로 삼으려면 `--only-poc v`를 주고 종료 코드를 그대로 쓰세요. 종료 코드가 정해지기 전에 필터가 적용됩니다. `--min-confidence high`도 등급 기준으로 똑같이 동작해, `low` 탐지 결과만 있던 실행은 `0`으로 끝납니다. (`jq`로 `severity == "High"`를 거는 방식도 지금은 거의 같은 집합을 얻습니다. severity가 티어를 따라가기 때문입니다. `V`는 `High`, `A`는 `Medium`, `R`은 `Info`입니다. 예외는 `I` 라이브러리 결과로, 권고(advisory)의 severity를 그대로 가지므로 `High`일 수 있습니다. [탐지 모델](../detection-model/) 참고.)

`--baseline`은 같은 종료 코드를 신규 여부로 좁힙니다. 기본 `filter` 모드에서는 억제된 건이 종료 코드 판정에 들어가지 않으므로, 백로그가 전부 베이스라인에 들어 있는 실행은 `0`으로 끝납니다. [베이스라인](#베이스라인-새로-생긴-것만-보고하기) 참고.

## 다음 단계

- [REST API 서버](../../integrations/server/)로 스캔을 자동화하세요.
- [MCP 서버](../../integrations/mcp/)로 AI 에이전트가 스캔을 돌리게 하세요.
