+++
title = "v2에서 마이그레이션"
description = "Dalfox v2(Go)와 v3(Rust) 사이에 바뀐 것들 — 통합된 서브커맨드, 이름이 바뀐 플래그, 사라진 기능과 그 대안."
weight = 5
toc = true
+++

Dalfox v3은 기존 Go 구조를 버리고 Rust로 완전히 새로 작성한 버전입니다. Go 소스는 [`v2` 브랜치](https://github.com/hahwul/dalfox/tree/v2)에 남아 있고 치명적인 보안 수정만 백포트됩니다. 새로운 작업은 모두 v3에서 이루어집니다.

이 페이지는 v2 작업 흐름을 v3에 옮기는 방법을 정리합니다. 어떤 서브커맨드가 하나로 합쳐졌고, 어떤 플래그 이름이 바뀌었고, 무엇이 왜 사라졌으며 그 대가로 무엇을 얻었는지 다룹니다.

## 1. 서브커맨드 통합

v3는 스캔 관련 서브커맨드를 하나의 진입점으로 모았습니다.

| v2 사용법 | v3 대응 | 설명 |
| :--- | :--- | :--- |
| `dalfox url [url]` | `dalfox scan [url]` | `dalfox [url]`만 써도 됩니다 — `scan`이 기본 서브커맨드입니다 |
| `dalfox file [file]` | `dalfox scan [file]` | 입력 종류는 자동으로 판별합니다 |
| `dalfox pipe` | `cat targets \| dalfox scan` (또는 `dalfox scan --input-type pipe`) | 파이프 입력은 `stdin`에서 그대로 읽습니다 |
| `dalfox sxss [url]` | `dalfox scan [url] --sxss` | 저장형 XSS는 이제 스캔 옵션입니다 — [저장형 XSS](../../guide/stored-xss/) 참고 |

{{ alert(type="info", body="기존 스크립트가 계속 동작하도록 legacy url, file, pipe 서브커맨드는 숨겨진 별칭으로 남아 있습니다. sxss는 예외입니다. 저장형 XSS 스캔은 scan 서브커맨드의 --sxss 플래그로 옮겨졌습니다.") }}

자동 판별은 v2가 읽지 못했던 입력 형식까지 다룹니다. 프록시로 잡아둔 원시 HTTP 요청(`--input-type raw-http`)과 HAR 익스포트(`dalfox scan capture.har`)를 그대로 넘길 수 있습니다. [빠른 시작](../quick-start/)을 참고하세요.

## 2. 이름이 바뀐 플래그

| v2 플래그 | v3 플래그 | 이유와 동작 |
| :--- | :--- | :--- |
| `--concurrence <int>` | `--workers <int>` | 이름만 바뀌었습니다. 동시에 도는 스캔 워커 수를 정합니다. |
| `-C, --cookie <string>` | `--cookies <string>` | 일관성을 위해 복수형으로 바꿨고, 여러 번 넘길 수 있습니다. |
| `-p <string>` | `-p, --param <string>` | 파라미터 종류까지 지정합니다 — `-p id:query`, `-p sort:body`. |

플래그 전체 목록은 [CLI 레퍼런스](../../reference/cli/)에 있습니다.

## 3. 사라진 기능과 대안

v3를 빠르고 안전하게, XSS에만 집중하도록 유지하기 위해 몇몇 레거시 플래그와 그 뒤의 무거운 엔진을 걷어냈습니다.

| 사라진 v2 플래그 | 대안 | 이유 |
| :--- | :--- | :--- |
| `--use-bav`, `--skip-bav` | 없음. | **범위**. BAV(Basic Another Vulnerability) 점검을 제거했습니다. v3는 오직 XSS 스캐너이며, 다른 취약점 유형은 전용 스캐너를 쓰는 편이 낫습니다. |
| `--found-action <cmd>`, `--found-action-shell` | [REST API 웹훅](../../integrations/server/), 또는 stdout 파이프(`dalfox scan ... \| post-script.sh`). | **보안**. 결과마다 임의 셸 명령을 실행하는 구조는 RCE 위험을 불러오고 동시성도 발목 잡았습니다. |
| `--skip-headless`, `--force-headless-verification` | 설정할 것이 없습니다 — 정적 분석이 항상 켜져 있습니다. | **엔진 교체**. Headless Chrome(`chromedp`)을 완전히 없앴습니다. v3는 컴파일러급 JavaScript 파서(`oxc`)로 데이터 흐름과 DOM 싱크를 브라우저 없이 추적합니다. [탐지 모델](../../guide/detection-model/) 참고. |
| `--grep <file>`, `--skip-grep` | 없음. | **엔진 교체**. 정규식 응답 매칭 대신 컨텍스트를 아는 AST 분석을 씁니다. |
| `--report`, `--report-format` | `-f markdown -o <file>`, `-f sarif -o <file>`. | **표준화**. 리포트 전용 플래그를 출력 형식 플래그로 합쳤습니다 — [출력과 리포트](../../guide/output/) 참고. |
| `--max-cpu` | 자동. | **구조 변화**. 비동기 스케줄러(`tokio`)가 코어에 작업을 알아서 분배하므로 수동 CPU 고정은 의미가 없습니다. |
| `--no-spinner` | 자동. | **UI**. 파이프, 조용한 모드(`-S`), 기계가 읽는 출력 형식(`json`, `sarif` 등)에서는 배너와 스피너가 알아서 억제됩니다. |

헤드리스 검증이 없어졌기 때문에 결과의 증거 등급이 v2보다 중요해졌습니다. `[V]`는 파싱한 응답에서 DOM 수준으로 확인된 것이고, `[A]`는 정적 분석이 찾아낸 소스→싱크 흐름으로 브라우저에서 한 번 확인해볼 값입니다. 등급 판정은 [탐지 모델](../../guide/detection-model/)에서 설명합니다.

## 4. v3에서 새로 생긴 것

- **MCP 서버(`dalfox mcp`)** — JSON-RPC로 AI 코딩 어시스턴트에 Dalfox를 노출합니다. [MCP 서버](../../integrations/mcp/) 참고.
- **시간 예산(`--scan-timeout <secs>`)** — 대상별 전체 스캔 시간을 제한해, 반쯤 멈춘 서버가 실행을 붙잡지 못하게 합니다.
- **페이로드 상한(`--max-payloads-per-param <int>`)** — 조합 폭발(우회 × 인코더)이 요청 폭주로 번지지 않게 막습니다.
- **사전 점검(`--dry-run`)** — 페이로드를 한 개도 보내지 않고 탐색된 파라미터와 예상 요청 수를 보여줍니다.
- **적응형 WAF 우회(`--waf-evasion`)** — WAF가 탐지되면 요청 간격을 무작위화하고, 차단 응답이 몰릴 때 쿨다운을 점증시킵니다. [WAF 우회](../../guide/waf-bypass/) 참고.
- **HTTP 파라미터 오염(`--hpp`)** — 쿼리 파라미터를 중복시켜 문자열 매칭에 의존하는 WAF를 지나갑니다.

## 다음 단계

- [스캔 모드](../../guide/scanning-modes/)를 다시 읽어보세요. 손이 기억하는 플래그가 옮겨졌을 수 있습니다.
- 자주 쓰는 v2 명령줄은 [설정 파일](../configuration/)로 옮기세요.
- [CLI 레퍼런스](../../reference/cli/)에서 v2에 아예 없던 플래그들을 훑어보세요.
