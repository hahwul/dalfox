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
| `dalfox url [url]` | `dalfox scan [url]` | `dalfox [url]`만 써도 됩니다 — `scan`이 기본 서브커맨드입니다. 다만 이 형태는 `--config`, `--debug`, `--no-color`, `-S` 외의 스캔 플래그를 받지 않습니다 |
| `dalfox file [file]` | `dalfox scan [file]` | 입력 종류는 자동으로 판별합니다 |
| `dalfox pipe` | `cat targets \| dalfox scan` (또는 `dalfox scan --input-type pipe`) | 파이프 입력은 `stdin`에서 그대로 읽습니다 |
| `dalfox sxss [url]` | `dalfox scan [url] --sxss` | 저장형 XSS는 이제 스캔 옵션입니다 — [저장형 XSS](../../guide/stored-xss/) 참고 |
| `dalfox server --type mcp` | `dalfox mcp` | MCP는 별도의 stdio 서브커맨드가 되었습니다 — [MCP 서버](../../integrations/mcp/) 참고 |
| `dalfox server` | `dalfox server` | 기본 바인딩 주소가 v2의 `0.0.0.0`에서 `127.0.0.1`로 바뀌었습니다. 모든 인터페이스에서 받으려면 `--host 0.0.0.0`을 주세요. 포트는 그대로 `6664`이고 `--type`은 없어졌습니다 — [REST API 서버](../../integrations/server/) 참고 |
| `dalfox payload --entity-event-handler`, `--entity-useful-tags`, `--entity-special-chars`, `--remote-portswigger`, `--remote-payloadbox` | `dalfox payload event-handlers`, `useful-tags`, `special-chars`, `portswigger`, `payloadbox` | 스위치 대신 위치 인자 하나로 고릅니다. `--enum-*`, `--entity-gf`, `--make-bulk`, `--encoder-url`에 대응하는 셀렉터는 없습니다. 있는 셀렉터는 `dalfox payload --help`로 확인하세요 |

{{ alert(type="info", body="legacy url, file, pipe 서브커맨드는 숨겨진 별칭으로 남아 있습니다. file과 pipe는 v2 형태 그대로입니다. url은 다릅니다. 대상을 -u/--url로 받기 때문에(dalfox url -u URL) v2의 dalfox url URL 형태는 실패하니 dalfox scan URL로 바꾸세요. sxss는 남지 않았습니다. 저장형 XSS 스캔은 scan 서브커맨드의 --sxss 플래그로 옮겨졌습니다.") }}

v2의 `--rawdata`, `--har`, `--http` 입력 스위치도 없어졌습니다. 프록시로 잡아둔 raw HTTP 요청과 HAR 익스포트는 자동으로 판별되며(`dalfox scan request.txt`, `dalfox scan capture.har`), `--input-type raw-http` / `--input-type har`로 강제할 수도 있습니다. 요청 줄에 경로만 있는 raw HTTP 요청은 `:scheme` 의사 헤더가 있으면 그 값을 따르고, 없으면 HTTP/2 신호가 있거나 Host가 `:443`이면 `https`로, 아니면 `http`로 보냅니다. 스킴을 고정하려면 요청 줄에 전체 URL을 쓰세요. [Raw HTTP 모드](../../guide/scanning-modes/#raw-http-모드)와 [HAR 모드](../../guide/scanning-modes/#har-모드)를 참고하세요.

## 2. 이름이 바뀐 플래그

| v2 플래그 | v3 플래그 | 이유와 동작 |
| :--- | :--- | :--- |
| `-w, --worker <int>` | `--workers <int>` | 이름이 바뀌었고 `-w` 단축형은 없습니다. 동시에 도는 스캔 워커 수를 정하며, 기본값이 100에서 50으로 줄었습니다. |
| `-H, --header <string>` | `-H, --headers <string>` | 긴 이름만 복수형이 되었고 `-H`는 그대로입니다. 여러 번 넘길 수 있습니다. |
| `-C, --cookie <string>` | `--cookies <string>` | 일관성을 위해 복수형으로 바꿨고 `-C` 단축형은 없습니다. 여러 번 넘길 수 있습니다. |
| `-p, --param <string>` | `-p, --param <string>` | 같은 플래그지만 위치 접미사를 붙일 수 있습니다: `-p id:query`, `-p sort:body`, `-p token:header`. |
| `--skip-mining-all` | `--skip-mining` | 이름만 바뀌었습니다. |
| `--mining-dict=false`, `--mining-dom=false` | `--skip-mining-dict`, `--skip-mining-dom` | `--skip-*` 형태만 남았습니다(v2에도 있던 플래그입니다). |
| `--output-request`, `--output-response` | `--include-request`, `--include-response` | 이름이 바뀌었고, `--include-all`은 둘 다 켭니다. 여전히 옵트인입니다. |
| `--limit-result <int>` | `--limit <int>` | 이름이 바뀌었고, 상한에 도달하면 스캔을 멈춥니다. `--limit-result-type`은 이름 그대로입니다. |
| `--trigger <url>` (`sxss`) | `--sxss-url <url>` | `--sxss`만 주고 `--sxss-url`을 생략하면 폼 탐색 결과로 확인 URL을 자동 판별합니다. |
| `--silence-force` (`file` / `pipe`) | `-S, --silence` | 이제 `-S`가 PoC 출력만 남깁니다. |
| `--mass`, `--multicast`, `--mass-worker` (`file` / `pipe`) | `--max-concurrent-targets`, `--max-targets-per-host` | 대상은 항상 동시에 스캔하며, 이 두 플래그로 그 폭을 제한합니다. |

플래그 전체 목록은 [CLI 레퍼런스](../../reference/cli/)에 있습니다.

## 3. 사라진 기능과 대안

v3를 빠르고 안전하게, XSS에만 집중하도록 유지하기 위해 몇몇 레거시 플래그와 그 뒤의 무거운 엔진을 걷어냈습니다.

| 사라진 v2 플래그 | 대안 | 이유 |
| :--- | :--- | :--- |
| `--use-bav`, `--skip-bav` | 없음. | **범위**. BAV(Basic Another Vulnerability) 점검을 제거했습니다. v3는 오직 XSS 스캐너이며, 다른 취약점 유형은 전용 스캐너를 쓰는 편이 낫습니다. |
| `--found-action <cmd>`, `--found-action-shell` | [REST API 웹훅](../../integrations/server/), 또는 stdout 파이프(`dalfox scan ... \| post-script.sh`). | **보안**. 결과마다 임의 셸 명령을 실행하는 구조는 RCE 위험을 불러오고 동시성도 발목 잡았습니다. |
| `--skip-headless`, `--force-headless-verification` | 설정할 것이 없습니다 — 정적 분석이 기본으로 켜져 있습니다(`--skip-ast-analysis`로 끌 수 있습니다). | **엔진 교체**. Headless Chrome(`chromedp`)을 완전히 없앴습니다. v3는 컴파일러급 JavaScript 파서(`oxc`)로 데이터 흐름과 DOM 싱크를 브라우저 없이 추적합니다. [탐지 모델](../../guide/detection-model/) 참고. |
| `--grep <file>`, `--skip-grepping` | 없음. | **엔진 교체**. 정규식 응답 매칭 대신 컨텍스트를 아는 AST 분석을 씁니다. `--only-poc g`(grep 결과)도 함께 사라졌습니다. |
| `--report`, `--report-format` | `-f markdown -o <file>`, `-f sarif -o <file>`. | **표준화**. 리포트 전용 플래그를 출력 형식 플래그로 합쳤습니다 — [출력과 리포트](../../guide/output/) 참고. |
| `--max-cpu` | 자동. | **구조 변화**. 비동기 스케줄러(`tokio`)가 코어에 작업을 알아서 분배하므로 수동 CPU 고정은 의미가 없습니다. |
| `--no-spinner` | 자동. | **UI**. 스피너와 진행 표시줄은 stdout이 터미널이고 `-S`가 꺼져 있을 때만 그려집니다. 배너는 `-S`와 `plain`을 제외한 모든 출력 형식에서 빠집니다. |
| `--context-aware`, `--magic-char-test` | 설정할 것이 없습니다. | **기본 내장**. 반사되는 모든 파라미터에 문자별 프로브(`valid_specials` / `invalid_specials`)를 보내고, 그 결과로 페이로드를 고릅니다. |
| `--deep-domxss`, `--detailed-analysis`, `--fast-scan`, `--har-file-path`, `--output-all` | 없음. | **제거됨**. 대신할 v3 플래그가 없습니다. v3는 HAR 파일을 입력으로 읽지만 기록하지는 않습니다. |

헤드리스 검증이 없어졌기 때문에 결과의 증거 등급이 v2보다 중요해졌습니다. `[V]`는 파싱한 응답에서 DOM 수준으로 확인된 것이고, `[A]`는 정적 분석이 찾아낸 소스→싱크 흐름으로 브라우저에서 한 번 확인해볼 값입니다. 등급 판정은 [탐지 모델](../../guide/detection-model/)에서 설명합니다.

## 4. v3에서 새로 생긴 것

- **MCP 서버(`dalfox mcp`)** — stdio 위의 JSON-RPC로 AI 코딩 어시스턴트에 Dalfox를 노출하며, v2의 `server --type mcp`를 대신합니다. [MCP 서버](../../integrations/mcp/) 참고.
- **시간 예산(`--scan-timeout <secs>`)** — 대상별 페이로드 주입 단계에 상한을 두어, 반쯤 멈춘 서버가 실행을 붙잡지 못하게 합니다. 사전 점검, 탐색, 마이닝은 그 단계보다 먼저 실행되어 이 상한에 포함되지 않으며, 거기에는 요청 단위 `--timeout`만 적용됩니다. (`dalfox server`와 MCP의 `scan_timeout`은 작업 전체에 적용됩니다.)
- **페이로드 상한(`--max-payloads-per-param <int>`)** — 조합 폭발(우회 × 인코더)이 요청 폭주로 번지지 않게 막습니다.
- **사전 점검(`--dry-run`)** — 페이로드를 한 개도 보내지 않고 탐색된 파라미터와 예상 요청 수를 보여줍니다.
- **적응형 WAF 우회(`--waf-evasion`)** — v2에도 있던 플래그지만 그때는 `worker=1, delay=3s`로 고정된 프리셋이었습니다. v3에서는 (WAF 탐지 여부와 무관하게) 요청 간격을 무작위화하고, 차단 응답이 몰릴 때 쿨다운을 점증시킵니다. [WAF 우회](../../guide/waf-bypass/) 참고.
- **HTTP 파라미터 오염(`--hpp`)** — 쿼리 파라미터를 중복시켜 문자열 매칭에 의존하는 WAF를 지나갑니다.
- **관리형 OAST(`--blind-oob`)** — interactsh 세션을 등록하고 콜백을 그것을 일으킨 페이로드와 연결합니다. 기존의 `-b` 콜백 URL과 함께 쓸 수 있습니다.
- **속도 조절과 재시도(`--rate-limit`, `--retries`)** — 모든 워커가 공유하는 전역 초당 요청 상한, 그리고 5xx와 일시적 오류에 대한 백오프 재시도.
- **이어서 하기와 증분 실행(`--state-file`, `--baseline`)** — 이전 실행에서 끝낸 대상은 건너뛰거나, 이전 JSON 리포트 이후 새로 생긴 결과만 보고합니다.
- **세션 감시** — 스캔에 자격증명이 있으면 자동으로 켜지며(`--session-check`로 확인할 마커를 직접 지정할 수 있습니다), 인증된 스캔 도중 세션이 끊기면 깨끗한 결과가 아니라 미완료로 보고합니다. [세션 모니터링](../../guide/scanning-modes/#세션-모니터링) 참고.
- **셸 자동완성(`dalfox completion <shell>`)** — bash, zsh, fish, PowerShell, Elvish.

## 다음 단계

- [스캔 모드](../../guide/scanning-modes/)를 다시 읽어보세요. 손이 기억하는 플래그가 옮겨졌을 수 있습니다.
- 자주 쓰는 v2 명령줄은 [설정 파일](../configuration/)로 옮기세요.
- [CLI 레퍼런스](../../reference/cli/)에서 v2에 아예 없던 플래그들을 훑어보세요.
