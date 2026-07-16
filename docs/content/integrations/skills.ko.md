+++
title = "에이전트 스킬"
description = "Claude Code, Cursor, OpenCode, Codex 및 기타 스킬 인식 에이전트를 위한 드롭인 `SKILL.md`."
weight = 3
toc = true
+++

Dalfox는 스킬을 인식하는 모든 에이전트에게 Dalfox를 올바르게 구동하는 법을 가르치는 **SKILL.md**를 함께 제공합니다: 인가 게이트 우선, CLI보다 MCP 우선, 무거운 스캔 전 프리플라이트, `V > A > R` 탐지 결과 우선순위. 에이전트가 이 파일을 참조하게 하면 모델이 플래그를 추측하지 않게 됩니다.

이 파일은 저장소의 [`skills/dalfox/SKILL.md`](https://github.com/hahwul/dalfox/blob/main/skills/dalfox/SKILL.md)에 있으므로, Dalfox를 클론하면 이미 로컬에 확보하게 됩니다.

## `npx skills`로 설치

가장 쉬운 방법은 [오픈 agent-skills CLI](https://github.com/vercel-labs/skills)입니다:

```bash
# Install to the current project (committed, shared with the team)
npx skills add hahwul/dalfox

# Or install globally (~/<agent>/skills/, available everywhere)
npx skills add hahwul/dalfox -g
```

이 CLI는 사용 중인 에이전트(Claude Code, Cursor, Codex, OpenCode, 그리고 [약 45개의 다른 에이전트](https://github.com/vercel-labs/skills#available-agents))를 자동으로 감지하여 각각에 스킬을 연결합니다. 하나만 원한다면 특정 에이전트를 지정하십시오:

```bash
# Only Claude Code
npx skills add hahwul/dalfox -a claude-code

# Non-interactive (CI-friendly)
npx skills add hahwul/dalfox -g -a claude-code -y
```

나중에 업데이트하려면:

```bash
npx skills update dalfox
```

제거하려면:

```bash
npx skills remove dalfox
```

## 수동으로 설치

`npx`를 실행하고 싶지 않다면, 스킬 파일을 에이전트가 기대하는 위치에 클론하십시오. Claude Code의 경우 `~/.claude/skills/dalfox/SKILL.md`입니다:

```bash
mkdir -p ~/.claude/skills/dalfox
curl -o ~/.claude/skills/dalfox/SKILL.md \
  https://raw.githubusercontent.com/hahwul/dalfox/main/skills/dalfox/SKILL.md
```

다른 클라이언트는 각자의 스킬 디렉터리에서 읽어 들입니다. 정확한 경로는 해당 에이전트의 문서를 참고하십시오.

## 스킬이 다루는 내용

- **트리거 조건:** 사용자가 URL의 XSS를 스캔하거나, 반사되는 파라미터를 열거하거나, "dalfox"를 명시적으로 언급할 때 발동됩니다. XSS가 아닌 취약점은 건너뜁니다.
- **인가 게이트:** 스킬은 사용자가 대상에 페이로드를 보낼 권한이 있음을 확인하기 전까지 스캔을 거부합니다.
- **모드 감지:** 사용 가능하면 MCP 도구를 우선 사용하고, 그렇지 않으면 `dalfox` CLI로 대체하며, 둘 다 없으면 설치 방법을 사용자에게 안내합니다.
- **MCP 플레이북:** `preflight_dalfox` → `scan_with_dalfox` → `get_results_dalfox` 폴링(`suggested_poll_interval_ms` 준수) → 완료 시 `delete_scan_dalfox`. 검증된 입력 범위(timeout 1–299초, delay 0–9999ms)를 포함하여 에이전트가 Dalfox가 거부할 값을 보내지 않게 합니다.
- **CLI 시나리오:** POST 본문, 인증된 세션, Burp 경유 프록시, 콜백 URL을 사용하는 블라인드 XSS, 스토어드 XSS, 파이프 입력, 빠른 스모크 테스트, 최대 커버리지 실행, 기계 판독 가능 출력.
- **결과 해석:** 탐지 결과 유형 범례(`V` 검증된 DOM 실행 > `A` AST 탐지 > `R` 반사만 확인)로 에이전트가 확인된 히트를 앞세우도록 합니다.
- **실패 모드:** `reachable: false`, 모든 결과가 R인 경우, 멈춘 스캔, `invalid_params` 응답이 실제로 무엇을 의미하는지, 그리고 이를 어떻게 복구하는지.

## 사전 요구 사항

이 스킬은 `dalfox` 바이너리 또는 [MCP 서버](./mcp/)가 에이전트 환경에서 도달 가능하다고 가정합니다. 먼저 Dalfox를 설치한 뒤([설치 가이드](../../getting-started/installation/)), 스킬을 설치하십시오.

## 작성 팁

스킬 파일은 저장소의 [`skills/dalfox/SKILL.md`](https://github.com/hahwul/dalfox/tree/main/skills/dalfox)에 있습니다. 기여를 환영합니다. 다만 이미 [CLI 참조](../../reference/cli/)에 있는 CLI 참조 자료를 다시 서술하기보다는 *에이전트가 Dalfox를 어떻게 구동해야 하는지*에 초점을 맞춰 주십시오.
