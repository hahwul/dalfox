+++
title = "연동"
description = "Dalfox를 CI/CD 파이프라인, 대시보드, Caido, REST 클라이언트, MCP 클라이언트, AI 코딩 에이전트에 연결합니다."
weight = 3
+++

Dalfox는 명령줄 외에도 REST와 MCP를 지원하고, 스킬 인식 에이전트용 SKILL.md를 제공하며, Caido 같은 도구와 직접 연동됩니다. 거의 어디서든 실행할 수 있습니다.

## 연동 방식 선택

- **[REST API 서버](./server/):** 장시간 실행되는 HTTP 서비스. 스캔을 제출하고, 상태를 폴링하고, 작업을 취소하며, Slack, 대시보드, CI/CD, 커스텀 도구와 연동합니다.
- **[MCP 서버](./mcp/):** [Model Context Protocol](https://modelcontextprotocol.io) stdio 서버. Claude, Cursor를 비롯한 모든 MCP 호환 클라이언트에 Dalfox를 도구로 노출합니다.
- **[Caido 워크플로](./caido/):** Caido의 Active Workflows와 Findings에서 Dalfox를 구동해, 프록시 세션 안에서 실시간으로 XSS 테스트를 자동화합니다.
- **[에이전트 스킬](./skills/):** Claude Code, Cursor, OpenCode, Codex 같은 스킬 인식 에이전트에게 Dalfox를 안전하게 구동하는 법을 알려주는, 그대로 얹기만 하면 되는 `SKILL.md`. `npx skills add hahwul/dalfox`로 설치합니다.

모든 연동은 CLI와 같은 스캔 엔진을 씁니다. 다른 것은 연결 방식뿐입니다.
