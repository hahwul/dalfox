+++
title = "연동"
description = "파이프라인, 대시보드 또는 AI 어시스턴트에서 Dalfox를 구동합니다."
weight = 3
+++

Dalfox는 커맨드 라인에서 잘 작동하지만, REST와 MCP도 지원하고, 스킬 인식 에이전트를 위한 SKILL.md를 제공하며, Caido 같은 도구에도 직접 연동됩니다. 따라서 거의 어디서든 구동할 수 있습니다.

## 연동 방식 선택

- **[REST API 서버](./server/):** 장시간 실행되는 HTTP 서비스. 스캔을 제출하고, 상태를 폴링하고, 작업을 취소하며, Slack, 대시보드, CI/CD, 커스텀 도구와 연동합니다.
- **[MCP 서버](./mcp/):** [Model Context Protocol](https://modelcontextprotocol.io) stdio 서버. Dalfox를 Claude, Cursor 및 모든 MCP 호환 클라이언트를 위한 도구로 노출합니다.
- **[Agent Skill](./skills/):** Claude Code, Cursor, OpenCode, Codex 및 기타 스킬 인식 에이전트에게 Dalfox를 안전하게 구동하는 방법을 알려주는 즉시 사용 가능한 `SKILL.md`. `npx skills add hahwul/dalfox`로 설치합니다.
- **[Caido 워크플로우](./caido/):** Caido Active Workflows 및 Findings에서 Dalfox를 구동하여 프록시 세션 내에서 실시간 자동화 XSS 테스트를 수행합니다.

모든 연동은 CLI와 완전히 동일한 스캐닝 엔진을 공유합니다. 결과는 동일하며, 연결 방식만 다릅니다.
