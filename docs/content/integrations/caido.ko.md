+++
title = "Caido 워크플로"
description = "Caido Active Workflows와 Findings에서 Dalfox를 자동으로 실행하여 XSS를 실시간으로 잡아냅니다."
weight = 4
toc = true
+++

Dalfox는 [Caido](https://caido.io) 워크플로 안에서 잘 작동합니다. 관심 있는 모든 요청(또는 선택한 트래픽)을 Dalfox 엔진에 곧바로 넣고, 탐지 결과를 클릭 한 번으로 Caido Findings로 전환할 수 있습니다.

이 페이지는 현재 권장 패턴(v3)과 워크플로 작성자를 곤란하게 만드는 흔한 "bool 함정"을 다룹니다.

## 핵심 패턴

Caido Workflows는 셸 단계를 실행할 수 있습니다. 이 단계는 현재 요청을(보통 JSON으로) stdin으로 받습니다. 원시 HTTP를 추출하여 `--input-type raw-http`로 Dalfox에 넘긴 다음, Finding을 생성할지 결정합니다.

### 최소 워크플로 단계 (bash/zsh)

```bash
#!/bin/bash
set -euo pipefail

DALFOX="${DALFOX_PATH:-/usr/local/bin/dalfox}"

# Caido usually sends { "request": "<raw HTTP>", ... }
RAW=$(cat - | jq -r '.request // .raw // .data.request // empty')

if [[ -z "$RAW" ]]; then
    echo "No request payload" >&2
    exit 0
fi

# Write to temp file (robust for multiline + special chars)
TMP=$(mktemp)
printf '%s' "$RAW" > "$TMP"

# Run Dalfox (tune flags to taste)
"$DALFOX" scan --input-type raw-http "$TMP" \
    -S \
    --no-color \
    --poc-type curl \
    --timeout 8

FOUND=$?

rm -f "$TMP"

# Exit code 1 from Dalfox means "findings existed"
if [[ $FOUND -eq 1 ]]; then
    # Caido If/Else: route this to the "finding" branch
    echo "XSS detected"
else
    # Clean – emit a truthy value so Caido treats it as "no finding"
    echo "1"
fi
```

### Caido 불리언 함정 (중요)

Caido의 Workflow If/Else 노드는 자체 [bool 규칙](https://docs.caido.io/app/reference/workflow_data_types.html#bool)을 사용하여 단계 출력을 평가합니다. 사람(또는 일반적인 셸)에게 "참 같아 보이는" 많은 문자열이 Caido 내부에서는 `false`가 됩니다.

**신뢰할 수 있는 커뮤니티 패턴**([이 댓글의 @m4dni5](https://github.com/hahwul/dalfox/discussions/992#discussion-10115370)가 공유):

- 탐지 결과가 있을 때는 실제 Dalfox 출력(또는 비어 있지 않은 마커)을 내보냅니다. Caido는 이를 "False" 분기로 봅니다.
- 깨끗할 때는 `1`이나 `true` 같은 단순한 참 토큰을 명시적으로 내보냅니다. 이는 "True" 분기로 갑니다.

그런 다음 다음과 같이 연결합니다:
- `False` → **Create Finding**
- `True` → (선택) Set Color / Tag / Continue

이것이 위 예시들이 탐지 경로에서만 의도적으로 결과를 출력하는 이유입니다.

## Caido 권장 플래그

| 플래그              | 이유 |
|-------------------|-----|
| `-S` / `--silence` | POC / 탐지 결과 라인만 stdout으로 나갑니다 (Caido 로그의 노이즈 감소) |
| `--no-color`      | 탐지 결과, 검색, 내보내기를 위한 깔끔한 텍스트 (커뮤니티 워크플로 예시에서 제안됨) |
| `--poc-type curl` (또는 `httpie`, `http-request`) | Caido Finding에서 바로 사용할 수 있는 재현 코드 |
| `--timeout 6-10`  | 요청별 예산; 워크플로를 빠릿하게 유지 |
| `--waf-bypass auto` | 프록시 내부에서도 여전히 가치 있음 |

Finding 증거에 전체 마크다운 보고서를 담고 싶다면 `--report --report-format md`를 추가할 수도 있습니다.

**silence 참고:** `-S`는 대부분의 로그를 억제하지만 탐지 결과가 있을 때는 검증된 POC 라인이 여전히 나타납니다. (연결된 논의의 커뮤니티 피드백에서는 더 깔끔한 워크플로 결과를 위해 `-S`가 POC 출력도 완전히 억제하도록 요청하기도 했습니다.) 깨끗한 실행에서 출력이 전혀 없기를 원한다면, 위 패턴(탐지 경로에서만 내보내기)이 이미 그것을 달성합니다.

## 전체 예시: If/Else + Create Finding

일반적인 Caido 워크플로 그래프:

1. **Trigger** (Manual / Proxy / Intercept / Scope filter)
2. **Shell / Execute** 단계에서 위 스크립트를 실행 → 출력이 `$RESULT`에 저장됨
3. **If/Else**
   - 조건: 이전 단계 출력이 거짓 / "False" 경로
   - **False 분기 (탐지)**: Create Finding
     - 제목: `XSS via Dalfox`
     - 요청: 원본
     - 증거 / 설명: `$RESULT` (또는 PoC 라인)
     - 심각도: 규칙에 따라 High / Medium
   - **True 분기 (깨끗)**: Set Color (녹색) 또는 Add Tag `dalfox-clean`

Caido의 추가 컨텍스트(호스트, 메서드, 파라미터 이름 등)로 Finding을 풍부하게 할 수 있습니다.

## 대안: 파일 단계 먼저 사용하기

일부 작성자는 두 단계를 선호합니다:

1. 원시 요청을 임시 파일에 씁니다 (Caido에는 파일 시스템 노드가 있거나 셸에서 할 수 있습니다).
2. `dalfox scan --input-type raw-http /path/to/req.txt ...`를 실행합니다

이것은 워크플로 그래프에서 약간 더 잘 보이지만 디버그하기 쉽습니다.

## 팁 및 함정

- **바이너리 위치**: Caido의 PATH에는 brew, asdf, linuxbrew가 포함되지 않을 수 있습니다. 전체 경로를 사용하거나 워크플로 / Caido 설정에서 `DALFOX_PATH` 환경 변수를 설정하고 `$DALFOX_PATH`를 참조하세요.
- **성능**: 브라우징이 바쁠 때는 Dalfox 단계 *앞에* Content-Type 또는 스코프 내 필터를 추가하세요. Dalfox는 빠르지만 모든 이미지/스타일시트를 스캔할 필요는 없습니다.
- **Blind XSS**: Caido가 구동하는 트래픽에서 대역 외(out-of-band) 탐지를 원할 때 `--blind https://your.collaborator/`를 추가하세요.
- **DOM XSS**: 기본 설정으로 바로 작동합니다 (AST 분석이 응답에서 실행됩니다).
- **JSON 출력**: 이후 워크플로 노드에서 더 고급 후처리를 하려면 `--format jsonl`을 사용하여 스트림을 파싱할 수 있습니다.

## v2 가이드에서 업데이트하기

이전 Dalfox v2 문서는 `dalfox pipe --rawdata`를 사용했습니다. v3에서 이에 해당하는 것은 `dalfox scan --input-type raw-http`(또는 입력 처리가 조정된 숨겨진 `dalfox pipe` 호환 명령)입니다. 위에 표시된 임시 파일 또는 프로세스 치환 방식이 가장 이식성이 높습니다.

표준 raw-http 사용법은 [스캐닝 모드](../guide/scanning-modes/#raw-http-mode) 페이지를 참조하세요.

## 참고

- [스캐닝 모드 – Raw HTTP](../guide/scanning-modes/#raw-http-mode)
- [출력 및 보고서](../guide/output/)
- [WAF 우회](../guide/waf-bypass/)
- GitHub 논의 [#992 (댓글)](https://github.com/hahwul/dalfox/discussions/992#discussion-10115370): Caido If/Else 불리언 우회 스크립트와 `--no-color` 제안이 담긴 원본 커뮤니티 보고
