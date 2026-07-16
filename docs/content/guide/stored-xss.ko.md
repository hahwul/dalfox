+++
title = "저장형 XSS"
description = "한 URL에서 주입하고, 다른 URL에서 페이로드가 실행되는지 검증합니다."
weight = 5
toc = true
+++

저장형 XSS는 서버에 남아 있습니다. 한 번 제출하면(댓글, 프로필 필드, 채팅 메시지) 누군가 해당 페이지를 볼 때마다 실행됩니다. Dalfox에는 이 패턴을 위한 전용 모드가 있습니다.

## 기본 흐름

```bash
dalfox https://target.app/post-comment \
  --sxss \
  --sxss-url https://target.app/comments
```

Dalfox는 다음을 수행합니다.

1. 각 페이로드를 첫 번째 URL(`post-comment`)에 **주입**합니다.
2. 두 번째 URL(`comments`)을 GET으로 **가져옵니다**(`--sxss-method`로 구성 가능).
3. 페이로드가 가져온 응답에 반사되는지, 그리고 실제 DOM 요소를 생성했는지 **검증**합니다.

두 단계를 모두 통과한 탐지 결과만 SXSS로 리포팅됩니다.

## 조회 URL 선택

저장된 값을 **읽어 오는** 페이지를 선택하세요. 예시:

| 주입 URL | 조회 URL |
|---------------|---------------|
| `POST /comments/new` | `GET /post/123/comments` |
| `PATCH /profile` | `GET /u/myself` |
| `POST /support/ticket` | `GET /admin/tickets` (관리자 권한이 있는 경우) |

`--sxss-url`을 생략하면, Dalfox는 응답 헤더(예: POST 이후의 `Location` 리다이렉트)에서 자동으로 감지하려고 시도합니다.

## 조회 메서드

```bash
dalfox https://target.app/form --sxss \
  --sxss-url https://target.app/list \
  --sxss-method GET
```

`GET`이 기본값입니다. 조회 엔드포인트가 필요로 한다면 `POST`나 다른 메서드를 사용하세요.

## 인증

저장형 XSS는 종종 두 개의 세션을 필요로 합니다. 하나는 쓰는 쪽(사용자), 다른 하나는 읽는 쪽(관리자)입니다. 조회 GET이 여러분이 작성한 내용을 볼 수 있을 만큼 충분한 접근 권한을 부여하는 헤더/쿠키를 사용하세요.

```bash
dalfox https://target.app/profile \
  --sxss --sxss-url https://target.app/admin/users \
  -H "Cookie: admin_session=abc; role=admin"
```

## 블라인드 + 저장형

조회 페이지가 여러분이 가지지 못한 로그인 뒤에 있다면, 블라인드 XSS로 전환하세요. 페이로드는 관리자의 브라우저에서 실행되고, 여러분의 콜백 서버가 이를 기록합니다.

```bash
dalfox https://target.app/support/ticket \
  -b https://callback.interact.sh
```

여전히 누군가가 페이지를 볼 때까지 기다려야 하며, 콜백이 그 시점을 알려 줍니다.

## 팁

- **범위를 좁게 설정하세요.** `-p`를 사용해 조회 URL에서 렌더링된다고 알고 있는 필드를 지정하세요. 그러면 Dalfox가 모든 쿠키를 테스트하지 않습니다.
- **정화 후 렌더링에 주의하세요.** 저장형 XSS는 쓰기 시점의 HTML 새니타이저는 통과하지만 읽기 시점의 두 번째 정화 과정에서 깨지는 경우가 많습니다. Dalfox의 mXSS 페이로드는 이에 맞춰 조정되어 있습니다.
- **속도를 늦추세요.** 일부 앱은 쓰기를 디바운스하거나 배치 처리합니다. 작은 `--delay` 값은 조회가 여러분의 페이로드를 보는 데 도움이 됩니다.

## 다음

- 주입되는 페이로드를 조정하려면 [페이로드와 인코딩](../payloads/)을 참고하세요.
- 탐지 결과를 전달하려면 [출력과 리포트](../output/)를 참고하세요.
