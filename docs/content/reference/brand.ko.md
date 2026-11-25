+++
title = "브랜드 키트"
description = "Dalfox 로고 파일, 색상 팔레트, 서체와 사용 지침입니다."
weight = 5
toc = true
+++

Dalfox는 여우와 초승달을 결합한 심볼에 짙은 네이비, 달빛을 닮은 인디고, 따뜻한 여우빛 색상을 사용합니다. 이 페이지에는 프로젝트 사이트에서 사용하는 그래픽과 디자인 토큰을 정리했습니다.

## 심볼과 로고

문서와 발표 자료에는 워드마크를 사용하세요. 정사각형 공간이거나 크기가 작을 때는 단독 심볼을 사용하세요.

<div style="display:flex; flex-wrap:wrap; gap:1rem; margin:1.5rem 0;">
  <figure style="flex:1 1 13rem; margin:0; padding:1.25rem; border-radius:0.75rem; background:#f4f1ea; text-align:center;">
    <a href="../../../images/logo.svg"><img src="../../../images/logo.svg" alt="밝은 배경용 Dalfox 워드마크" width="200" style="max-width:100%; height:auto;"></a>
    <figcaption style="color:#1d2030;">밝은 배경 · <a href="../../../images/logo.svg" style="color:#30365e;">SVG 다운로드</a></figcaption>
  </figure>
  <figure style="flex:1 1 13rem; margin:0; padding:1.25rem; border-radius:0.75rem; background:#0b0d16; text-align:center;">
    <a href="../../../images/logo-dark.svg"><img src="../../../images/logo-dark.svg" alt="어두운 배경용 Dalfox 워드마크" width="200" style="max-width:100%; height:auto;"></a>
    <figcaption style="color:#e9ecf4;">어두운 배경 · <a href="../../../images/logo-dark.svg" style="color:#b1b8f5;">SVG 다운로드</a></figcaption>
  </figure>
  <figure style="flex:0 1 13rem; max-width:13rem; margin:0; padding:1.25rem; border-radius:0.75rem; background:#f4f1ea; text-align:center;">
    <div style="display:flex; justify-content:center; gap:0.75rem; margin-bottom:0.75rem;">
      <a href="../../../images/logo_solo.svg" style="display:block; width:4.5rem; padding:0.25rem; border-radius:0.5rem; background:#f4f1ea;"><img src="../../../images/logo_solo.svg" alt="밝은 배경용 Dalfox 단독 심볼" width="72" style="max-width:100%; height:auto;"></a>
      <a href="../../../images/logo_solo-dark.svg" style="display:block; width:4.5rem; padding:0.25rem; border-radius:0.5rem; background:#0b0d16;"><img src="../../../images/logo_solo-dark.svg" alt="어두운 배경용 Dalfox 단독 심볼" width="72" style="max-width:100%; height:auto;"></a>
    </div>
    <figcaption style="color:#1d2030;">단독 심볼 · <a href="../../../images/logo_solo.svg" style="color:#30365e;">밝은 SVG</a> · <a href="../../../images/logo_solo-dark.svg" style="color:#30365e;">어두운 SVG</a> · <a href="../../../images/logo_solo.png" style="color:#30365e;">PNG</a> · <a href="../../../images/logo_solo.webp" style="color:#30365e;">WebP</a></figcaption>
  </figure>
</div>

| 종류 | 용도 | 파일 |
|------|------|------|
| 밝은 배경용 워드마크 | 밝은 표면의 기본 로고 | [SVG](../../../images/logo.svg) · [PNG](../../../images/logo.png) · [WebP](../../../images/logo.webp) |
| 어두운 배경용 워드마크 | 어두운 표면 | [SVG](../../../images/logo-dark.svg) |
| 단독 심볼 | 아바타, 파비콘, 정사각형 그래픽에서 배경 대비에 맞는 버전 사용 | [밝은 SVG](../../../images/logo_solo.svg) · [어두운 SVG](../../../images/logo_solo-dark.svg) · [PNG](../../../images/logo_solo.png) · [WebP](../../../images/logo_solo.webp) |

단독 심볼 래스터 파일은 512 × 512, 워드마크 래스터 파일은 1920 × 902입니다. 로고를 자르지 말고 비율을 유지하세요. 워드마크를 알아보기 어려울 만큼 작게 써야 한다면 단독 심볼을 사용하세요.

## 색상

로고는 브랜드 네이비와 흰색을 사용합니다. 문서 사이트는 여기에 달빛 인디고와 여우빛 강조색을 더하며, 어두운 테마와 밝은 테마에서 각각 다른 값을 씁니다.

<div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(9rem,1fr)); gap:0.75rem; margin:1rem 0;">
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#30365e;"></span>
    <strong>브랜드 네이비</strong><br><code>#30365E</code><br>
    <small>심볼, 밝은 표면의 기본 강조색</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#8f99ef;"></span>
    <strong>달빛</strong><br><code>#8F99EF</code><br>
    <small>어두운 표면의 기본 강조색</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#b1b8f5;"></span>
    <strong>달빛 하이라이트</strong><br><code>#B1B8F5</code><br>
    <small>어두운 표면의 강조·활성 상태</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#d99a63;"></span>
    <strong>여우빛 주황</strong><br><code>#D99A63</code><br>
    <small>여우 그래픽, 어두운 표면의 따뜻한 강조색</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#b8743f;"></span>
    <strong>종이빛 주황</strong><br><code>#B8743F</code><br>
    <small>여우 그래픽, 밝은 표면의 따뜻한 강조색</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border:1px solid #6e7791;border-radius:0.4rem;background:#0b0d16;"></span>
    <strong>밤</strong><br><code>#0B0D16</code><br>
    <small>문서 사이트의 어두운 배경</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border:1px solid #b9b5ad;border-radius:0.4rem;background:#f4f1ea;"></span>
    <strong>종이</strong><br><code>#F4F1EA</code><br>
    <small>문서 사이트의 밝은 배경</small>
  </div>
</div>

문서 사이트 색상은 `docs/static/css/style.css`에, 로고 파일은 `docs/static/images/`에 있습니다.

## 서체

- 문서와 인터페이스에는 **Inter**를 사용합니다.
- 명령어, 코드, 짧은 기술 라벨에는 **JetBrains Mono**를 사용합니다.

## 로고 사용

Dalfox를 소개하거나 Dalfox와의 연동을 표시할 때 제공된 파일을 사용하세요. 심볼을 다시 그리거나 색을 바꾸고, 비율을 변형하거나 자르지 마세요. Dalfox가 제품이나 서비스를 보증하는 듯한 인상을 주어서도 안 됩니다. 저장소는 MIT 라이선스를 사용하지만 로고 그래픽에 대한 별도 라이선스는 공개되어 있지 않습니다. 다른 용도가 필요하면 관리자에게 문의하세요.
