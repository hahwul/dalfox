+++
title = "Brand Kit"
description = "Dalfox logo files, brand palette, typography, and usage guidance."
weight = 5
toc = true
+++

Dalfox pairs a fox-and-crescent mark with deep navy, moonlit indigo, and warm fox accents. This page documents the artwork and design tokens used by the project site.

## The mark

Use the full wordmark in documents and presentations. Use the standalone mark when space is square or limited.

<div style="display:flex; flex-wrap:wrap; gap:1rem; margin:1.5rem 0;">
  <figure style="flex:1 1 15rem; margin:0; padding:1.25rem; border-radius:0.75rem; background:#f4f1ea; text-align:center;">
    <a href="../../images/logo.svg"><img src="../../images/logo.svg" alt="Dalfox wordmark for light backgrounds" width="200" style="max-width:100%; height:auto;"></a>
    <figcaption style="color:#1d2030;">Light background · <a href="../../images/logo.svg" style="color:#30365e;">Download SVG</a></figcaption>
  </figure>
  <figure style="flex:1 1 15rem; margin:0; padding:1.25rem; border-radius:0.75rem; background:#0b0d16; text-align:center;">
    <a href="../../images/logo-dark.svg"><img src="../../images/logo-dark.svg" alt="Dalfox wordmark for dark backgrounds" width="200" style="max-width:100%; height:auto;"></a>
    <figcaption style="color:#e9ecf4;">Dark background · <a href="../../images/logo-dark.svg" style="color:#b1b8f5;">Download SVG</a></figcaption>
  </figure>
  <figure style="flex:0 1 11rem; max-width:12rem; margin:0; padding:1.25rem; border-radius:0.75rem; background:#f4f1ea; text-align:center;">
    <a href="../../images/logo_solo.webp"><img src="../../images/logo_solo.webp" alt="Standalone Dalfox fox-and-crescent mark" width="112" style="max-width:100%; height:auto;"></a>
    <figcaption style="color:#1d2030;">Standalone mark · <a href="../../favicon.svg" style="color:#30365e;">SVG</a> · <a href="../../images/logo_solo.png" style="color:#30365e;">PNG</a> · <a href="../../images/logo_solo.webp" style="color:#30365e;">WebP</a></figcaption>
  </figure>
</div>

| Variant | Use | Files |
|---------|-----|-------|
| Wordmark, light | Default on light surfaces | [SVG](../../images/logo.svg) · [PNG](../../images/logo.png) · [WebP](../../images/logo.webp) |
| Wordmark, dark | Use on dark surfaces | [SVG](../../images/logo-dark.svg) |
| Standalone mark | Avatars, favicons, and square artwork | [SVG](../../favicon.svg) · [PNG](../../images/logo_solo.png) · [WebP](../../images/logo_solo.webp) |

The standalone raster files are 512 × 512. The full wordmark raster files are 1920 × 902. Keep the artwork uncropped and preserve its proportions. When the wordmark is too small to read, use the standalone mark.

## Colours

The logo uses brand navy and white. The site adds moonlit indigo and fox-coloured accents, with separate dark and light theme values.

<div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(9rem,1fr)); gap:0.75rem; margin:1rem 0;">
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#30365e;"></span>
    <strong>Brand navy</strong><br><code>#30365E</code><br>
    <small>Mark and primary accent on light surfaces</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#8f99ef;"></span>
    <strong>Moonlight</strong><br><code>#8F99EF</code><br>
    <small>Primary accent on dark surfaces</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#b1b8f5;"></span>
    <strong>Moonlight highlight</strong><br><code>#B1B8F5</code><br>
    <small>Emphasis and active details on dark surfaces</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#d99a63;"></span>
    <strong>Fox ember</strong><br><code>#D99A63</code><br>
    <small>Fox artwork and warm accent on dark surfaces</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border-radius:0.4rem;background:#b8743f;"></span>
    <strong>Paper ember</strong><br><code>#B8743F</code><br>
    <small>Fox artwork and warm accent on light surfaces</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border:1px solid #6e7791;border-radius:0.4rem;background:#0b0d16;"></span>
    <strong>Night</strong><br><code>#0B0D16</code><br>
    <small>Documentation site's dark canvas</small>
  </div>
  <div style="padding:0.85rem; border:1px solid var(--line); border-radius:0.75rem; background:var(--bg-2);">
    <span aria-hidden="true" style="display:block;width:2rem;height:2rem;margin-bottom:0.6rem;border:1px solid #b9b5ad;border-radius:0.4rem;background:#f4f1ea;"></span>
    <strong>Paper</strong><br><code>#F4F1EA</code><br>
    <small>Documentation site's light canvas</small>
  </div>
</div>

The site palette lives in `docs/static/css/style.css`; the logo files live in `docs/static/images/`.

## Typography

- **Inter** for documentation and interface text.
- **JetBrains Mono** for commands, code, and compact technical labels.

## Using the marks

Use the supplied files when referring to Dalfox or showing an integration with it. Do not redraw, recolour, distort, or crop the mark, and do not imply that Dalfox endorses a product or service. The repository is MIT-licensed; it does not publish a separate license for the logo artwork. Contact the maintainers if you need guidance for another use.
