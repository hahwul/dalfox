+++
title = "강력한 XSS 스캐너"
description = "오픈소스 XSS 스캐너이자 자동화 도구. 반사형, 저장형, DOM 기반 XSS를 AST 수준으로 검증합니다."
template = "landing"
+++

<section class="hero">
  <div class="hero-illustration" aria-hidden="true"></div>
  <div class="hero-inner">
    <h1 class="hero-title">
      <span class="strike">모든</span> <span class="accent">XSS</span>를 사냥하세요,<br>
      당하기 전에.
    </h1>
    <p class="hero-desc">
      반사형, 저장형, DOM 기반 취약점을 파라미터마다 AST 수준의 정밀도로 찾아내고 검증합니다.
    </p>
    <div class="hero-actions">
      <a href="./getting-started/" class="btn btn-primary">
        시작하기
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
      </a>
      <a href="https://github.com/hahwul/dalfox" class="btn btn-secondary" target="_blank" rel="noopener">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
        GitHub에서 스타
      </a>
    </div>
  </div>
</section>

<div class="stats-bar">
  <div class="stats-inner">
    <div class="stat-item">
      <span class="stat-value">6</span>
      <span class="stat-label">스캔 모드</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">AST</span>
      <span class="stat-label">DOM 검증</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">MCP</span>
      <span class="stat-label">AI 지원</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">OSS</span>
      <span class="stat-label">MIT 라이선스</span>
    </div>
  </div>
</div>

<section class="section section--terminal">
  <div class="section-inner">
    <h2 class="section-title">명령 하나로, 검증된 결과까지</h2>
    <p class="section-desc">Dalfox에 대상을 넘기면 파라미터를 탐색하고, 컨텍스트를 확인하고, 페이로드를 주입한 뒤, 리포트에 담기 전에 DOM 수준에서 적중을 확인합니다.</p>
    <div class="terminal-demo">
      <div class="hero-visual">
        <div class="terminal">
          <div class="terminal-bar">
            <div class="terminal-dots">
              <span class="terminal-dot red"></span>
              <span class="terminal-dot amber"></span>
              <span class="terminal-dot green"></span>
            </div>
            <div class="terminal-title">dalfox · scan</div>
          </div>
          <div class="terminal-body">
            <div class="t-line"><span class="t-prompt">$</span><span class="t-cmd">dalfox scan https://xss-game.appspot.com/level1/frame</span></div>
            <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> start scan to https://xss-game.appspot.com/level1/frame</div>
            <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> found reflected 1 params</div>
            <div class="t-line t-dim">└── query valid_specials="/\'{`<>"();=|}[.:]+,$-" invalid_specials=""</div>
            <div class="t-line"></div>
            <div class="t-line"><span class="t-ts">6:42PM</span> <span class="t-wrn">WRN</span> XSS found 1 XSS</div>
            <div class="t-line"><span class="t-poc">[POC][V][GET][inHTML]</span> ...?query=%3Csvg%2Fonload%3Dalert%281%29%3E</div>
            <div class="t-line t-dim">  ├── Issue: XSS payload DOM object identified</div>
            <div class="t-line t-dim">  ├── Payload: &lt;svg/onload=alert(1)&gt;</div>
            <div class="t-line t-dim">  └── L13: matches for &#x3c;svg/onload=alert(1)&#x3e;</div>
            <div class="t-line"></div>
            <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> scan completed in 3.482 seconds</div>
            <div class="t-line t-cursor"></div>
          </div>
        </div>
      </div>
      <div class="hero-install" data-install>
        <div class="hero-install-pm">
          <button class="hero-install-pm-btn" type="button" aria-haspopup="listbox" aria-expanded="false" aria-label="설치 방법 선택">
            <span class="hero-install-pm-label">brew</span>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <ul class="hero-install-pm-menu" role="listbox" aria-label="설치 방법">
            <li role="option" class="is-selected" aria-selected="true" data-label="brew" data-cmd="brew install dalfox">Homebrew</li>
            <li role="option" aria-selected="false" data-label="snap" data-cmd="sudo snap install dalfox">Snap</li>
            <li role="option" aria-selected="false" data-label="aur" data-cmd="yay -S dalfox">Arch (AUR)</li>
            <li role="option" aria-selected="false" data-label="nix" data-cmd="nix profile install github:hahwul/dalfox">Nix</li>
            <li role="option" aria-selected="false" data-label="cargo" data-cmd="cargo install dalfox">Cargo</li>
          </ul>
        </div>
        <span class="hero-install-sep" aria-hidden="true"></span>
        <span class="dollar">$</span>
        <code>brew install dalfox</code>
        <button class="hero-install-copy" type="button">복사</button>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <p class="section-eyebrow">// 기능</p>
    <h2 class="section-title">스캐너 하나로 XSS 작업 전체를</h2>
    <p class="section-desc">URL 하나든 전체 파이프라인이든 그대로 돌립니다. CLI, 파일 배치, 파이프, 서버, MCP까지 어느 쪽이든 같은 엔진이 동작하고, 모든 결과는 파싱과 DOM 검증을 거쳐 바로 활용할 수 있는 형식으로 돌아옵니다.</p>
    <div class="features-grid">
      <div class="feature-cell wide">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
        </div>
        <h3>깊이 있는 XSS 탐색</h3>
        <p>반사형, 저장형, DOM 기반 XSS를 페이로드 최적화와 함께 찾습니다. AST 기반 DOM 검증 덕분에 단순 반사로 인한 오탐이 사라집니다.</p>
        <div class="feature-tags">
          <span class="feature-tag">reflected</span>
          <span class="feature-tag">stored</span>
          <span class="feature-tag">dom</span>
          <span class="feature-tag">ast-verify</span>
        </div>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m7 11 2-2-2-2"/><path d="M11 13h4"/><rect x="3" y="3" width="18" height="18" rx="2"/></svg>
        </div>
        <h3>파라미터 인텔리전스</h3>
        <p>마이닝, 정적 분석, BAV 테스트, 컨텍스트 인식 문자셋 프로빙으로 모든 파라미터에 완전한 공격 프로파일을 만듭니다.</p>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4"/><path d="M12 18v4"/><path d="m4.93 4.93 2.83 2.83"/><path d="m16.24 16.24 2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="m4.93 19.07 2.83-2.83"/><path d="m16.24 7.76 2.83-2.83"/></svg>
        </div>
        <h3>WAF 인식</h3>
        <p>주요 WAF를 핑거프린팅하고 인코딩, 대소문자 변형, 폴리글롯 기법으로 페이로드를 변형해 우회합니다.</p>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        </div>
        <h3>파이프라인을 위한 설계</h3>
        <p>파이프, 파일 배치, 서버 모드가 CI/CD에 들어맞습니다. 프록시, 크롤러, 정찰 스택 뒤에 Dalfox를 연결하세요.</p>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>
        </div>
        <h3>REST API &amp; MCP</h3>
        <p>Dalfox를 REST로 제어하는 상시 서버로 실행하거나, 에이전트와 IDE에 MCP 도구로 노출합니다.</p>
      </div>
      <div class="feature-cell full">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        </div>
        <h3>바로 제출할 수 있는 리포트</h3>
        <p>터미널의 간결한 출력부터 GitHub 코드 스캐닝용 SARIF까지, 작업 흐름에 맞는 형식으로 내보냅니다.</p>
        <div class="feature-tags">
          <span class="feature-tag">JSON</span>
          <span class="feature-tag">JSONL</span>
          <span class="feature-tag">Markdown</span>
          <span class="feature-tag">SARIF</span>
          <span class="feature-tag">TOML</span>
          <span class="feature-tag">Plain</span>
          <span class="feature-tag">Silence</span>
        </div>
      </div>
    </div>
  </div>
</section>

<section class="section section--modes">
  <div class="modes-illustration" aria-hidden="true"></div>
  <div class="section-inner">
    <p class="section-eyebrow">// 모드</p>
    <h2 class="section-title">Dalfox를 실행하는 여섯 가지 방법</h2>
    <p class="section-desc">대상에 맞는 형태를 고르세요. 모든 모드가 같은 탐색·검증 엔진을 공유합니다.</p>
    <div class="modes" data-modes>
      <input class="mode-radio" type="radio" name="dalfox-mode" id="m-url" checked>
      <input class="mode-radio" type="radio" name="dalfox-mode" id="m-file">
      <input class="mode-radio" type="radio" name="dalfox-mode" id="m-pipe">
      <input class="mode-radio" type="radio" name="dalfox-mode" id="m-sxss">
      <input class="mode-radio" type="radio" name="dalfox-mode" id="m-server">
      <input class="mode-radio" type="radio" name="dalfox-mode" id="m-mcp">
      <div class="mode-tabs" role="tablist" aria-label="Dalfox 실행 모드">
        <label class="mode-tab" for="m-url"><span class="mode-tab-name">URL</span><span class="mode-tab-sub">단일 대상</span></label>
        <label class="mode-tab" for="m-file"><span class="mode-tab-name">FILE</span><span class="mode-tab-sub">목록 일괄 처리</span></label>
        <label class="mode-tab" for="m-pipe"><span class="mode-tab-name">PIPE</span><span class="mode-tab-sub">stdin 파이프라인</span></label>
        <label class="mode-tab" for="m-sxss"><span class="mode-tab-name">SXSS</span><span class="mode-tab-sub">저장형 XSS</span></label>
        <label class="mode-tab" for="m-server"><span class="mode-tab-name">SERVER</span><span class="mode-tab-sub">REST 데몬</span></label>
        <label class="mode-tab" for="m-mcp"><span class="mode-tab-name">MCP</span><span class="mode-tab-sub">에이전트 네이티브</span></label>
      </div>
      <div class="mode-panels">
        <div class="mode-panel" data-mode="url">
          <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan https://target.app</code></div>
          <p>Dalfox에 URL 하나를 넘기세요. 파라미터를 마이닝하고, 각 컨텍스트를 프로빙하고, 모든 적중을 DOM 수준에서 검증합니다.</p>
        </div>
        <div class="mode-panel" data-mode="file">
          <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan urls.txt</code></div>
          <p>파일에 담긴 대상 목록을 한 줄에 하나씩, 같은 엔진과 하나의 리포트로 훑습니다.</p>
        </div>
        <div class="mode-panel" data-mode="pipe">
          <div class="mode-panel-cmd"><span class="dollar">$</span><code>cat urls.txt | dalfox scan</code></div>
          <p>stdin으로 대상을 읽어 Dalfox를 크롤러나 정찰 파이프라인에 곧장 연결합니다.</p>
        </div>
        <div class="mode-panel" data-mode="sxss">
          <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan https://app/post --sxss-url https://app/feed</code></div>
          <p>한 엔드포인트에서 주입하고, 페이로드가 다른 곳에서 실행되는지 확인합니다. 저장형 XSS를 처음부터 끝까지 검증합니다.</p>
        </div>
        <div class="mode-panel" data-mode="server">
          <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox server</code></div>
          <p>비동기 스캔 작업, 연동, 대시보드를 위한 상시 REST API로 Dalfox를 실행합니다.</p>
        </div>
        <div class="mode-panel" data-mode="mcp">
          <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox mcp</code></div>
          <p>Dalfox를 MCP 도구로 노출해 에이전트와 IDE가 대신 스캔하도록 합니다.</p>
        </div>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <h2 class="section-title">설치부터 검증된 결과까지, 세 단계로</h2>
    <p class="section-desc">Dalfox는 이미 쓰고 있는 환경에 그대로 들어갑니다. 거창한 설치 절차도, 먼저 세워야 할 오케스트레이션 계층도 없습니다.</p>
    <div class="how-steps">
      <div class="how-step">
        <h3>설치</h3>
        <p>Homebrew, Snap, Nix, cargo, 또는 사전 빌드된 바이너리로 Dalfox를 받으세요. 명령 하나면 되고, 관리할 런타임이 없습니다.</p>
        <code>brew install dalfox</code>
      </div>
      <div class="how-step">
        <h3>대상 지정</h3>
        <p>URL이나 파일을 주거나 크롤링 결과를 파이프로 넘기세요. Dalfox가 파라미터를 마이닝하고 컨텍스트를 프로빙하며 상황에 맞춰 조정합니다.</p>
        <code>dalfox scan https://target.app</code>
      </div>
      <div class="how-step">
        <h3>결과 전달</h3>
        <p>SARIF, JSON, Markdown으로 내보내거나 결과를 파이프라인으로 프록시하세요. 결과는 추측이 아니라 검증을 거쳐 나옵니다.</p>
        <code>dalfox scan urls.txt -o report.sarif</code>
      </div>
    </div>
  </div>
</section>

<section class="section section--community">
  <div class="section-inner">
    <h2 class="section-title">곳곳의 헌터들과 함께, 오픈소스로</h2>
    <p class="section-desc">Dalfox는 직접 쓰는 사람들의 손으로 다듬어집니다. 이슈를 열고, 풀 리퀘스트를 보내고, 커뮤니티와 페이로드를 나눠 보세요. 기여 하나하나가 다음 스캔을 더 날카롭게 만듭니다.</p>
    <div class="community-links">
      <a href="https://github.com/hahwul/dalfox/blob/main/CONTRIBUTING.md" class="btn btn-secondary" target="_blank" rel="noopener">기여 가이드</a>
      <a href="https://github.com/hahwul/dalfox/issues" class="btn btn-ghost" target="_blank" rel="noopener">열린 이슈 보기 →</a>
    </div>
    <p class="contributors-label">기여자 여러분 감사합니다</p>
    <div class="contributors" role="img" aria-label="Dalfox 기여자">
      <img src="/images/CONTRIBUTORS.svg" alt="Dalfox 기여자" loading="lazy">
    </div>
  </div>
</section>

<section class="cta-section">
  <div class="cta-illustration" aria-hidden="true"></div>
  <div class="cta-inner">
    <h2 class="cta-title">사냥을 시작할까요?</h2>
    <p class="cta-desc">문서를 읽고, 저장소에 스타를 남기고, 다음 정찰 루프에 Dalfox를 넣어 보세요.</p>
    <div class="cta-buttons">
      <a href="./getting-started/" class="btn btn-primary">시작하기</a>
      <a href="./reference/cli/" class="btn btn-secondary">CLI 레퍼런스</a>
    </div>
  </div>
</section>
