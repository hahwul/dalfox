+++
title = "Dalfox: 오픈소스 XSS 스캐너"
description = "Dalfox는 반사형, 저장형, DOM 기반 XSS를 탐지하고 AST 수준으로 검증하는 오픈소스 스캐너이자 자동화 도구입니다."
template = "landing"
+++

<section class="field">
  <canvas id="field" class="field-canvas" aria-hidden="true"></canvas>
  <div class="hero" data-fox-avoid>
    <blockquote class="hero-quote">메아리 가득한 들판에서,<br>달아나는 하나만 쫓는다.</blockquote>
    <h1 class="hero-title">Dalfox는 <span class="ember">XSS</span>를 사냥합니다.</h1>
    <div class="hero-prose">
      <p>Rust로 작성한 <strong>반사형, 저장형, DOM 기반 XSS</strong> 오픈소스 스캐너입니다. 파라미터를 찾아내고, 컨텍스트마다 탐침을 보내고, 파싱한 HTML과 JavaScript에서 실행을 확인한 뒤에야 결과로 보고합니다.</p>
      <p><a href="./getting-started/quick-start/">명령줄</a>, <a href="./integrations/server/">REST 서버</a>, <a href="./integrations/mcp/">MCP 도구</a> 어느 쪽으로 실행해도 같은 엔진이 돌고, 모든 결과에는 근거 등급이 붙습니다.</p>
    </div>
    <p class="hero-links">
      <a href="./getting-started/">시작하기</a><span class="sep">/</span>
      <a href="https://github.com/hahwul/dalfox" target="_blank" rel="noopener">github</a><span class="sep">/</span>
      <a href="https://github.com/hahwul/dalfox/releases" target="_blank" rel="noopener">릴리스</a><span class="sep">/</span>
      <a href="./reference/cli/">cli 레퍼런스</a>
    </p>
  </div>
  <p class="field-stat" data-fox-avoid aria-hidden="true"><span>여우</span><b id="fox-count">0</b><span>마리가 들판에</span><span class="hint">· 클릭해서 XSS를 떨어뜨려 보세요</span></p>
  <span class="field-scroll" aria-hidden="true">scroll</span>
</section>

<section class="strip">
  <div class="strip-inner" data-n="01">
    <p class="strip-label">install</p>
    <div class="strip-body">
      <h2 class="strip-title">바이너리 하나. 따로 준비할 것은 없습니다.</h2>
      <div class="install-row">
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
            <li role="option" aria-selected="false" data-label="choco" data-cmd="choco install dalfox">Chocolatey</li>
            <li role="option" aria-selected="false" data-label="nix" data-cmd="nix profile install github:hahwul/dalfox">Nix</li>
            <li role="option" aria-selected="false" data-label="cargo" data-cmd="cargo install dalfox">Cargo</li>
            <li role="option" aria-selected="false" data-label="docker" data-cmd="docker run -it hahwul/dalfox:latest">Docker</li>
          </ul>
        </div>
        <span class="hero-install-sep" aria-hidden="true"></span>
        <span class="dollar">$</span>
        <code>brew install dalfox</code>
        <button class="hero-install-copy" type="button">복사</button>
      </div>
      <p class="strip-prose">macOS, Linux, Windows용 빌드 바이너리는 <a href="https://github.com/hahwul/dalfox/releases" target="_blank" rel="noopener">릴리스 페이지</a>에 있습니다. Docker와 소스 빌드를 포함한 모든 설치 경로는 <a href="./getting-started/installation/">설치 가이드</a>에서 다룹니다.</p>
      </div>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="02">
    <p class="strip-label">run</p>
    <div class="strip-body">
      <h2 class="strip-title">명령 하나로, 검증된 결과까지.</h2>
      <p class="strip-prose">대상만 지정하세요. 파라미터를 찾고, 컨텍스트마다 살아남는 문자를 탐침하고, 페이로드를 주입한 뒤 파싱한 DOM에서 실행을 확인하고 나서야 보고합니다.</p>
      <div class="terminal">
        <div class="terminal-bar"><span>dalfox · scan</span><span>zsh</span></div>
        <div class="terminal-body">
          <div class="t-line"><span class="t-prompt">$</span><span class="t-cmd">dalfox scan https://xss-game.appspot.com/level1/frame</span></div>
          <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> start scan to https://xss-game.appspot.com/level1/frame</div>
          <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> found reflected 1 params</div>
          <div class="t-line t-dim">└── query valid_specials="/\'{`<>"();=|}[.:]+,$-" invalid_specials=""</div>
          <div class="t-line"><span class="t-ts">6:42PM</span> <span class="t-wrn">WRN</span> XSS found 1 XSS</div>
          <div class="t-line"><span class="t-poc">[POC][V][GET][inHTML]</span> ...?query=%3Csvg%20onload%3Dalert%281%29%20class%3Ddlx444fc070%3E</div>
          <div class="t-line t-dim">  ├── Issue: XSS payload DOM object identified</div>
          <div class="t-line t-dim">  ├── Payload: &lt;svg onload=alert(1) class=dlx444fc070&gt;</div>
          <div class="t-line t-dim">  └── L13: …results were found for &lt;b&gt;&lt;svg onload=alert(1) class=dlx444fc070&gt;&lt;/b&gt;</div>
          <div class="t-line"></div>
          <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> scan completed in 3.482 seconds</div>
          <div class="t-line t-cursor"></div>
        </div>
      </div>
      <p class="strip-prose"><code>[V]</code>는 페이로드가 단순히 되돌아온 것이 아니라 파싱된 응답 안에서 실행 위치에 놓였다는 뜻입니다. 등급별 의미는 <a href="./guide/detection-model/">탐지 모델</a>에서 설명합니다.</p>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="03">
    <p class="strip-label">what it does</p>
    <div class="strip-body">
      <h2 class="strip-title">XSS 워크플로 전체를 스캐너 하나로.</h2>
      <dl class="facts">
        <div>
          <dt>discover</dt>
          <dd>쿼리, 본문, 경로, 헤더, 쿠키, 폼, 프래그먼트에서 파라미터를 찾고, DOM과 워드리스트, JSON 키에서 더 캐냅니다.</dd>
        </div>
        <div>
          <dt>probe</dt>
          <dd>문자 단위 탐침으로 파라미터가 어디에 놓이는지, 어떤 문자가 살아남는지 알아내고, 그 자리에서 통할 수 있는 페이로드만 보냅니다.</dd>
        </div>
        <div>
          <dt>verify</dt>
          <dd>HTML 파서와 JavaScript AST로 실행되는 반사와 단순히 되돌아오는 반사를 구분합니다. 모든 결과에 근거가 붙습니다.</dd>
        </div>
        <div>
          <dt>evade</dt>
          <dd>주요 WAF를 식별하고 인코딩, 대소문자, 공백, 엔티티 변형으로 페이로드를 바꿔 우회를 시도합니다.</dd>
        </div>
        <div>
          <dt>pipeline</dt>
          <dd>URL, 파일, stdin, 원시 HTTP 요청, HAR, OpenAPI를 읽습니다. CI에서 크롤러, 프록시, 정찰 도구 뒤에 바로 이어 붙일 수 있습니다.</dd>
        </div>
        <div>
          <dt>report</dt>
          <dd>Plain, JSON, JSONL, Markdown, TOML, 그리고 GitHub 코드 스캐닝용 SARIF. 요청과 응답 본문은 요청했을 때만 포함합니다.</dd>
        </div>
      </dl>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="04">
    <p class="strip-label">modes</p>
    <div class="strip-body">
      <h2 class="strip-title">여섯 가지 실행 방식.</h2>
      <p class="strip-prose">대상에 맞는 형태를 고르세요. 어떤 모드든 같은 탐색·검증 엔진을 공유합니다.</p>
      <div class="modes" data-modes>
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-url" checked>
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-file">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-pipe">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-sxss">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-server">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-mcp">
        <div class="mode-tabs" role="tablist" aria-label="Dalfox 실행 모드">
          <label class="mode-tab" for="m-url"><span class="mode-tab-name">url</span><span class="mode-tab-sub">단일 대상</span></label>
          <label class="mode-tab" for="m-file"><span class="mode-tab-name">file</span><span class="mode-tab-sub">목록 일괄 스캔</span></label>
          <label class="mode-tab" for="m-pipe"><span class="mode-tab-name">pipe</span><span class="mode-tab-sub">stdin 파이프라인</span></label>
          <label class="mode-tab" for="m-sxss"><span class="mode-tab-name">sxss</span><span class="mode-tab-sub">저장형 XSS</span></label>
          <label class="mode-tab" for="m-server"><span class="mode-tab-name">server</span><span class="mode-tab-sub">REST 데몬</span></label>
          <label class="mode-tab" for="m-mcp"><span class="mode-tab-name">mcp</span><span class="mode-tab-sub">에이전트 네이티브</span></label>
        </div>
        <div class="mode-panels">
          <div class="mode-panel" data-mode="url">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan https://target.app</code></div>
            <p>URL 하나를 스캔합니다. 파라미터를 캐내고, 컨텍스트마다 탐침하고, 모든 적중을 파싱한 응답에서 확인합니다.</p>
          </div>
          <div class="mode-panel" data-mode="file">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan urls.txt</code></div>
            <p>한 줄에 URL 하나씩 적힌 파일을 읽어 대상 목록을 리포트 하나로 스캔합니다.</p>
          </div>
          <div class="mode-panel" data-mode="pipe">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>cat urls.txt | dalfox scan</code></div>
            <p>stdin에서 대상을 읽어 크롤러나 정찰 파이프라인의 맨 끝에 놓을 수 있습니다.</p>
          </div>
          <div class="mode-panel" data-mode="sxss">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan https://app/post --sxss --sxss-url https://app/feed</code></div>
            <p>한 엔드포인트에 주입하고, 저장된 페이로드가 나타나는 페이지에서 확인합니다.</p>
          </div>
          <div class="mode-panel" data-mode="server">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox server</code></div>
            <p>비동기 스캔 작업, 연동, 대시보드를 위한 장기 실행 REST API로 띄웁니다.</p>
          </div>
          <div class="mode-panel" data-mode="mcp">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox mcp</code></div>
            <p>에이전트와 IDE가 대신 스캔을 돌릴 수 있도록 MCP 도구로 노출합니다.</p>
          </div>
        </div>
      </div>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="05">
    <p class="strip-label">community</p>
    <div class="strip-body">
      <h2 class="strip-title">공개된 곳에서, 세계의 헌터들과 함께.</h2>
      <p class="strip-prose">Dalfox는 직접 쓰는 사람들이 만들어 갑니다. 이슈를 열고, 풀 리퀘스트를 보내고, 페이로드를 커뮤니티와 나눠 주세요.</p>
      <div class="community-links">
        <a href="./getting-started/" class="btn btn-primary">문서 읽기</a>
        <a href="https://github.com/hahwul/dalfox/blob/main/.github/CONTRIBUTING.md" class="btn btn-secondary" target="_blank" rel="noopener">기여 가이드</a>
        <a href="https://github.com/hahwul/dalfox/issues" class="btn btn-ghost" target="_blank" rel="noopener">열린 이슈</a>
      </div>
      <div class="contributors" role="img" aria-label="Dalfox 기여자">
        <img src="/images/CONTRIBUTORS.svg" alt="Dalfox 기여자" loading="lazy">
      </div>
    </div>
  </div>
</section>
