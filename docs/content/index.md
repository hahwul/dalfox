+++
title = "Dalfox: Open-Source XSS Scanner"
description = "Dalfox is an open-source XSS scanner and automation tool for reflected, stored, and DOM-based XSS, with parameter discovery and AST-level verification."
template = "landing"
+++

<section class="field">
  <canvas id="field" class="field-canvas" aria-hidden="true"></canvas>
  <div class="hero" data-fox-avoid>
    <blockquote class="hero-quote">in a field of echoes,<br>follow the one that runs.</blockquote>
    <h1 class="hero-title">Dalfox hunts <span class="ember">XSS</span>.</h1>
    <div class="hero-prose">
      <p>An open-source scanner for <strong>reflected, stored, and DOM-based XSS</strong>, written in Rust. It finds the parameters, probes each context, and proves every hit in the parsed HTML and JavaScript before it reports it.</p>
      <p>Run it as a <a href="./getting-started/quick-start/">command</a>, a <a href="./integrations/server/">REST server</a>, or an <a href="./integrations/mcp/">MCP tool</a>. One engine underneath, and every finding graded by the evidence behind it.</p>
    </div>
    <p class="hero-links">
      <a href="./getting-started/">get started</a><span class="sep">/</span>
      <a href="https://github.com/hahwul/dalfox" target="_blank" rel="noopener">github</a><span class="sep">/</span>
      <a href="https://github.com/hahwul/dalfox/releases" target="_blank" rel="noopener">releases</a><span class="sep">/</span>
      <a href="./reference/cli/">cli reference</a>
    </p>
  </div>
  <p class="field-stat" data-fox-avoid aria-hidden="true"><b id="fox-count">0</b><span>foxes in the field</span><span class="hint">· click the field to drop an XSS</span></p>
  <span class="field-scroll" aria-hidden="true">scroll</span>
</section>

<section class="strip">
  <div class="strip-inner" data-n="01">
    <p class="strip-label">install</p>
    <div class="strip-body">
      <h2 class="strip-title">One binary. Nothing else to set up.</h2>
      <div class="install-row">
      <div class="hero-install" data-install>
        <div class="hero-install-pm">
          <button class="hero-install-pm-btn" type="button" aria-haspopup="listbox" aria-expanded="false" aria-label="Choose install method">
            <span class="hero-install-pm-label">brew</span>
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></svg>
          </button>
          <ul class="hero-install-pm-menu" role="listbox" aria-label="Install method">
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
        <button class="hero-install-copy" type="button">copy</button>
      </div>
      <p class="strip-prose">Prebuilt binaries for macOS, Linux, and Windows are on the <a href="https://github.com/hahwul/dalfox/releases" target="_blank" rel="noopener">releases page</a>. The <a href="./getting-started/installation/">installation guide</a> covers every channel, including Docker and building from source.</p>
      </div>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="02">
    <p class="strip-label">run</p>
    <div class="strip-body">
      <h2 class="strip-title">One command, a verified finding.</h2>
      <p class="strip-prose">Point Dalfox at a target. It discovers the parameters, probes which characters survive in each context, injects payloads, and checks the hit in the parsed DOM before it reports it.</p>
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
      <p class="strip-prose">The <code>[V]</code> means the payload was found executing in the parsed response, not merely echoed back. The <a href="./guide/detection-model/">detection model</a> explains every grade.</p>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="03">
    <p class="strip-label">what it does</p>
    <div class="strip-body">
      <h2 class="strip-title">The whole XSS workflow, in one scanner.</h2>
      <dl class="facts">
        <div>
          <dt>discover</dt>
          <dd>Finds parameters in the query, body, path, headers, cookies, forms, and fragments, then mines more from the DOM, a wordlist, and JSON keys.</dd>
        </div>
        <div>
          <dt>probe</dt>
          <dd>Per-character probes tell Dalfox where each parameter lands and which characters survive, so it only sends payloads that can work there.</dd>
        </div>
        <div>
          <dt>verify</dt>
          <dd>An HTML parser plus a JavaScript AST separate a reflection that executes from one that only echoes back. Findings carry their evidence.</dd>
        </div>
        <div>
          <dt>evade</dt>
          <dd>Fingerprints common WAFs and mutates payloads with encoding, case, whitespace, and entity tricks to get past them.</dd>
        </div>
        <div>
          <dt>pipeline</dt>
          <dd>Reads URLs, files, stdin, raw HTTP requests, HAR, and OpenAPI. Chains after your crawler, proxy, or recon tools in CI.</dd>
        </div>
        <div>
          <dt>report</dt>
          <dd>Plain, JSON, JSONL, Markdown, TOML, or SARIF for GitHub code scanning. Request and response bodies only when you ask.</dd>
        </div>
      </dl>
    </div>
  </div>
</section>

<section class="strip">
  <div class="strip-inner" data-n="04">
    <p class="strip-label">modes</p>
    <div class="strip-body">
      <h2 class="strip-title">Six ways to run it.</h2>
      <p class="strip-prose">Pick the shape that fits your target. Every mode shares the same discovery and verification engine.</p>
      <div class="modes" data-modes>
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-url" checked>
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-file">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-pipe">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-sxss">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-server">
        <input class="mode-radio" type="radio" name="dalfox-mode" id="m-mcp">
        <div class="mode-tabs" role="tablist" aria-label="Dalfox run modes">
          <label class="mode-tab" for="m-url"><span class="mode-tab-name">url</span><span class="mode-tab-sub">single target</span></label>
          <label class="mode-tab" for="m-file"><span class="mode-tab-name">file</span><span class="mode-tab-sub">batch from a list</span></label>
          <label class="mode-tab" for="m-pipe"><span class="mode-tab-name">pipe</span><span class="mode-tab-sub">stdin pipeline</span></label>
          <label class="mode-tab" for="m-sxss"><span class="mode-tab-name">sxss</span><span class="mode-tab-sub">stored XSS</span></label>
          <label class="mode-tab" for="m-server"><span class="mode-tab-name">server</span><span class="mode-tab-sub">REST daemon</span></label>
          <label class="mode-tab" for="m-mcp"><span class="mode-tab-name">mcp</span><span class="mode-tab-sub">agent-native</span></label>
        </div>
        <div class="mode-panels">
          <div class="mode-panel" data-mode="url">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan https://target.app</code></div>
            <p>Scan a single URL. Dalfox mines parameters, probes each context, and checks every hit in the parsed response.</p>
          </div>
          <div class="mode-panel" data-mode="file">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan urls.txt</code></div>
            <p>Scan a list of targets from a file, one URL per line, into one report.</p>
          </div>
          <div class="mode-panel" data-mode="pipe">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>cat urls.txt | dalfox scan</code></div>
            <p>Read targets from stdin, so Dalfox sits at the end of your crawler or recon pipeline.</p>
          </div>
          <div class="mode-panel" data-mode="sxss">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox scan https://app/post --sxss --sxss-url https://app/feed</code></div>
            <p>Inject on one endpoint, then check the page where the stored payload shows up.</p>
          </div>
          <div class="mode-panel" data-mode="server">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox server</code></div>
            <p>Run Dalfox as a long-lived REST API for async scan jobs, integrations, and dashboards.</p>
          </div>
          <div class="mode-panel" data-mode="mcp">
            <div class="mode-panel-cmd"><span class="dollar">$</span><code>dalfox mcp</code></div>
            <p>Expose Dalfox as MCP tools so agents and IDEs can run scans for you.</p>
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
      <h2 class="strip-title">Built in the open, by hunters everywhere.</h2>
      <p class="strip-prose">Dalfox is shaped by the people who run it. Open an issue, send a pull request, or share payloads with the community.</p>
      <div class="community-links">
        <a href="./getting-started/" class="btn btn-primary">Read the docs</a>
        <a href="https://github.com/hahwul/dalfox/blob/main/.github/CONTRIBUTING.md" class="btn btn-secondary" target="_blank" rel="noopener">Contributing guide</a>
        <a href="https://github.com/hahwul/dalfox/issues" class="btn btn-ghost" target="_blank" rel="noopener">Open issues</a>
      </div>
      <div class="contributors" role="img" aria-label="Dalfox contributors">
        <img src="/images/CONTRIBUTORS.svg" alt="Dalfox contributors" loading="lazy">
      </div>
    </div>
  </div>
</section>
