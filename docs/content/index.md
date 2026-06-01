+++
title = "Dalfox — Powerful XSS Scanner"
description = "A powerful open-source XSS scanner and automation utility. Reflected, Stored, DOM-based with AST-level verification."
template = "landing"
+++

<section class="hero">
  <div class="hero-illustration" aria-hidden="true"></div>
  <div class="hero-inner">
    <div class="hero-text">
      <h1 class="hero-title">
        Hunt <span class="strike">every</span> <span class="accent">XSS</span><br>
        before it hunts you.
      </h1>
      <p class="hero-desc">
        <strong>Dalfox</strong> is a powerful open-source XSS scanner and automation utility. Reflected, Stored, DOM-based — discovered, verified, and reported with AST-level precision across every parameter in your app.
      </p>
      <div class="hero-actions">
        <a href="./getting-started/" class="btn btn-primary">
          Get Started
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
        </a>
        <a href="https://github.com/hahwul/dalfox" class="btn btn-secondary" target="_blank" rel="noopener">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          Star on GitHub
        </a>
      </div>
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
            <li role="option" aria-selected="false" data-label="nix" data-cmd="nix profile install github:hahwul/dalfox">Nix</li>
            <li role="option" aria-selected="false" data-label="cargo" data-cmd="cargo install dalfox">Cargo</li>
          </ul>
        </div>
        <span class="hero-install-sep" aria-hidden="true"></span>
        <span class="dollar">$</span>
        <code>brew install dalfox</code>
        <button class="hero-install-copy" type="button">copy</button>
      </div>
    </div>
    <div class="hero-visual">
      <div class="terminal">
        <div class="terminal-bar">
          <div class="terminal-dots">
            <span class="terminal-dot red"></span>
            <span class="terminal-dot amber"></span>
            <span class="terminal-dot green"></span>
          </div>
          <div class="terminal-title">dalfox — scan</div>
        </div>
        <div class="terminal-body">
          <div class="t-line"><span class="t-prompt">$</span><span class="t-cmd">dalfox scan https://xss-game.appspot.com/level1/frame</span></div>
          <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> start scan to https://xss-game.appspot.com/level1/frame</div>
          <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> found reflected 1 params</div>
          <div class="t-line t-dim">└── query valid_specials="/\'{`<>"();=|}[.:]+,$-" invalid_specials=""</div>
          <div class="t-line"></div>
          <div class="t-line"></div>
          <div class="t-line"><span class="t-ts">6:42PM</span> <span class="t-wrn">WRN</span> XSS found 1 XSS</div>
          <div class="t-line"><span class="t-poc">[POC][V][GET][inHTML]</span> ...?query=%3Csvg%2Fonload%3Dalert%281%29%3E</div>
          <div class="t-line t-dim">  ├── Issue: XSS payload DOM object identified</div>
          <div class="t-line t-dim">  ├── Payload: &lt;svg/onload=alert(1)&gt;</div>
          <div class="t-line t-dim">  └── L13: s were found for &#x3c;b&#x3e;&#x3c;svg/onload=alert(1)&#x3e;&#x3c;/b&#x3e;..</div>
          <div class="t-line"></div>
          <div class="t-line t-dim"><span class="t-ts">6:42PM</span> <span class="t-info">INF</span> scan completed in 3.482 seconds</div>
          <div class="t-line t-cursor"></div>
        </div>
      </div>
    </div>
  </div>
</section>

<div class="stats-bar">
  <div class="stats-inner">
    <div class="stat-item">
      <span class="stat-value">6</span>
      <span class="stat-label">Scan Modes</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">AST</span>
      <span class="stat-label">DOM Verification</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">MCP</span>
      <span class="stat-label">AI Ready</span>
    </div>
    <div class="stat-item">
      <span class="stat-value">OSS</span>
      <span class="stat-label">MIT Licensed</span>
    </div>
  </div>
</div>

<section class="section">
  <div class="section-inner">
    <p class="section-eyebrow">// Capabilities</p>
    <h2 class="section-title">Everything you need to catch cross-site scripting</h2>
    <p class="section-desc">From a single URL to full pipelines, Dalfox adapts to how you work — CLI, file batch, pipe, server mode, or MCP. Every finding is parsed, verified, and reported with context you can act on.</p>
    <div class="features-grid">
      <div class="feature-cell wide">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
        </div>
        <h3>Deep XSS discovery</h3>
        <p>Reflected, Stored, and DOM-based XSS with payload optimization. AST-backed DOM verification means no more false positives from blind reflections.</p>
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
        <h3>Parameter intelligence</h3>
        <p>Mining, static analysis, BAV testing, and context-aware charset probing — every parameter gets a full attack profile.</p>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v4"/><path d="M12 18v4"/><path d="m4.93 4.93 2.83 2.83"/><path d="m16.24 16.24 2.83 2.83"/><path d="M2 12h4"/><path d="M18 12h4"/><path d="m4.93 19.07 2.83-2.83"/><path d="m16.24 7.76 2.83-2.83"/></svg>
        </div>
        <h3>WAF aware</h3>
        <p>Fingerprints popular WAFs and mutates payloads with encoding, casing, and polyglot tactics to slip through.</p>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        </div>
        <h3>Built for pipelines</h3>
        <p>Pipe, file-batch, and server modes drop into CI/CD. Pair with your proxy, crawler, or recon stack without friction.</p>
      </div>
      <div class="feature-cell">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg>
        </div>
        <h3>REST API &amp; MCP</h3>
        <p>Run Dalfox as a long-lived server with REST control, or expose it as an MCP tool to agents and IDEs.</p>
      </div>
      <div class="feature-cell full">
        <div class="feature-icon">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
        </div>
        <h3>Reports you can ship</h3>
        <p>Export to the format your workflow speaks — from terse CLI output to SARIF for GitHub code scanning.</p>
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
    <p class="section-eyebrow">// Modes</p>
    <h2 class="section-title">Six ways to run Dalfox</h2>
    <p class="section-desc">Pick the shape that fits your target. Every mode shares the same discovery and verification engine.</p>
    <div class="modes">
      <div class="mode">
        <div class="mode-name">URL</div>
        <div class="mode-desc">Single target scan</div>
      </div>
      <div class="mode">
        <div class="mode-name">FILE</div>
        <div class="mode-desc">Batch from list</div>
      </div>
      <div class="mode">
        <div class="mode-name">PIPE</div>
        <div class="mode-desc">stdin pipeline</div>
      </div>
      <div class="mode">
        <div class="mode-name">SXSS</div>
        <div class="mode-desc">Stored XSS</div>
      </div>
      <div class="mode">
        <div class="mode-name">SERVER</div>
        <div class="mode-desc">REST + daemon</div>
      </div>
      <div class="mode">
        <div class="mode-name">MCP</div>
        <div class="mode-desc">Agent-native</div>
      </div>
    </div>
  </div>
</section>

<section class="section">
  <div class="section-inner">
    <p class="section-eyebrow">// Workflow</p>
    <h2 class="section-title">From install to verified finding in three steps</h2>
    <p class="section-desc">Dalfox is designed to drop into whatever you already have — no fancy setup, no heavy orchestration.</p>
    <div class="how-steps">
      <div class="how-step">
        <h3>Install</h3>
        <p>Grab Dalfox through Homebrew, Snap, Nix, cargo, or a prebuilt binary. One command, no runtime to manage.</p>
        <code>brew install dalfox</code>
      </div>
      <div class="how-step">
        <h3>Point at a target</h3>
        <p>Give it a URL, a file, or pipe in a crawl. Dalfox mines parameters, probes contexts, and adapts.</p>
        <code>dalfox scan https://target.app</code>
      </div>
      <div class="how-step">
        <h3>Ship the findings</h3>
        <p>Export to SARIF, JSON, or Markdown, or proxy results to your pipeline. Findings come verified, not guessed.</p>
        <code>dalfox scan urls.txt -o report.sarif</code>
      </div>
    </div>
  </div>
</section>

<section class="cta-section">
  <div class="cta-inner">
    <h2 class="cta-title">Ready to hunt?</h2>
    <p class="cta-desc">Thousands of scans, zero fuss. Star the repo, read the docs, or drop Dalfox in your next recon loop.</p>
    <div class="cta-buttons">
      <a href="./getting-started/installation/" class="btn btn-primary">Install Dalfox</a>
      <a href="./reference/cli/" class="btn btn-secondary">CLI Reference</a>
      <a href="https://github.com/hahwul/dalfox" class="btn btn-ghost" target="_blank" rel="noopener">GitHub →</a>
    </div>
    <p class="contributors-label">Thanks to our contributors</p>
    <svg class="cg-filters" width="0" height="0" aria-hidden="true" focusable="false">
      <filter id="cg-red" x="-30%" y="-30%" width="160%" height="160%" color-interpolation-filters="sRGB">
        <feColorMatrix type="matrix" values="1 0 0 0 0  0 0 0 0 0  0 0 0 0 0  0 0 0 1 0"/>
      </filter>
      <filter id="cg-cyan" x="-30%" y="-30%" width="160%" height="160%" color-interpolation-filters="sRGB">
        <feColorMatrix type="matrix" values="0 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 1 0"/>
      </filter>
    </svg>
    <div class="contributors-glitch" role="img" aria-label="Dalfox contributors"
         style="--contrib-src: url('https://github.com/hahwul/dalfox/raw/main/docs/static/images/CONTRIBUTORS.svg')">
      <img class="cg-base" src="https://github.com/hahwul/dalfox/raw/main/docs/static/images/CONTRIBUTORS.svg" alt="" aria-hidden="true" loading="lazy">
      <span class="cg-layer cg-r" aria-hidden="true"></span>
      <span class="cg-layer cg-b" aria-hidden="true"></span>
      <span class="cg-layer cg-slice" aria-hidden="true"></span>
      <span class="cg-scan" aria-hidden="true"></span>
    </div>
  </div>
</section>
