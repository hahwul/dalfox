// Shared UI behaviour, loaded on every page.
// Extracted from inline <script> blocks / onclick handlers so the site can ship
// a strict `script-src 'self'` Content-Security-Policy (no 'unsafe-inline').
(function () {
  // --- Syntax highlighting (highlight.js is loaded locally, before this file) ---
  if (window.hljs && typeof window.hljs.highlightAll === 'function') {
    window.hljs.highlightAll();
  }

  // --- Active nav/sidebar link highlighting ---
  var path = location.pathname.replace(/\/$/, '') || '/';
  document.querySelectorAll('.sidebar-links a, .site-nav a').forEach(function (a) {
    var href = (a.getAttribute('href') || '')
      .replace(/^https?:\/\/[^/]+/, '')
      .replace(/\/$/, '') || '/';
    if (href === path) {
      a.classList.add('active');
      a.setAttribute('aria-current', 'page');
    } else if (a.closest('.site-nav') && href !== '/' && href !== '/ko' && path.indexOf(href + '/') === 0) {
      a.classList.add('active');
    }
  });

  // --- Landing header: transparent over the field, solid once scrolled ---
  var header = document.querySelector('.site-header');
  if (header && document.body.classList.contains('is-landing')) {
    var onScroll = function () { header.classList.toggle('is-scrolled', window.scrollY > 24); };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  // --- Theme toggle (night by default; the choice persists) ---
  var themeBtn = document.querySelector('.theme-toggle');
  var themeMeta = document.querySelector('meta[name="theme-color"]');
  function applyTheme(light) {
    if (light) document.documentElement.setAttribute('data-theme', 'light');
    else document.documentElement.removeAttribute('data-theme');
    if (themeBtn) themeBtn.setAttribute('aria-label', themeBtn.getAttribute(light ? 'data-label-dark' : 'data-label-light'));
    if (themeMeta) themeMeta.setAttribute('content', light ? '#f4f1ea' : '#0b0d16');
    try { localStorage.setItem('dalfox-theme', light ? 'light' : 'dark'); } catch (e) {}
  }
  if (themeBtn) {
    var isLight = document.documentElement.getAttribute('data-theme') === 'light';
    themeBtn.setAttribute('aria-label', themeBtn.getAttribute(isLight ? 'data-label-dark' : 'data-label-light'));
    if (themeMeta && isLight) themeMeta.setAttribute('content', '#f4f1ea');
    themeBtn.addEventListener('click', function () {
      applyTheme(document.documentElement.getAttribute('data-theme') !== 'light');
    });
  }

  // --- Search overlay wiring (handlers live in search.js) ---
  var overlay = document.getElementById('searchOverlay');
  var trigger = document.querySelector('.search-trigger');
  if (trigger && overlay) {
    trigger.addEventListener('click', function () {
      if (window.openSearch) window.openSearch();
    });
  }
  if (overlay) {
    overlay.addEventListener('click', function (e) {
      if (e.target === overlay && window.closeSearch) window.closeSearch();
    });
    var escKbd = overlay.querySelector('.search-input-wrap kbd');
    if (escKbd) {
      escKbd.addEventListener('click', function () {
        if (window.closeSearch) window.closeSearch();
      });
    }
  }

  // --- Sidebar collapse / expand (desktop docs layout) ---
  // The initial state is applied pre-paint by js/boot.js; here we just
  // wire the toggle buttons and persist the choice.
  var collapseBtn = document.getElementById('sidebar-collapse');
  var expandBtn = document.getElementById('sidebar-expand');
  function setSidebarCollapsed(collapsed) {
    document.documentElement.classList.toggle('sidebar-collapsed', collapsed);
    try {
      localStorage.setItem('dalfox-sidebar-collapsed', collapsed ? '1' : '0');
    } catch (e) {}
    if (collapseBtn) collapseBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    if (expandBtn) expandBtn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  }
  if (collapseBtn) {
    collapseBtn.addEventListener('click', function () {
      setSidebarCollapsed(true);
    });
  }
  if (expandBtn) {
    expandBtn.addEventListener('click', function () {
      setSidebarCollapsed(false);
    });
  }

  // --- Code blocks: language bar + copy (docs articles only) ---
  var ko = document.documentElement.lang === 'ko';
  document.querySelectorAll('.docs-article pre > code').forEach(function (code) {
    var pre = code.parentNode;
    var m = /language-([\w+-]+)/.exec(code.className);
    pre.setAttribute('data-lang', m ? m[1] : 'text');
    if (!navigator.clipboard) return;
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'code-copy';
    btn.textContent = ko ? '복사' : 'copy';
    btn.addEventListener('click', function () {
      navigator.clipboard.writeText(code.textContent.replace(/\n$/, '')).then(function () {
        btn.classList.add('copied');
        btn.textContent = ko ? '복사됨' : 'copied';
        setTimeout(function () {
          btn.classList.remove('copied');
          btn.textContent = ko ? '복사' : 'copy';
        }, 1500);
      });
    });
    pre.appendChild(btn);
  });

  // --- Tables scroll inside a wrapper instead of shrinking the table box ---
  document.querySelectorAll('.docs-article table').forEach(function (table) {
    var wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  });

  // --- Prev / next pager, derived from the sidebar order ---
  var pager = document.querySelector('.docs-pager');
  var sideLinks = Array.prototype.slice.call(document.querySelectorAll('.sidebar-links a'));
  var cur = sideLinks.findIndex(function (a) { return a.classList.contains('active'); });
  if (pager && cur !== -1) {
    function cell(a, cls, label) {
      if (!a) return '<span class="docs-pager-empty"></span>';
      return '<a class="' + cls + '" href="' + a.getAttribute('href') + '">' +
        '<span class="docs-pager-label">' + label + '</span>' +
        '<span class="docs-pager-title">' + a.textContent.trim() + '</span></a>';
    }
    pager.innerHTML = cell(sideLinks[cur - 1], 'is-prev', pager.getAttribute('data-prev')) +
      cell(sideLinks[cur + 1], 'is-next', pager.getAttribute('data-next'));
    pager.hidden = false;
  }

  // --- Mobile hamburger menu (docs layout only) ---
  var hamburger = document.querySelector('.hamburger');
  var sidebar = document.querySelector('.docs-sidebar');
  var siteOverlay = document.querySelector('.site-overlay');

  if (hamburger && sidebar && siteOverlay) {
    function setExpanded(expanded) {
      hamburger.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      sidebar.classList.toggle('open', expanded);
      siteOverlay.classList.toggle('active', expanded);
    }

    hamburger.addEventListener('click', function (e) {
      e.preventDefault();
      setExpanded(!sidebar.classList.contains('open'));
    });

    siteOverlay.addEventListener('click', function () {
      setExpanded(false);
    });

    sidebar.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        setExpanded(false);
      });
    });

    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && sidebar.classList.contains('open')) {
        setExpanded(false);
      }
    });
  }
})();
