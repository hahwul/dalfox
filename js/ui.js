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
