// Landing page install widget (copy button + package-manager dropdown).
// Extracted from the inline <script> in landing.html so the page can ship a
// strict `script-src 'self'` Content-Security-Policy (no 'unsafe-inline').
(function () {
  var wrap = document.querySelector('.hero-install');
  if (!wrap) return;
  var code = wrap.querySelector('code');

  var copyBtn = wrap.querySelector('.hero-install-copy');
  if (copyBtn && code) {
    copyBtn.addEventListener('click', function () {
      navigator.clipboard.writeText(code.textContent.trim()).then(function () {
        copyBtn.classList.add('copied');
        var prev = copyBtn.textContent;
        copyBtn.textContent = 'copied';
        setTimeout(function () {
          copyBtn.classList.remove('copied');
          copyBtn.textContent = prev;
        }, 1500);
      });
    });
  }

  var pm = wrap.querySelector('.hero-install-pm');
  if (pm && code) {
    var btn = pm.querySelector('.hero-install-pm-btn');
    var label = pm.querySelector('.hero-install-pm-label');
    var options = pm.querySelectorAll('[role="option"]');

    function close() {
      pm.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
    }

    btn.addEventListener('click', function (e) {
      e.stopPropagation();
      if (pm.classList.contains('open')) {
        close();
      } else {
        pm.classList.add('open');
        btn.setAttribute('aria-expanded', 'true');
      }
    });

    options.forEach(function (opt) {
      opt.addEventListener('click', function () {
        options.forEach(function (o) {
          o.classList.remove('is-selected');
          o.setAttribute('aria-selected', 'false');
        });
        opt.classList.add('is-selected');
        opt.setAttribute('aria-selected', 'true');
        code.textContent = opt.getAttribute('data-cmd');
        if (label) label.textContent = opt.getAttribute('data-label');
        close();
      });
    });

    document.addEventListener('click', function (e) {
      if (!pm.contains(e.target)) close();
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') close();
    });
  }
})();

// Scroll-reveal — fade the landing sections up as they enter the viewport.
// The hidden state lives behind a `.reveal-on` class that this script adds, so
// a visitor with JS disabled, no IntersectionObserver, or a reduced-motion
// preference always sees fully-rendered content (never a blank page).
(function () {
  var landing = document.querySelector('.landing');
  if (!landing) return;
  if (!('IntersectionObserver' in window)) return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

  var SELECTOR = [
    '.hero-eyebrow', '.hero-title', '.hero-desc', '.hero-actions', '.hero-install', '.hero-visual',
    '.stat-item',
    '.section-eyebrow', '.section-title', '.section-desc',
    '.feature-cell', '.mode-tab', '.how-step',
    '.community-links', '.contributors-label', '.contributors',
    '.cta-title', '.cta-desc', '.cta-buttons'
  ].join(', ');

  var targets = Array.prototype.slice.call(landing.querySelectorAll(SELECTOR));
  if (!targets.length) return;

  landing.classList.add('reveal-on');
  targets.forEach(function (el) { el.setAttribute('data-reveal', ''); });

  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (!entry.isIntersecting) return;
      io.unobserve(entry.target);
      entry.target.classList.add('in-view');
    });
  }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });

  // Stagger siblings that reveal together (grid cells, stat columns, buttons)
  // so a row cascades in rather than snapping as one block.
  targets.forEach(function (el) {
    var siblings = Array.prototype.filter.call(el.parentElement.children, function (c) {
      return c.hasAttribute && c.hasAttribute('data-reveal');
    });
    var index = siblings.indexOf(el);
    if (index > 0) {
      el.style.setProperty('--reveal-delay', Math.min(index, 6) * 55 + 'ms');
    }
    io.observe(el);
  });
})();
