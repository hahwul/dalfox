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
        copyBtn.textContent = document.documentElement.lang === 'ko' ? '복사됨' : 'copied';
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

// The field sinks as the strips slide over it, and each strip reveals as it
// enters the viewport. Both are skipped under prefers-reduced-motion, and the
// hidden state lives behind html.motion-on so no-JS visitors see everything.
(function () {
  var field = document.querySelector('.field');
  if (!field) return;
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduced) return;
  // is-sinking gates the costly blur filter to the transition itself;
  // is-covered hides the field entirely (no paint, no compositing) and tells
  // fox.js to stop its loop. Writes are skipped when nothing changed, since
  // scroll keeps firing long after the field is gone.
  var ticking = false, lastP = '';
  function update() {
    ticking = false;
    var h = field.offsetHeight || 1;
    var p = Math.min(1, Math.max(0, window.scrollY / (h * 0.85)));
    var ps = p.toFixed(3);
    if (ps === lastP) return;
    lastP = ps;
    field.style.setProperty('--field-p', ps);
    field.classList.toggle('is-sinking', p > 0);
    field.classList.toggle('is-covered', p >= 1);
  }
  window.addEventListener('scroll', function () {
    if (!ticking) { ticking = true; requestAnimationFrame(update); }
  }, { passive: true });
  window.addEventListener('resize', update);
  update();

  if (!('IntersectionObserver' in window)) return;
  var strips = document.querySelectorAll('.strip');
  if (!strips.length) return;
  document.documentElement.classList.add('motion-on');
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (e) {
      if (!e.isIntersecting) return;
      e.target.classList.add('in-view');
      io.unobserve(e.target);
    });
  }, { rootMargin: '0px 0px -18% 0px', threshold: 0.12 });
  strips.forEach(function (el) { io.observe(el); });
})();
