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
