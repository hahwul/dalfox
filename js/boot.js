// Runs synchronously in <head>, before first paint (inline scripts are
// forbidden by the site CSP). Restores two persisted preferences so neither
// flashes on load: the colour theme (night is the default; "light" is opt-in)
// and the collapsed docs sidebar. The toggles themselves live in js/ui.js.
(function () {
  var root = document.documentElement;
  try {
    if (localStorage.getItem('dalfox-theme') === 'light') root.setAttribute('data-theme', 'light');
    if (localStorage.getItem('dalfox-sidebar-collapsed') === '1') root.classList.add('sidebar-collapsed');
  } catch (e) {}
})();
