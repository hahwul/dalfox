// Restore the persisted "collapsed sidebar" preference before first paint so a
// collapsed sidebar never flashes open on load. Loaded synchronously in <head>
// (inline scripts are forbidden by the site CSP). The toggle logic and
// persistence live in js/ui.js.
(function () {
  try {
    if (localStorage.getItem('dalfox-sidebar-collapsed') === '1') {
      document.documentElement.classList.add('sidebar-collapsed');
    }
  } catch (e) {}
})();
