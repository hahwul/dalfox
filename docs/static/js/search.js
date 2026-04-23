(function () {
  var searchData = null;
  var activeIndex = -1;
  var overlay = document.getElementById('searchOverlay');
  var input = document.getElementById('searchInput');
  var resultsEl = document.getElementById('searchResults');

  function loadSearchData(cb) {
    if (searchData) return cb(searchData);
    var base = document.querySelector('link[rel="stylesheet"]').href;
    var searchUrl = base.substring(0, base.indexOf('/css/')) + '/search.json';
    fetch(searchUrl)
      .then(function (r) { return r.json(); })
      .then(function (data) { searchData = data; cb(data); })
      .catch(function () { searchData = []; cb([]); });
  }

  window.openSearch = function () {
    overlay.classList.add('active');
    input.value = '';
    resultsEl.innerHTML = '';
    activeIndex = -1;
    input.focus();
    loadSearchData(function () {});
  };

  window.closeSearch = function () {
    overlay.classList.remove('active');
    activeIndex = -1;
  };

  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      if (overlay.classList.contains('active')) {
        closeSearch();
      } else {
        openSearch();
      }
    }
    if (e.key === 'Escape' && overlay.classList.contains('active')) {
      closeSearch();
    }
  });

  function escapeHtml(s) {
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  function highlightMatch(text, query) {
    if (!query) return escapeHtml(text);
    var escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    var re = new RegExp('(' + escaped + ')', 'gi');
    return escapeHtml(text).replace(re, '<mark>$1</mark>');
  }

  function getSnippet(content, query) {
    var lower = content.toLowerCase();
    var idx = lower.indexOf(query.toLowerCase());
    var start = Math.max(0, idx - 60);
    var end = Math.min(content.length, idx + query.length + 100);
    var snippet = content.substring(start, end).replace(/\s+/g, ' ').trim();
    if (start > 0) snippet = '...' + snippet;
    if (end < content.length) snippet = snippet + '...';
    return snippet;
  }

  function search(query) {
    if (!searchData || !query.trim()) {
      resultsEl.innerHTML = '';
      activeIndex = -1;
      return;
    }
    var q = query.trim().toLowerCase();
    var results = [];
    for (var i = 0; i < searchData.length; i++) {
      var item = searchData[i];
      var titleIdx = item.title.toLowerCase().indexOf(q);
      var contentIdx = item.content.toLowerCase().indexOf(q);
      if (titleIdx !== -1 || contentIdx !== -1) {
        var score = titleIdx !== -1 ? 100 - titleIdx : contentIdx;
        results.push({ item: item, score: score });
      }
    }
    results.sort(function (a, b) { return b.score - a.score; });
    results = results.slice(0, 10);

    if (results.length === 0) {
      resultsEl.innerHTML = '<div class="search-no-results">No results for "' + escapeHtml(query) + '"</div>';
      activeIndex = -1;
      return;
    }

    var html = '';
    for (var j = 0; j < results.length; j++) {
      var r = results[j].item;
      var snippet = getSnippet(r.content, query.trim());
      html += '<a class="search-result-item" href="' + r.url + '" data-index="' + j + '">'
        + '<div class="search-result-title">' + highlightMatch(r.title, query.trim()) + '</div>'
        + '<div class="search-result-snippet">' + highlightMatch(snippet, query.trim()) + '</div>'
        + '</a>';
    }
    html += '<div class="search-hint"><span><kbd>&uarr;</kbd><kbd>&darr;</kbd> navigate</span><span><kbd>Enter</kbd> open</span><span><kbd>ESC</kbd> close</span></div>';
    resultsEl.innerHTML = html;
    activeIndex = -1;
  }

  function updateActive() {
    var items = resultsEl.querySelectorAll('.search-result-item');
    for (var i = 0; i < items.length; i++) {
      items[i].classList.toggle('active', i === activeIndex);
    }
    if (activeIndex >= 0 && items[activeIndex]) {
      items[activeIndex].scrollIntoView({ block: 'nearest' });
    }
  }

  if (input) {
    input.addEventListener('input', function () {
      loadSearchData(function () { search(input.value); });
    });

    input.addEventListener('keydown', function (e) {
      var items = resultsEl.querySelectorAll('.search-result-item');
      var count = items.length;
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        activeIndex = (activeIndex + 1) % count;
        updateActive();
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        activeIndex = (activeIndex - 1 + count) % count;
        updateActive();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (activeIndex >= 0 && items[activeIndex]) {
          window.location.href = items[activeIndex].href;
        } else if (items.length > 0) {
          window.location.href = items[0].href;
        }
      }
    });
  }
})();