// Example 1: Basic DOM XSS vulnerability
let urlParam = location.search;
document.getElementById('foo').innerHTML = urlParam;

// Example 2: Eval with location hash
let hash = location.hash;
eval(hash);

// Example 3: Document.write with cookie
let data = document.cookie;
document.write(data);

// Example 4: Direct source to sink
document.write(location.search);

// Example 5: Template literal (tainted)
let search = location.search;
let html = `<div>${search}</div>`;
document.body.innerHTML = html;

// Example 6: Safe code (no vulnerability)
let safeData = "Hello World";
document.getElementById('bar').innerHTML = safeData;
