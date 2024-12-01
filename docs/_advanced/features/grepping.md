---
title: Grepping
redirect_from: /docs/grepping/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Grepping

Grepping is a passive scan with patterns during the XSS scanning flow. By default, grepping is enabled in Dalfox.

## Built-in Patterns

Dalfox includes a set of built-in patterns for grepping. Here are some examples:

```go
{
    "dalfox-ssti":                  "2958816",
    "dalfox-rsa-key":               "-----BEGIN RSA PRIVATE KEY-----|-----END RSA PRIVATE KEY-----",
    "dalfox-priv-key":              "-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----",
    "dalfox-aws-s3":                "s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com",
    "dalfox-aws-appsync-graphql":   "da2-[a-z0-9]{26}",
    "dalfox-slack-webhook1":        "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "dalfox-slack-webhook2":        "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}",
    "dalfox-slack-token":           "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "dalfox-facebook-oauth":        "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]",
    "dalfox-twitter-oauth":         "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]",
    "dalfox-heroku-api":            "[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "dalfox-mailgun-api":           "key-[0-9a-zA-Z]{32}",
    "dalfox-mailchamp-api":         "[0-9a-f]{32}-us[0-9]{1,2}",
    "dalfox-picatic-api":           "sk_live_[0-9a-z]{32}",
    "dalfox-google-oauth-id":       "[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com",
    "dalfox-google-api":            "AIza[0-9A-Za-z-_]{35}",
    "dalfox-google-oauth":          "ya29\\.[0-9A-Za-z\\-_]+",
    "dalfox-aws-access-key":        "AKIA[0-9A-Z]{16}",
    "dalfox-amazon-mws-auth-token": "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "dalfox-facebook-access-token": "EAACEdEose0cBA[0-9A-Za-z]+",
    "dalfox-github-access-token":   "[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*",
    "dalfox-github":                "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "dalfox-azure-storage":         "[a-zA-Z0-9_-]*\\.file.core.windows.net",
    "dalfox-telegram-bot-api-key":  "[0-9]+:AA[0-9A-Za-z\\-_]{33}",
    "dalfox-square-access-token":   "sq0atp-[0-9A-Za-z\\-_]{22}",
    "dalfox-square-oauth-secret":   "sq0csp-[0-9A-Za-z\\-_]{43}",
    "dalfox-twitter-access-token":  "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "dalfox-twilio-api-key":        "SK[0-9a-fA-F]{32}",
    "dalfox-braintree-token":       "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "dalfox-stripe-api-key":        "sk_live_[0-9a-zA-Z]{24}",
    "dalfox-stripe-restricted-key": "rk_live_[0-9a-zA-Z]{24}",
    "dalfox-error-mysql":           "(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \\(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\\.|com\\.mysql\\.jdbc\\.exceptions)",
    "dalfox-error-postgresql":      "(PostgreSQL.*ERROR|Warning.*\\Wpg_.*|valid PostgreSQL result|Npgsql\\.|PG::SyntaxError:|org\\.postgresql\\.util\\.PSQLException|ERROR:\\s\\ssyntax error at or near)",
    "dalfox-error-mssql":           "(Driver.* SQL[\\-\\_\\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\\s\\S]Exception.*\\WSystem\\.Data\\.SqlClient\\.|[\\s\\S]Exception.*\\WRoadhouse\\.Cms\\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})",
    "dalfox-error-msaccess":        "(Microsoft Access (\\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)",
    "dalfox-error-oracle":          "(\\bORA-\\d{5}|Oracle error|Oracle.*Driver|Warning.*\\Woci_.*|Warning.*\\Wora_.*)",
    "dalfox-error-ibmdb2":          "(CLI Driver.*DB2|DB2 SQL error|\\bdb2_\\w+\\(|SQLSTATE.+SQLCODE)",
    "dalfox-error-informix":        "(Exception.*Informix)",
    "dalfox-error-firebird":        "(Dynamic SQL Error|Warning.*ibase_.*)",
    "dalfox-error-sqlite":          "(SQLite\\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\\[SQLITE_ERROR\\])",
    "dalfox-error-sapdb":           "(SQL error.*POS([0-9]+).*|Warning.*maxdb.*)",
    "dalfox-error-sybase":          "(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\\.sybase\\.jdbc)",
    "dalfox-error-ingress":         "(Warning.*ingres_|Ingres SQLSTATE|Ingres\\W.*Driver)",
    "dalfox-error-frontbase":       "(Exception (condition )?\\d+. Transaction rollback.)",
    "dalfox-error-hsqldb":          "(org\\.hsqldb\\.jdbc|Unexpected end of command in statement \\[|Unexpected token.*in statement \\[)",

    // SQL Injection patterns
    "dalfox-error-mysql1":  "SQL syntax.*?MySQL",
    "dalfox-error-mysql2":  "Warning.*?mysqli?",
    "dalfox-error-mysql3":  "MySQLSyntaxErrorException",
    "dalfox-error-mysql4":  "valid MySQL result",
    "dalfox-error-mysql5":  "check the manual that (corresponds to|fits) your MySQL server version",
    "dalfox-error-mysql6":  "check the manual that (corresponds to|fits) your MariaDB server version",
    "dalfox-error-mysql7":  "check the manual that (corresponds to|fits) your Drizzle server version",
    "dalfox-error-mysql8":  "Unknown column '[^ ]+' in 'field list'",
    "dalfox-error-mysql9":  "com\\.mysql\\.jdbc",
    "dalfox-error-mysql10": "Zend_Db_(Adapter|Statement)_Mysqli_Exception",
    "dalfox-error-mysql11": "MySqlException",
    "dalfox-error-mysql12": "Syntax error or access violation",

    // PostgreSQL patterns
    "dalfox-error-psql1":  "PostgreSQL.*?ERROR",
    "dalfox-error-psql2":  "Warning.*?\\Wpg_",
    "dalfox-error-psql3":  "valid PostgreSQL result",
    "dalfox-error-psql4":  "Npgsql\\.",
    "dalfox-error-psql5":  "PG::SyntaxError:",
    "dalfox-error-psql6":  "org\\.postgresql\\.util\\.PSQLException",
    "dalfox-error-psql7":  "ERROR:\\s\\ssyntax error at or near",
    "dalfox-error-psql8":  "ERROR: parser: parse error at or near",
    "dalfox-error-psql9":  "PostgreSQL query failed",
    "dalfox-error-psql10": "org\\.postgresql\\.jdbc",
    "dalfox-error-psql11": "PSQLException",

    // MSSQL patterns
    "dalfox-error-mssql1":  "Driver.*? SQL[\\-\\_\\ ]*Server",
    "dalfox-error-mssql2":  "OLE DB.*? SQL Server",
    "dalfox-error-mssql3":  "\bSQL Server[^&lt;&quot;]+Driver",
    "dalfox-error-mssql4":  "Warning.*?\\W(mssql|sqlsrv)_",
    "dalfox-error-mssql5":  "\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
    "dalfox-error-mssql6":  "System\\.Data\\.SqlClient\\.SqlException",
    "dalfox-error-mssql7":  "(?s)Exception.*?\bRoadhouse\\.Cms\\.",
    "dalfox-error-mssql8":  "Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
    "dalfox-error-mssql9":  "\\[SQL Server\\]",
    "dalfox-error-mssql10": "ODBC SQL Server Driver",
    "dalfox-error-mssql11": "ODBC Driver \\d+ for SQL Server",
    "dalfox-error-mssql12": "SQLServer JDBC Driver",
    "dalfox-error-mssql13": "com\\.jnetdirect\\.jsql",
    "dalfox-error-mssql14": "macromedia\\.jdbc\\.sqlserver",
    "dalfox-error-mssql15": "Zend_Db_(Adapter|Statement)_Sqlsrv_Exception",
    "dalfox-error-mssql16": "com\\.microsoft\\.sqlserver\\.jdbc",
    "dalfox-error-mssql18": "SQL(Srv|Server)Exception"
}
```

## Disabling Built-in Grepping

If you do not want to use the built-in grepping patterns, you can disable them using the `--skip-grepping` option.

### Command

```bash
dalfox url https://google.com --skip-grepping
```

## Output Format

Here is an example of the output you can expect when grepping is enabled:

```
[*] 🦊 Start scan [SID:Single] / URL: http://testphp.vulnweb.com/listproducts.php
[G] Found dalfox-error-mysql via built-in grepping / original request
    Warning: mysql_fetch_array() expects parameter 1 to be resource, null given in /hj/var/www/listproducts.php on line 74
[POC][G][BUILT-IN/dalfox-error-mysql/GET] http://testphp.vulnweb.com/listproducts.php
```

## Using Custom Grepping

If you want to use custom grepping patterns, you can specify a custom file using the `--grep` option.

### Command

```bash
dalfox url https://google.com --grep grep_pattern.json
```

### Example Output

```
[G] Found via custom grepping / payload: 'adf , grep: internal_domain://asdf
    1 line:  internal_domain://asdf~~({"isSuccess":false,"errorMsg":"Parameter error! apps is null","error
    +> https://blahblha!~~~
```

### Sample Custom Grepping File

You can find a sample custom grepping file [here](https://github.com/hahwul/dalfox/blob/main/samples/sample_grep.json).
