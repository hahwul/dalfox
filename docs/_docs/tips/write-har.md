---
title: Write HAR file for interaction with other tools
permalink: /docs/tips/write-har/
---

In dalfox 2.9 and later, all requests can be logged in HAR format. Enter the file path to save using `--har-file-path` flag.

```
▶ dalfox url --no-spinner \
    --no-color \
    --output-all \
    --follow-redirects \
    --silence \
    --format json \
    --har-file-path dump.har \
    http://testphp.vulnweb.com/listproducts.php?cat=2
```

<details>
  <summary>jq output (click to expand)</summary>
  
```json
[
  {
    "startedDateTime": "2023-02-13T14:32:31+11:00",
    "time": 413.50575,
    "request": {
      "method": "GET",
      "url": "http://testphp.vulnweb.com/listproducts.php?cat=2%27%22%3E%3Csvg%2Fclass%3Ddalfox+onload%3D%26%2397%26%23108%26%23101%26%23114%26%2300116%26%2340%26%2341%26%23x2f%26%23x2f",
      "httpVersion": "HTTP/1.1",
      "cookies": [],
      "headers": [
        {
          "name": "Accept",
          "value": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
        },
        {
          "name": "User-Agent",
          "value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0"
        }
      ],
      "queryString": [
        {
          "name": "cat",
          "value": "2'\"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f"
        }
      ],
      "headersSize": -1,
      "bodySize": -1
    },
    "response": {
      "status": 200,
      "statusText": "200 OK",
      "httpVersion": "HTTP/1.1",
      "cookies": [],
      "headers": [
        {
          "name": "Server",
          "value": "nginx/1.19.0"
        },
        {
          "name": "Date",
          "value": "Mon, 13 Feb 2023 03:32:31 GMT"
        },
        {
          "name": "Content-Type",
          "value": "text/html; charset=UTF-8"
        },
        {
          "name": "X-Powered-By",
          "value": "PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1"
        }
      ],
      "content": {
        "size": -1,
        "mimeType": "text/html; charset=UTF-8",
        "text": "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n\"http://www.w3.org/TR/html4/loose.dtd\">\n<html><!-- InstanceBegin template=\"/Templates/main_dynamic_template.dwt.php\" codeOutsideHTMLIsLocked=\"false\" -->\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=iso-8859-2\">\n\n<!-- InstanceBeginEditable name=\"document_title_rgn\" -->\n<title>pictures</title>\n<!-- InstanceEndEditable -->\n<link rel=\"stylesheet\" href=\"style.css\" type=\"text/css\">\n<!-- InstanceBeginEditable name=\"headers_rgn\" -->\n<!-- InstanceEndEditable -->\n<script language=\"JavaScript\" type=\"text/JavaScript\">\n<!--\nfunction MM_reloadPage(init) {  //reloads the window if Nav4 resized\n  if (init==true) with (navigator) {if ((appName==\"Netscape\")&&(parseInt(appVersion)==4)) {\n    document.MM_pgW=innerWidth; document.MM_pgH=innerHeight; onresize=MM_reloadPage; }}\n  else if (innerWidth!=document.MM_pgW || innerHeight!=document.MM_pgH) location.reload();\n}\nMM_reloadPage(true);\n//-->\n</script>\n\n</head>\n<body> \n<div id=\"mainLayer\" style=\"position:absolute; width:700px; z-index:1\">\n<div id=\"masthead\"> \n  <h1 id=\"siteName\"><a href=\"https://www.acunetix.com/\"><img src=\"images/logo.gif\" width=\"306\" height=\"38\" border=\"0\" alt=\"Acunetix website security\"></a></h1>   \n  <h6 id=\"siteInfo\">TEST and Demonstration site for <a href=\"https://www.acunetix.com/vulnerability-scanner/\">Acunetix Web Vulnerability Scanner</a></h6>\n  <div id=\"globalNav\"> \n      \t<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tr>\n\t<td align=\"left\">\n\t\t<a href=\"index.php\">home</a> | <a href=\"categories.php\">categories</a> | <a href=\"artists.php\">artists\n\t\t</a> | <a href=\"disclaimer.php\">disclaimer</a> | <a href=\"cart.php\">your cart</a> | \n\t\t<a href=\"guestbook.php\">guestbook</a> | \n\t\t<a href=\"AJAX/index.php\">AJAX Demo</a>\n\t</td>\n\t<td align=\"right\">\n\t\t</td>\n\t</tr></table>\n  </div> \n</div> \n<!-- end masthead --> \n\n<!-- begin content -->\n<!-- InstanceBeginEditable name=\"content_rgn\" -->\n<div id=\"content\">\n\tError: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''\"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f' at line 1\nWarning: mysql_fetch_array() expects parameter 1 to be resource, boolean given in /hj/var/www/listproducts.php on line 74\n</div>\n<!-- InstanceEndEditable -->\n<!--end content -->\n\n<div id=\"navBar\"> \n  <div id=\"search\"> \n    <form action=\"search.php?test=query\" method=\"post\"> \n      <label>search art</label> \n      <input name=\"searchFor\" type=\"text\" size=\"10\"> \n      <input name=\"goButton\" type=\"submit\" value=\"go\"> \n    </form> \n  </div> \n  <div id=\"sectionLinks\"> \n    <ul> \n      <li><a href=\"categories.php\">Browse categories</a></li> \n      <li><a href=\"artists.php\">Browse artists</a></li> \n      <li><a href=\"cart.php\">Your cart</a></li> \n      <li><a href=\"login.php\">Signup</a></li>\n\t  <li><a href=\"userinfo.php\">Your profile</a></li>\n\t  <li><a href=\"guestbook.php\">Our guestbook</a></li>\n\t\t<li><a href=\"AJAX/index.php\">AJAX Demo</a></li>\n\t  </li> \n    </ul> \n  </div> \n  <div class=\"relatedLinks\"> \n    <h3>Links</h3> \n    <ul> \n      <li><a href=\"http://www.acunetix.com\">Security art</a></li> \n\t  <li><a href=\"https://www.acunetix.com/vulnerability-scanner/php-security-scanner/\">PHP scanner</a></li>\n\t  <li><a href=\"https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/\">PHP vuln help</a></li>\n\t  <li><a href=\"http://www.eclectasy.com/Fractal-Explorer/index.html\">Fractal Explorer</a></li> \n    </ul> \n  </div> \n  <div id=\"advert\"> \n    <p>\n      <object classid=\"clsid:D27CDB6E-AE6D-11cf-96B8-444553540000\" codebase=\"http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,29,0\" width=\"107\" height=\"66\">\n        <param name=\"movie\" value=\"Flash/add.swf\">\n        <param name=quality value=high>\n        <embed src=\"Flash/add.swf\" quality=high pluginspage=\"http://www.macromedia.com/shockwave/download/index.cgi?P1_Prod_Version=ShockwaveFlash\" type=\"application/x-shockwave-flash\" width=\"107\" height=\"66\"></embed>\n      </object>\n    </p>\n  </div> \n</div> \n\n<!--end navbar --> \n<div id=\"siteInfo\">  <a href=\"http://www.acunetix.com\">About Us</a> | <a href=\"privacy.php\">Privacy Policy</a> | <a href=\"mailto:wvs@acunetix.com\">Contact Us</a> | &copy;2019\n  Acunetix Ltd \n</div> \n<br> \n<div style=\"background-color:lightgray;width:100%;text-align:center;font-size:12px;padding:1px\">\n<p style=\"padding-left:5%;padding-right:5%\"><b>Warning</b>: This is not a real shop. This is an example PHP application, which is intentionally vulnerable to web attacks. It is intended to help you test Acunetix. It also helps you understand how developer errors and bad configuration may let someone break into your website. You can use it to test other tools and your manual hacking skills as well. Tip: Look for potential SQL Injections, Cross-site Scripting (XSS), and Cross-site Request Forgery (CSRF), and more.</p>\n</div>\n</div>\n</body>\n<!-- InstanceEnd --></html>\n"
      },
      "redirectURL": "",
      "headersSize": -1,
      "bodySize": -1
    },
    "cache": null,
    "timings": {
      "blocked": 0.001791,
      "dns": 0.775084,
      "connect": 190.115667,
      "send": 0.016708,
      "wait": 222.568834,
      "receive": 0.80275,
      "ssl": -1
    },
    "_messageId": 322
  }
]
```
</details>

Example of the HAR file being loaded in to Chrome dev tools.

![chrome screenshot](https://user-images.githubusercontent.com/369053/218365521-5df5ff3c-759e-4bb8-9205-a45ac25481ca.png)

## Reference
- [https://github.com/hahwul/dalfox/pull/440](https://github.com/hahwul/dalfox/pull/440)
