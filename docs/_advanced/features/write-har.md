---
title: Write HAR file
redirect_from: /docs/tips/write-har/
nav_order: 1
parent: Features
toc: true
layout: page
---

# Write HAR file
{: .d-inline-block }

SINCE (v2.9.0) 
{: .label .label-green }

In Dalfox 2.9 and later, all requests can be logged in HAR format. This allows you to save the HTTP Archive (HAR) file for further analysis or interaction with other tools.

## Generating a HAR File

To generate a HAR file, use the `--har-file-path` flag to specify the file path where the HAR file will be saved. Here is an example command:

```bash
dalfox url http://testphp.vulnweb.com/listproducts.php?cat=2 \
    --no-spinner \
    --no-color \
    --output-all \
    --follow-redirects \
    --silence \
    --format json \
    --har-file-path dump.har
```

## Example HAR File

Here is an example of the content you can expect in the generated HAR file:

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
        "text": "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\n\"http://www.w3.org/TR/html4/loose.dtd\">\n<html><!-- InstanceBegin template=\"/Templates/...snip...meone break into your website. You can use it to test other tools and your manual hacking skills as well. Tip: Look for potential SQL Injections, Cross-site Scripting (XSS), and Cross-site Request Forgery (CSRF), and more.</p>\n</div>\n</div>\n</body>\n<!-- InstanceEnd --></html>\n"
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

## Viewing the HAR File

You can load the generated HAR file into Chrome DevTools or other tools that support HAR format for detailed analysis.

![chrome screenshot](https://user-images.githubusercontent.com/369053/218365521-5df5ff3c-759e-4bb8-9205-a45ac25481ca.png)

## Additional Resources

For more information and advanced usage, please refer to the [pull request](https://github.com/hahwul/dalfox/pull/440) that introduced this feature.