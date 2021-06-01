---
title: Payload Mode
permalink: /docs/modes/payload-mode/
---

`payload` mode is a mode for easy testing of XSS. Generate and Enumerate XSS Payloads and wordlists

```
▶ dalfox payload {flags}
```

e.g
```
▶ dalfox payload --enum-injs --entity-event-handler"
```

## Encoder
```
--encoder-url            Encoding output [URL]
```

## Supported
```
--entity-event-handler   Enumerate a event handlers for xss
--entity-gf              Enumerate a gf-patterns xss params
--entity-special-chars   Enumerate a special chars for xss
--entity-useful-tags     Enumerate a useful tags for xss
--enum-attr              Enumerate a in-attr xss payloads
--enum-common            Enumerate a common xss payloads
--enum-html              Enumerate a in-html xss payloads
--enum-injs              Enumerate a in-js xss payloads
--make-bulk              Make bulk payloads for stored xss
--remote-payloadbox      Enumerate a payloadbox's xss payloads
--remote-portswigger     Enumerate a portswigger xss cheatsheet payloads
```

## Screenshots
![1414](https://user-images.githubusercontent.com/13212227/120361642-0b9e1000-c345-11eb-8283-9c0b7fdac8b3.jpg)
