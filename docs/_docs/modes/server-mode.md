---
title: Server Mode (REST API)
permalink: /docs/modes/server-mode/
---
`server` mode is a REST API mode that takes into account scalability. Using this mode, dalfox acts as a REST API server and can perform scanning using a web request.
```
$ dalfox server
```

e.g
```
$ dalfox server --host 0.0.0.0 --port 8090
```

and supported swagger-ui
![](https://user-images.githubusercontent.com/13212227/89736705-5002ab80-daa6-11ea-9ee8-d2def396c25a.png)
