---
title: Use config file
permalink: /docs/config/
---

## Make config file
Please check [sample file](https://github.com/hahwul/dalfox/blob/main/samples/sample_config.json)
```json
{
	"Header":"",
	"Cookie":"",
	"UniqParam":"",
	"BlindURL":"",
	"CustomPayloadFile":"",
	"Data":"",
	"UserAgent":"",
	"OutputFile":"",
	"Format":"",
	"FoundAction":"",
	"Proxy":"",
	"Timeout": 30,
	"Concurrence": 100,
	"Delay": 30,
	"OnlyDiscovery": false
}
```

and Config is mapped to options.model.
https://github.com/hahwul/dalfox/blob/main/pkg/model/options.go

e.g
```
$ dalfox url https://google.com --config config.json 
```
