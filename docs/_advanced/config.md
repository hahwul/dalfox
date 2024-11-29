---
title: Configurations
redirect_from: /docs/config/
nav_order: 5
toc: true
layout: page
---

## Make config file
Please check [sample file](https://github.com/hahwul/dalfox/blob/main/samples/sample_config.json)
```json
{
	"header":[
		""
	],
	"cookie":"",
	"param":[
		""
	],
	"blind":"",
	"custom-payload-file":"",
	"data":"",
	"user-agent":"",
	"output":"",
	"format":"",
	"found-action":"",
	"proxy":"",
	"timeout": 30,
	"worker": 100,
	"delay": 30,
	"only-discovery": false
}

```

and Config is mapped to options.model.
https://github.com/hahwul/dalfox/blob/main/pkg/model/options.go

e.g
```
$ dalfox url https://google.com --config config.json 
```
