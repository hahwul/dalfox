---
title: In the Code
permalink: /docs/code/
---

## Get libary of dalfox
```
▶ go get github.com/hahwul/dalfox/v2/lib
```

## Sample of code
```go
package main 

import (
	"fmt"

	dalfox "github.com/hahwul/dalfox/v2/lib"
)

func main() {
	opt := dalfox.Options{
		Cookie:     "ABCD=1234",
	}
	result, err := dalfox.NewScan(dalfox.Target{
		URL:     "https://xss-game.appspot.com/level1/frame",
		Method:  "GET",
		Options: opt,
	})
	if err != {
		fmt.Println(err)
	} else {
		fmt.Println(result)
	}
}
```

## More info
[https://pkg.go.dev/github.com/hahwul/dalfox/v2/lib](https://pkg.go.dev/github.com/hahwul/dalfox/v2/lib)
