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
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(result)
	}
}
```

### Running log
go mod init your project
```
$ go mod init <YOUR_PROJECT_REPO>
```

go build 
```
$ go build -o testapp
go: finding module for package github.com/hahwul/dalfox/v2/lib
go: downloading github.com/hahwul/dalfox/v2 v2.4.5
go: found github.com/hahwul/dalfox/v2/lib in github.com/hahwul/dalfox/v2 v2.4.5
...
```

run your application
```
$ ./testapp
[] [{V GET https://xss-game.appspot.com/level1/frame?query=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprint%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E}] 2.618998247s 2021-07-11 10:59:26.508483153 +0900 KST m=+0.000794230 2021-07-11 10:59:29.127481217 +0900 KST m=+2.619792477}
```

## More info
[https://pkg.go.dev/github.com/hahwul/dalfox/v2/lib](https://pkg.go.dev/github.com/hahwul/dalfox/v2/lib)
