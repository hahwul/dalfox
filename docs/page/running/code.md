---
title: In the Code
redirect_from: /docs/code/
parent: Running
nav_order: 4
toc: true
layout: page
---

# Using Dalfox in Your Code

This guide provides detailed instructions on how to use Dalfox as a library in your Go projects. Follow the steps below to integrate Dalfox into your code.

## Get the Dalfox Library

First, you need to download the Dalfox library using the `go get` command:

```bash
go get github.com/hahwul/dalfox/v2/lib
```

## Sample Code

Here is a sample Go program that demonstrates how to use the Dalfox library to perform a scan:

```go
package main 

import (
    "fmt"

    dalfox "github.com/hahwul/dalfox/v2/lib"
)

func main() {
    // Set up options for the scan
    opt := dalfox.Options{
        Cookie: "ABCD=1234",
    }

    // Create a new scan target
    target := dalfox.Target{
        URL:     "https://xss-game.appspot.com/level1/frame",
        Method:  "GET",
        Options: opt,
    }

    // Perform the scan
    result, err := dalfox.NewScan(target)
    if err != nil {
        fmt.Println("Error:", err)
    } else {
        fmt.Println("Scan Result:", result)
    }
}
```

## Running the Code

To run the sample code, follow these steps:

### Initialize Your Project

First, initialize your Go module:

```bash
go mod init <YOUR_PROJECT_REPO>
```

Replace `<YOUR_PROJECT_REPO>` with the path to your project repository.

### Build the Application

Next, build your application:

```bash
go build -o testapp
```

During the build process, Go will download the Dalfox library and its dependencies.

### Run the Application

Finally, run your application:

```bash
./testapp
```

You should see output similar to the following:

```bash
# [] [{V GET https://xss-game.appspot.com/level1/frame?query=%3Ciframe+srcdoc%3D%22%3Cinput+onauxclick%3Dprint%281%29%3E%22+class%3Ddalfox%3E%3C%2Fiframe%3E}] 2.618998247s 2021-07-11 10:59:26.508483153 +0900 KST m=+0.000794230 2021-07-11 10:59:29.127481217 +0900 KST m=+2.619792477
```

## More Information

For more information and advanced usage, please refer to the [official Dalfox library documentation](https://pkg.go.dev/github.com/hahwul/dalfox/v2).