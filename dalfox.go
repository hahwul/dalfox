/*
Code by @hahwul
Happy hacking :D
*/
package main

import (
	"runtime"

	"github.com/hahwul/dalfox/v2/cmd"
)

func main() {
	// Default setting
	runtime.GOMAXPROCS(1)
	cmd.Execute()
}
