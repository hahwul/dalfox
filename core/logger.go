package core

import (
	"fmt"
	"os"
	"sync"

	"github.com/logrusorgru/aurora"
)

var (
	mutex = &sync.Mutex{}
)

// Dallog is log
func DalLog(level, text string) {
	if level == "INFO" {
		text = aurora.Blue("[INFO] ").String() + text
	}
	if level == "WEAK" {
		text = aurora.Yellow("[WEAK] ").String() + text
	}
	if level == "VULN" {
		text = aurora.Red("[VULN] ").String() + text
	}
	if level == "SYSTEM" {
		text = aurora.White("[*] ").String() + text
	}
	text = text + "\n"
	mutex.Lock()
	fmt.Fprintf(os.Stderr, text)
	mutex.Unlock()

}
