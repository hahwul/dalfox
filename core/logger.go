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
		text = aurora.Blue("[I] ").String() + text
	}
	if level == "WEAK" {
		text = aurora.Yellow("[W]").String() + text
	}
	if level == "VULN" {
		text = aurora.Red("[V]").String() + text
	}
	if level == "SYSTEM" {
		text = aurora.White("[*] ").String() + text
	}
	mutex.Lock()
	fmt.Fprintln(os.Stderr, text)
	mutex.Unlock()

}
