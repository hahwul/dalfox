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
		text = aurora.Yellow("[W] ").String() + text
	}
	if level == "VULN" {
		text = aurora.Red("[V] ").String() + text
	}
	if level == "SYSTEM" {
		text = aurora.White("[*] ").String() + text
	}

	if level == "CODE" {
		text = aurora.Gray(16-1, "    "+text).String()
	}

	//mutex.Lock()
	if level == "PRINT" {
		text = " -  " + text
		fmt.Println(text)
	} else {
		fmt.Fprintln(os.Stderr, text)
	}
	//mutex.Unlock()

}
