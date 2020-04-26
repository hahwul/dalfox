package printing

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"
)

var (
	mutex = &sync.Mutex{}
)

// DalLog is log fomatting for DalFox
func DalLog(level, text string, optionsStr map[string]string) {
	fdata := text
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

	if level == "ERROR" {
		text = aurora.Yellow("[E] ").String() + text
	}

	//mutex.Lock()
	if level == "PRINT" {
		text = "    +> " + text
		fmt.Println(text)
	} else {
		text = "\r" + text
		fmt.Fprintln(os.Stderr, text)
	}

	if optionsStr["output"] != "" {
		var ftext string
		if strings.ToLower(optionsStr["format"]) == "json" {
			escapedFdata := strings.ReplaceAll(fdata, "\"", "\\\"")
			ftext = "{\"type\":\"" + level + "\",\"text\":\"" + escapedFdata + "\"},"
		} else if strings.ToLower(optionsStr["format"]) == "xml" {
			escapedFdata := strings.ReplaceAll(fdata, "<", "&lt;")
			escapedFdata = strings.ReplaceAll(escapedFdata, ">", "&gt;")
			ftext = "<log><type>" + level + "</type><value>" + escapedFdata + "</value></log>"
		} else { // format: txt or any case
			ftext = text
		}
		f, err := os.OpenFile(optionsStr["output"],
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "output file error (file)")
		}
		defer f.Close()
		if _, err := f.WriteString(ftext + "\n"); err != nil {
			fmt.Fprintln(os.Stderr, "output file error (write)")
		}
	}
	//mutex.Unlock()

}
