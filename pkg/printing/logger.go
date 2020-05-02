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
	var ftext string
	if level == "INFO" {
		if optionsStr["output"] != "" {
			ftext = "[I] " + text
		}
		text = aurora.Blue("[I] ").String() + text

	}
	if level == "WEAK" {
		if optionsStr["output"] != "" {
			ftext = "[W] " + text
		}
		text = aurora.Yellow("[W] ").String() + text

	}
	if level == "VULN" {
		if optionsStr["output"] != "" {
			ftext = "[V] " + text
		}
		text = aurora.Red("[V] ").String() + text

	}
	if level == "SYSTEM" {
		if optionsStr["output"] != "" {
			ftext = "[*] " + text
		}
		text = aurora.White("[*] ").String() + text

	}
	if level == "GREP" {
		if optionsStr["output"] != "" {
			ftext = "[G] " + text
		}
		text = aurora.Green("[G] ").String() + text

	}

	if level == "CODE" {
		if optionsStr["output"] != "" {
			ftext = "    " + text
		}
		text = aurora.Gray(16-1, "    "+text).String()
	}

	if level == "ERROR" {
		if optionsStr["output"] != "" {
			ftext = "[I] " + text
		}
		text = aurora.Yellow("[E] ").String() + text
	}

	//mutex.Lock()
	if optionsStr["silence"] != "" {
		ftext = "    +> " + text
	} else {
		if level == "PRINT" {
			ftext = "    +> " + text
			text = "    +> " + text
			fmt.Println(text)
		} else {
			text = "\r" + text
			fmt.Fprintln(os.Stderr, text)
		}
	}

	if optionsStr["output"] != "" {
		var fdtext string
		if strings.ToLower(optionsStr["format"]) == "json" {
			escapedFdata := strings.ReplaceAll(fdata, "\"", "\\\"")
			fdtext = "{\"type\":\"" + level + "\",\"text\":\"" + escapedFdata + "\"},"
		} else if strings.ToLower(optionsStr["format"]) == "xml" {
			escapedFdata := strings.ReplaceAll(fdata, "<", "&lt;")
			escapedFdata = strings.ReplaceAll(escapedFdata, ">", "&gt;")
			fdtext = "<log><type>" + level + "</type><value>" + escapedFdata + "</value></log>"
		} else { // format: txt or any case
			fdtext = ftext
		}
		f, err := os.OpenFile(optionsStr["output"],
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "output file error (file)")
		}
		defer f.Close()
		if _, err := f.WriteString(fdtext + "\n"); err != nil {
			fmt.Fprintln(os.Stderr, "output file error (write)")
		}
	}
	//mutex.Unlock()

}
