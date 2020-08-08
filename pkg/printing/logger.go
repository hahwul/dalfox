package printing

import (
	"fmt"
	"os"
	"sync"

	"github.com/logrusorgru/aurora"
)

var (
	mutex = &sync.Mutex{}
)

// DalLog is log fomatting for DalFox
func DalLog(level, text string, optionsStr map[string]string) {
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

	if level == "YELLOW"{
		text = aurora.BrightYellow(text).String()
	}

	//mutex.Lock()
	if optionsStr["silence"] != "" {
		ftext = "[POC] "+text
	} else {
		if level == "PRINT" {
			if optionsStr["format"] == "json" {
				ftext = text
				//fmt.Println(aurora.BrightGreen(text))
				fmt.Println(text)

			} else {
				ftext = "[POC] "+text
				fmt.Println(aurora.BrightGreen("[POC]"+text))
			}
		} else {
			text = "\r" + text
			fmt.Fprintln(os.Stderr, text)
		}
	}

	if optionsStr["output"] != "" {
		var fdtext string
		fdtext = ftext
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
