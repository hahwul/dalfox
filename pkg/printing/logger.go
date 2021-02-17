package printing

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hahwul/dalfox/v2/pkg/model"
	"github.com/logrusorgru/aurora"
)

var (
	mutex = &sync.Mutex{}
)

func boolToColorStr(b bool) string {
	str := ""
	if b {
		str = aurora.BrightGreen(strconv.FormatBool(b)).String()
	} else {
		str = aurora.BrightRed(strconv.FormatBool(b)).String()
	}
	return str
}

// Summary is printing options
func Summary(options model.Options, target string) {
	if !options.Silence {
		miningWord := "Gf-Patterns"
		if options.MiningWordlist != "" {
			miningWord = options.MiningWordlist
		}

		fmt.Fprintf(os.Stderr, "\n 🎯  Target: %s\n", aurora.BrightYellow(target).String())
		fmt.Fprintf(os.Stderr, "───────────────────────────┬───────────────────────────────────────\n")
		fmt.Fprintf(os.Stderr, " 🏁  Method                │ %s\n", aurora.BrightBlue(options.Method).String())
		fmt.Fprintf(os.Stderr, " 🧞‍♂️  Worker                │ %d\n", options.Concurrence)
		fmt.Fprintf(os.Stderr, " 🦹🏼‍♂️  BAV                   │ %s\n", boolToColorStr(!options.NoBAV))
		fmt.Fprintf(os.Stderr, " ⛏   Mining                │ %s (%s)\n", boolToColorStr(options.Mining), miningWord)
		fmt.Fprintf(os.Stderr, " 🔬  Mining-DOM            │ %s (mining from DOM)\n", boolToColorStr(options.FindingDOM))
		if options.BlindURL != "" {
			fmt.Fprintf(os.Stderr, " 🛰   Blind XSS Callback    │ %s\n", aurora.BrightBlue(options.BlindURL).String())
		}
		fmt.Fprintf(os.Stderr, " ⏱   Timeout               │ %d\n", options.Timeout)
		fmt.Fprintf(os.Stderr, " 📤  FollowRedirect        │ %s\n", boolToColorStr(options.FollowRedirect))
		fmt.Fprintf(os.Stderr, "───────────────────────────┴───────────────────────────────────────\n")
	}
}

// DalLog is log fomatting for DalFox
func DalLog(level, text string, options model.Options) {
	var ftext string
	if level == "INFO" {
		if options.Debug {
			ftext = "[I] " + text
		}
		text = aurora.Blue("[I] ").String() + text

	}
	if level == "WEAK" {
		if options.Debug {
			ftext = "[W] " + text
		}
		text = aurora.Yellow("[W] ").String() + text

	}
	if level == "VULN" {
		if options.Debug {
			ftext = "[V] " + text
		}
		text = aurora.Red("[V] ").String() + text

	}
	if level == "SYSTEM" {
		if options.Debug {
			ftext = "[*] " + text
		}
		if options.NoSpinner {
			text = aurora.White("[*] ").String() + text
		} else if !(options.Silence || options.NoSpinner) {
			setSpinner("[ SYSTEM ] [ "+text+" ]", options)
			text = "HIDDENMESSAGE!!"
		}
	}
	//!(options.Silence || options.NoSpinner)
	if level == "SYSTEM-M" {
		if options.Debug {
			ftext = "[*] " + text
		}
		text = aurora.White("[*] ").String() + text
		fmt.Fprintln(os.Stderr, text)
	}
	if level == "GREP" {
		if options.Debug {
			ftext = "[G] " + text
		}
		text = aurora.Green("[G] ").String() + text

	}

	if level == "CODE" {
		if options.Debug {
			ftext = "    " + text
		}
		text = aurora.Gray(16-1, "    "+text).String()
	}

	if level == "ERROR" {
		if options.Debug {
			ftext = "[E] " + text
		}
		text = aurora.Yellow("[E] ").String() + text
	}

	if level == "YELLOW" {
		text = aurora.BrightYellow(text).String()
	}

	mutex.Lock()
	if options.Silence {
		if level == "PRINT" {
			stopSpinner(options)
			if options.Format == "json" {
				ftext = text
				//fmt.Println(aurora.BrightGreen(text))
				fmt.Println(text)

			} else {
				ftext = "[POC] " + text
				if options.NoColor {
					fmt.Println("[POC]" + text)
				} else {
					fmt.Println(aurora.BrightGreen("[POC]" + text))
				}
			}
			restartSpinner(options)
		}
	} else {
		if level == "PRINT" {
			if options.Format == "json" {
				ftext = text
				//fmt.Println(aurora.BrightGreen(text))
				fmt.Println(text)

			} else {
				ftext = "[POC] " + text
				if options.NoColor {
					fmt.Println("[POC]" + text)
				} else {
					fmt.Println(aurora.BrightGreen("[POC]" + text))
				}
			}
		} else {
			if text != "HIDDENMESSAGE!!" {
				if options.NoColor {
					text = "\r" + ftext
				} else {
					text = "\r" + text
				}
				fmt.Fprintln(os.Stderr, text)
			}
		}
	}

	if options.OutputFile != "" {
		var fdtext string
		if ftext != "" {
			fdtext = ftext
			f, err := os.OpenFile(options.OutputFile,
				os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				fmt.Fprintln(os.Stderr, "output file error (file)")
			}
			defer f.Close()
			if _, err := f.WriteString(fdtext + "\n"); err != nil {
				fmt.Fprintln(os.Stderr, "output file error (write)")
			}
		}
	}
	mutex.Unlock()
}

func setSpinner(str string, options model.Options) {
	if options.SpinnerObject != nil {
		options.SpinnerObject.Suffix = "  " + str
	}
}

func restartSpinner(options model.Options) {
	if options.SpinnerObject != nil {
		options.SpinnerObject.Restart()
	}
}

func stopSpinner(options model.Options) {
	if options.SpinnerObject != nil {
		options.SpinnerObject.Stop()
	}
}
