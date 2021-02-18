package printing

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

var (
	mutex = &sync.Mutex{}
)

func boolToColorStr(b bool, options model.Options) string {
	str := ""
	if b {
		str = options.AuroraObject.BrightGreen(strconv.FormatBool(b)).String()
	} else {
		str = options.AuroraObject.BrightRed(strconv.FormatBool(b)).String()
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
		fmt.Fprintf(os.Stderr, "\n 🎯  Target                 %s\n", options.AuroraObject.BrightYellow(target).String())
		fmt.Fprintf(os.Stderr, " 🏁  Method                 %s\n", options.AuroraObject.BrightBlue(options.Method).String())
		fmt.Fprintf(os.Stderr, " 🧞‍♂️  Worker                 %d\n", options.Concurrence)
		fmt.Fprintf(os.Stderr, " 🦹🏼‍♂️  BAV                    %s\n", boolToColorStr(!options.NoBAV, options))
		fmt.Fprintf(os.Stderr, " ⛏   Mining                 %s (%s)\n", boolToColorStr(options.Mining, options), miningWord)
		fmt.Fprintf(os.Stderr, " 🔬  Mining-DOM             %s (mining from DOM)\n", boolToColorStr(options.FindingDOM, options))
		if options.BlindURL != "" {
			fmt.Fprintf(os.Stderr, " 🛰   Blind XSS Callback     %s\n", options.AuroraObject.BrightBlue(options.BlindURL).String())
		}
		fmt.Fprintf(os.Stderr, " ⏱   Timeout                %d\n", options.Timeout)
		fmt.Fprintf(os.Stderr, " 📤  FollowRedirect         %s\n", boolToColorStr(options.FollowRedirect, options))
		fmt.Fprintf(os.Stderr, " 🕰   Started at             %s\n", options.StartTime.String())
		//fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\n >>>>>>>>>>>>>>>>>>>>>>>>>\n")
	}
}

// DalLog is log fomatting for DalFox
func DalLog(level, text string, options model.Options) {
	var ftext string
	switch level {
	case "INFO":
		if options.Debug {
			ftext = "[I] " + text
		}
		text = options.AuroraObject.BrightBlue("[I] ").String() + text

	case "WEAK":
		if options.Debug {
			ftext = "[W] " + text
		}
		text = options.AuroraObject.Yellow("[W] ").String() + text

	case "VULN":
		if options.Debug {
			ftext = "[V] " + text
		}
		text = options.AuroraObject.BrightRed("[V] ").String() + text

	case "SYSTEM":
		if options.Debug {
			ftext = "[*] " + text
		}
		if options.NoSpinner {
			text = options.AuroraObject.White("[*] ").String() + text
		} else if !(options.Silence || options.NoSpinner) {
			setSpinner(text, options)
			text = "HIDDENMESSAGE!!"
		}

	case "SYSTEM-M":
		if options.Debug {
			ftext = "[*] " + text
		}
		text = options.AuroraObject.White("[*] ").String() + text
		fmt.Fprintln(os.Stderr, text)

	case "GREP":
		if options.Debug {
			ftext = "[G] " + text
		}
		text = options.AuroraObject.Green("[G] ").String() + text
	case "CODE":
		if options.Debug {
			ftext = "    " + text
		}
		text = options.AuroraObject.Gray(16-1, "    "+text).String()
	case "ERROR":
		if options.Debug {
			ftext = "[E] " + text
		}
		text = options.AuroraObject.Yellow("[E] ").String() + text

	case "YELLOW":
		text = options.AuroraObject.BrightYellow(text).String()
	}

	// Printing
	mutex.Lock()
	if level == "PRINT" {
		if options.Silence {
			stopSpinner(options)
		}
		if options.Format == "json" {
			ftext = text
			//fmt.Println(options.AuroraObject.BrightGreen(text))
			fmt.Println(text)

		} else {
			ftext = "[POC] " + text
			fmt.Println(options.AuroraObject.BrightMagenta("[POC]" + text))
		}
		if options.Silence {
			restartSpinner(options)
		}
	} else {
		if !options.Silence {
			if text != "HIDDENMESSAGE!!" {
				text = "\r" + text
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
