package printing

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hahwul/dalfox/v2/pkg/model"
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
		if target == "REST API Mode" {
			fmt.Fprintf(os.Stderr, " 🧲  Listen Address         %s\n", options.AuroraObject.BrightBlue(options.ServerHost+":"+strconv.Itoa(options.ServerPort)).String())
		}
		fmt.Fprintf(os.Stderr, " 🏁  Method                 %s\n", options.AuroraObject.BrightBlue(options.Method).String())
		fmt.Fprintf(os.Stderr, " 🖥   Worker                 %d\n", options.Concurrence)
		fmt.Fprintf(os.Stderr, " 🔦  BAV                    %s\n", boolToColorStr(!options.NoBAV, options))
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
	var mutex *sync.Mutex
	if options.Mutex != nil {
		mutex = options.Mutex
	} else {
		mutex = &sync.Mutex{}
	}
	var ftext string
	var allWrite = false
	if options.Debug {
		allWrite = true
	}
	if options.OutputAll {
		allWrite = true
	}

	switch level {
	case "DEBUG":
		if options.Debug {
			if allWrite {
				ftext = "[DEBUG] " + text
			}
			text = options.AuroraObject.BrightBlue("[DEBUG] ").String() + text
		} else {
			return
		}

	case "INFO":
		if allWrite {
			ftext = "[I] " + text
		}
		text = options.AuroraObject.BrightBlue("[I] ").String() + text

	case "WEAK":
		if allWrite {
			ftext = "[W] " + text
		}
		text = options.AuroraObject.Yellow("[W] ").String() + text

	case "VULN":
		if allWrite {
			ftext = "[V] " + text
		}
		text = options.AuroraObject.BrightRed("[V] ").String() + text

	case "SYSTEM":
		if allWrite {
			ftext = "[*] " + text
		}
		if options.NoSpinner {
			text = options.AuroraObject.White("[*] ").String() + text
		} else if !(options.Silence || options.NoSpinner) {
			SetSpinner(text, options)
			text = "HIDDENMESSAGE!!"
		}

	case "SYSTEM-M":
		if allWrite {
			ftext = "[*] " + text
		}
		text = options.AuroraObject.White("[*] ").String() + text
		if options.Silence && options.MulticastMode {
			StopSpinner(options)
			fmt.Fprintln(os.Stderr, text)
			RestartSpinner(options)
		}

	case "GREP":
		if allWrite {
			ftext = "[G] " + text
		}
		text = options.AuroraObject.Green("[G] ").String() + text
	case "CODE":
		if text == "" {
			return
		}
		if allWrite {
			ftext = "    " + text
		}
		text = options.AuroraObject.Gray(16-1, "    "+text).String()
	case "ERROR":
		if allWrite {
			ftext = "[E] " + text
		}
		text = options.AuroraObject.Yellow("[E] ").String() + text

	case "YELLOW":
		text = options.AuroraObject.BrightYellow(text).String()
	}

	// Printing
	mutex.Lock()
	if options.IsLibrary {
		options.ScanResult.Logs = append(options.ScanResult.Logs, text)
	} else {
		if level == "PRINT" {
			StopSpinner(options)
			if options.Format == "json" {
				ftext = text
				fmt.Println(text)
			} else {
				ftext = "[POC]" + text
				fmt.Println(options.AuroraObject.BrightMagenta("[POC]" + text))
			}
			RestartSpinner(options)
		} else {
			if !options.Silence {
				if text != "HIDDENMESSAGE!!" {
					text = "\r" + text
					fmt.Fprintln(os.Stderr, text)
				}
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

// SetSpinner is set string to global spinner
func SetSpinner(str string, options model.Options) {
	if options.SpinnerObject != nil {
		options.SpinnerObject.Suffix = "  " + str
	}
}

// RestartSpinner is restart global spinner
func RestartSpinner(options model.Options) {
	if options.SpinnerObject != nil {
		options.SpinnerObject.Restart()
	}
}

// StopSpinner is stop global spinner
func StopSpinner(options model.Options) {
	if options.SpinnerObject != nil {
		options.SpinnerObject.Stop()
	}
}
