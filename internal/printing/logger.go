package printing

import (
	"fmt"
	"os"
	"strconv"
	"sync"

	"github.com/hahwul/dalfox/v2/internal/utils"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

func boolToColorStr(b bool, options model.Options) string {
	str := ""
	if options.AuroraObject == nil {
		return strconv.FormatBool(b)
	}

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

		targetStr := target
		methodStr := options.Method
		listenAddrStr := options.ServerHost + ":" + strconv.Itoa(options.ServerPort)
		blindURLStr := options.BlindURL

		if options.AuroraObject != nil {
			targetStr = options.AuroraObject.BrightYellow(target).String()
			methodStr = options.AuroraObject.BrightBlue(options.Method).String()
			listenAddrStr = options.AuroraObject.BrightBlue(listenAddrStr).String()
			blindURLStr = options.AuroraObject.BrightBlue(options.BlindURL).String()
		}

		fmt.Fprintf(os.Stderr, " 🎯  Target                 %s\n", targetStr)
		if target == "REST API Mode" {
			fmt.Fprintf(os.Stderr, " 🧲  Listen Address         %s\n", listenAddrStr)
		}
		fmt.Fprintf(os.Stderr, " 🏁  Method                 %s\n", methodStr)
		fmt.Fprintf(os.Stderr, " 🖥   Performance            %d worker / %d cpu\n", options.Concurrence, options.MaxCPU)
		fmt.Fprintf(os.Stderr, " ⛏   Mining                 %s (%s%s)\n", boolToColorStr(options.Mining, options), miningWord,
			func() string {
				if options.FindingDOM {
					return ", DOM Mining Enabled"
				}
				return ""
			}())
		if options.BlindURL != "" {
			fmt.Fprintf(os.Stderr, " 🛰   Blind XSS Callback     %s\n", blindURLStr)
		}
		fmt.Fprintf(os.Stderr, " ⏱   Timeout                %d\n", options.Timeout)
		fmt.Fprintf(os.Stderr, " 📤  FollowRedirect         %s\n", boolToColorStr(options.FollowRedirect, options))
		fmt.Fprintf(os.Stderr, " 🕰   Started at             %s\n", options.StartTime.Format("2006-01-02 15:04:05"))
		fmt.Fprintf(os.Stderr, "\n")
		DalLog("SYSTEM-M", utils.GenerateTerminalWidthLine("-"), options)
	}
}

// DalLog is log fomatting for Dalfox
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
			if options.AuroraObject != nil {
				text = options.AuroraObject.BrightBlue("[DEBUG] ").String() + text
			} else {
				text = "[DEBUG] " + text
			}
		} else {
			return
		}

	case "INFO":
		if allWrite {
			ftext = "[I] " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.BrightBlue("[I] ").String() + text
		} else {
			text = "[I] " + text
		}

	case "WEAK":
		if allWrite {
			ftext = "[W] " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.Yellow("[W] ").String() + text
		} else {
			text = "[W] " + text
		}

	case "VULN":
		if allWrite {
			ftext = "[V] " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.BrightRed("[V] ").String() + text
		} else {
			text = "[V] " + text
		}

	case "SYSTEM":
		if allWrite {
			ftext = "[*] " + text
		}
		if options.NoSpinner {
			if options.AuroraObject != nil {
				text = options.AuroraObject.White("[*] ").String() + text
			} else {
				text = "[*] " + text
			}
		} else if !(options.Silence || options.NoSpinner) {
			SetSpinner(text, options)
			text = "HIDDENMESSAGE!!"
		}

	case "SYSTEM-M":
		if allWrite {
			ftext = "[*] " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.White("[*] ").String() + text
		} else {
			text = "[*] " + text
		}
		if options.Silence && options.MulticastMode {
			StopSpinner(options)
			fmt.Fprintln(os.Stderr, text)
			RestartSpinner(options)
		}

	case "GREP":
		if allWrite {
			ftext = "[G] " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.Green("[G] ").String() + text
		} else {
			text = "[G] " + text
		}
	case "CODE":
		if text == "" {
			return
		}
		if allWrite {
			ftext = "    " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.Gray(16-1, "    "+text).String()
		} else {
			text = "    " + text
		}
	case "ERROR":
		if allWrite {
			ftext = "[E] " + text
		}
		if options.AuroraObject != nil {
			text = options.AuroraObject.Yellow("[E] ").String() + text
		} else {
			text = "[E] " + text
		}

	case "YELLOW":
		if options.AuroraObject != nil {
			text = options.AuroraObject.BrightYellow(text).String()
		}
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
				if options.AuroraObject != nil {
					fmt.Println(options.AuroraObject.BrightMagenta("[POC]" + text))
				} else {
					fmt.Println("[POC]" + text)
				}
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
