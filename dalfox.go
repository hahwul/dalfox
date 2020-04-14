package main

import (
	"bufio"
	"flag"
	"os"
	"strings"

	"github.com/hahwul/dalfox/core"
	"github.com/projectdiscovery/gologger"
)

func main() {
	var targets []string
	options_str := make(map[string]string)
	options_bool := make(map[string]bool)

	// input options
	url := flag.String("url", "", "target url")
	iL := flag.String("iL", "", "target urls(file)")
	data := flag.String("data", "", "POST data")
	pipe := flag.Bool("pipe", false, "Pipeline mode (default is false)")
	header := flag.String("header", "", "Add custom headers")
	cookie := flag.String("cookie", "", "Add custom cookies")
	user_agent := flag.String("user-agent", "", "Add custom UA")
	blind := flag.String("blind", "", "Add blind XSS payload, e.g -blind https://hahwul.xss.ht")
	helphelp := flag.Bool("help", false, "Show help message")
	onlydiscovery := flag.Bool("only-discovery", false, "Use only discovery mode")
	p := flag.String("p", "", "Testing only selected parameter")
	// to options

	flag.Parse()
	if (flag.NFlag() == 0) || *helphelp {
		core.Banner()
		flag.Usage()
		return
	}
	if *url != "" {
		targets = append(targets, *url)
		_ = data

	}
	if *iL != "" {
		ff, err := readLinesOrLiteral(*iL)
		_ = err
		for i, target := range ff {
			_ = i
			targets = append(targets, target)
		}
	}

	if *pipe {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.ToLower(sc.Text())
			targets = append(targets, target)
		}
	}
	options_str["header"] = *header
	options_str["cookie"] = *cookie
	options_str["p"] = *p
	options_str["blind"] = *blind
	options_str["ua"] = *user_agent
	options_bool["only-discovery"] = *onlydiscovery
	// Remove Deplicated value
	targets = unique(targets)
	core.Banner()
	gologger.Infof("Loaded %d target urls", len(targets))
	for i, _ := range targets {
		core.Scan(targets[i], options_str, options_bool)
	}
}

// a slice of strings, returning the slice and any error
func readLines(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{}, err
	}
	defer f.Close()

	lines := make([]string, 0)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}

	return lines, sc.Err()
}

// readLinesOrLiteral tries to read lines from a file, returning
// the arg in a string slice if the file doesn't exist, unless
// the arg matches its default value
func readLinesOrLiteral(arg string) ([]string, error) {
	if isFile(arg) {
		return readLines(arg)
	}

	// if the argument isn't a file, but it is the default, don't
	// treat it as a literal value

	return []string{arg}, nil
}

// isFile returns true if its argument is a regular file
func isFile(path string) bool {
	f, err := os.Stat(path)
	return err == nil && f.Mode().IsRegular()
}

func unique(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
