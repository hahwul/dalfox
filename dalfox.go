package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/hahwul/dalfox/core"
)

func main() {
	// input options
	url := flag.String("url", "", "target url")
	iL := flag.String("iL", "", "target urls(file)")
	data := flag.String("data", "", "POST data")
	// to options
	var targets []string
	flag.Parse()
	if flag.NFlag() == 0 {
		core.Banner()
		flag.Usage()
		return
	}
	if *url != "" {
		targets = append(targets, *url)
		_ = data

	}
	if *iL == "" {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.ToLower(sc.Text())
			targets = append(targets, target)
		}
	} else {
		ff, err := readLinesOrLiteral(*iL)
		_ = err
		for i, target := range ff {
			_ = i
			targets = append(targets, target)
		}

	}
	// Remove Deplicated value
	targets = unique(targets)
	//fmt.Println(targets)
	for i, _ := range targets {
		core.Scan(targets[i])
		fmt.Println(core.GetEventHandlers())
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
