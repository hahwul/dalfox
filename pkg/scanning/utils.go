package scanning

import (
	"bufio"
	"os"
	"strings"

	"github.com/hahwul/dalfox/v2/pkg/model"
)

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

// unique is ..
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

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 //not found.
}

func duplicatedResult(result []model.PoC, rst model.PoC) bool {
	for _, v := range result {
		if v.Type == rst.Type {
			return true
		}
	}
	return false
}

func containsFromArray(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	t := strings.Split(item, "(")
	i := t[0]
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[i]
	return ok
}

func checkPType(str string) bool {
	if strings.Contains(str, "toBlind") {
		return false
	}
	if strings.Contains(str, "toGrepping") {
		return false
	}
	return true
}
