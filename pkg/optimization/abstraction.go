package optimization

import (
	"sort"
	"strings"
)

// Abstraction is abstract for optimization
func Abstraction(s string) []string {
	var mapdata []string

	bodyarr := strings.Split(s, "\n")

	for _, text := range bodyarr {

		//	scanner := bufio.NewScanner(strings.NewReader(s))
		//	for scanner.Scan() {
		//		text := scanner.Text()
		//	lines = append(lines, text)

		pointer := make(map[int]string)
		sstart := strings.Index(text, "<script")
		send := strings.Index(text, "</script")
		ptn := strings.Index(text, "DalFox")
		if sstart != -1 {
			pointer[sstart] = "script-start"
		}
		if send != -1 {
			pointer[send] = "script-end"
		}
		if ptn != -1 {
			pointer[ptn] = "DalFox"
		}

		keys := make([]int, 0, len(pointer))
		for k := range pointer {
			keys = append(keys, k)
		}
		sort.Ints(keys)

		//0 : hmtml , 1: injs
		mode := 0
		for _, k := range keys {
			if pointer[k] == "script-start" {
				mode = 1
			}
			if pointer[k] == "script-end" {
				mode = 0
			}
			if pointer[k] == "DalFox" {
				if mode == 0 {
					mapdata = append(mapdata, "inHTML")
				} else {
					mapdata = append(mapdata, "inJS")
				}
			}
		}

	}
	//err := error
	return mapdata
}
