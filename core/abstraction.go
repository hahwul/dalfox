package core

import (
	"bufio"
	"sort"
	"strings"
)

func Abstraction(s string) (lines []string, err error) {
	var mapdata []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())

		pointer := make(map[int]string)
		sstart := strings.Index(scanner.Text(), "<script")
		send := strings.Index(scanner.Text(), "</script")
		ptn := strings.Index(scanner.Text(), "DalFox")

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
	err = scanner.Err()
	return mapdata, err
}
