package optimization

import (
	"sort"
	"strings"
)

// Abstraction is abstract for optimization
func Abstraction(s, payload string) []string {
	var mapdata []string

	bodyarr := strings.Split(s, "\n")
	lineSize := 0
	mode := 1
	position := 1
	for _, text := range bodyarr {
		pointer := make(map[int]string)
		ptn := FindIndexesInLine(text, payload, lineSize, 0)
		doubleQuote := FindIndexesInLine(text, "\"", lineSize, 0)
		singleQuote := FindIndexesInLine(text, "'", lineSize, 0)
		backtick := FindIndexesInLine(text, "`", lineSize, 0)
		startTag := FindIndexesInLine(text, "<", lineSize, 0)
		endTag := FindIndexesInLine(text, ">", lineSize, 0)
		startScript := FindIndexesInLine(text, "<script", lineSize, 0)
		endScript := FindIndexesInLine(text, "</script", lineSize, 0)

		// script와 태그를 구별하기 위해 tag부터(덮어써지도록)
		setPointer(startTag, pointer, "tag-start")
		setPointer(endTag, pointer, "tag-end")
		setPointer(startScript, pointer, "script-start")
		setPointer(endScript, pointer, "script-end")
		setPointer(doubleQuote, pointer, "double")
		setPointer(singleQuote, pointer, "single")
		setPointer(backtick, pointer, "backtick")
		setPointer(ptn, pointer, payload)

		lineSize = lineSize + len(text)

		keys := make([]int, 0, len(pointer))
		for k := range pointer {
			keys = append(keys, k)
		}
		sort.Ints(keys)

		modeMap := make(map[int]string)
		positionMap := make(map[int]string)

		modeMap[1] = "inHTML"
		modeMap[2] = "inJS"
		modeMap[3] = "inATTR"
		modeMap[4] = "inTagScript"
		positionMap[1] = "none"
		positionMap[2] = "double"
		positionMap[3] = "single"
		positionMap[4] = "backtick"
		positionMap[5] = "comment"
		positionMap[6] = "pre"
		positionMap[7] = "textarea"

		// 1 none
		// 2 double
		// 3 single
		// 4 backtick
		// 5 comment
		// 6 pre
		// 7 textarea

		for _, k := range keys {
			if pointer[k] == "script-start" {
				if (mode == 1) || ((mode == 3) && (position == 1)) {
					mode = 4
				}
			}
			if pointer[k] == "script-end" {
				if (mode != 3) && (mode != 4) {
					mode = 1
				}
			}
			if pointer[k] == "tag-start" {
				if mode == 1 {
					mode = 3
				}
			}
			if pointer[k] == "tag-end" {
				if mode == 4 {
					mode = 2
				} else if mode == 3 || position == 1 {
					mode = 1
				}
			}
			if pointer[k] == "double" {
				if (mode == 2 || mode == 3) && position == 1 {
					position = 2
				} else if (mode == 2 || mode == 3) && position == 2 {
					position = 1
				}
			}
			if pointer[k] == "single" {
				if (mode == 2 || mode == 3) && position == 1 {
					position = 3
				} else if (mode == 2 || mode == 3) && position == 3 {
					position = 1
				}
			}
			if pointer[k] == "backtick" {
				if (mode == 2) && position == 1 {
					position = 4
				} else if (mode == 2) && position == 4 {
					position = 1
				}
			}
			if pointer[k] == payload {
				mapdata = append(mapdata, modeMap[mode]+"-"+positionMap[position])

			}
		}

	}
	//err := error
	return mapdata
}

// setPointer is settting pointer
func setPointer(arr []int, pointer map[int]string, key string) {
	if len(arr) > 0 {
		for k, v := range arr {
			_ = k
			pointer[v] = key
		}
	}
}

// FindIndexesInLine is check included key data in line
func FindIndexesInLine(text, key string, lineSize, pointing int) []int {
	var indexes []int
	pointer := strings.Index(text, key)
	if pointer != -1 {
		tempIndexes := FindIndexesInLine(text[pointer+1:], key, lineSize, pointer+pointing+1)
		indexes = append(indexes, pointer+lineSize+pointing)
		indexes = append(indexes, tempIndexes...)
	}
	return indexes
}
