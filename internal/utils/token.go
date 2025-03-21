package utils

import (
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"
)

// GenerateRandomToken is make scan id
func GenerateRandomToken(url string) string {
	now := time.Now()
	nanos := now.UnixNano()
	sum := sha256.Sum256([]byte(strconv.FormatInt(nanos, 10) + url))
	data := fmt.Sprintf("%x", string(sum[:]))
	return data
}
