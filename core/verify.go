package core

import (
	"github.com/PuerkitoBio/goquery"
	"io"
)

// VerifyDOM is check success inject on code
func VerifyDOM(body io.ReadCloser, pattern string) bool {
	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(body)
	check := false
	if err != nil {
		return false
	}
	// Find the review items
	doc.Find(pattern).Each(func(i int, s *goquery.Selection) {
		// For each item found, get the band and title
		check = true
	})
	if check {
		return true
	} else {
		return false
	}
}
