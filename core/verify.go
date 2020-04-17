package core

import (
	"io"

	"github.com/PuerkitoBio/goquery"
)

// VerifyDOM is check success inject on code
func VerifyDOM(body io.ReadCloser) bool {
	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(body)
	check := false
	if err != nil {
		return false
	}
	// Find the review items
	doc.Find("dalfox").Each(func(i int, s *goquery.Selection) {
		// For each item found, get the band and title
		check = true
	})
	if check {
		return true
	} else {
		doc.Find(".dalfox").Each(func(i int, s *goquery.Selection) {
			// For each item found, get the band and title
			check = true
		})
		if check {
			return true
		} else {
			return false
		}
	}
}
