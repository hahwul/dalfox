package verification

import (
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// VerifyReflection is check reflected xss pattern
func VerifyReflection(body, payload string) bool {
	if strings.Contains(body, payload) {
		return true
	} else {
		return false
	}
}

// VerifyDOM is check success inject on code
func VerifyDOM(s string) bool { //(body io.ReadCloser) bool {

	body := ioutil.NopCloser(strings.NewReader(s)) // r type is io.ReadCloser
	defer body.Close()

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(body)
	check := false
	if err != nil {
		fmt.Println(err)
		return false
	}
	// Find the review items
	doc.Find(".dalfox").Each(func(i int, s *goquery.Selection) {
		check = true
	})
	if !check {
		doc.Find("dalfox").Each(func(i int, s *goquery.Selection) {
			// For each item found, get the band and title
			check = true
		})
	}
	return check
}
