package scanning

import (
	"context"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// CheckXSSWithHeadless is XSS Testing with headless browser
func CheckXSSWithHeadless(url string, options model.Options) bool {
	// create chrome instance
	check := false
	ctx, cancel := chromedp.NewContext(
		context.Background(),
		//chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	// create a timeout
	ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if ev, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			if string(ev.Message) == options.CustomAlertValue {
				check = true
				cancel()
			} else {
				go func() {
					chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
				}()
			}
		}
	})

	/*
		var headers map[string]interface{}


		if options.Header != "" {
			h := strings.Split(options.Header, ": ")
			if len(h) > 1 {
				headers[h[0]] = h[1]
			}
		}

		if options.Cookie != "" {
			headers["Cookie"] = options.Cookie
		}

		if options.UserAgent != "" {
			headers["User-Agent"] = options.UserAgent
		}
	*/

	/*
		var res string
		err := chromedp.Run(ctx, setheaders(
			url,
			headers,
			&res,
		))
	*/

	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		// wait for footer element is visible (ie, page is loaded)
		// chromedp.WaitVisible(`body > footer`),
	)
	if err != nil {
		//
	}
	return check
}

func setheaders(host string, headers map[string]interface{}, res *string) chromedp.Tasks {
	return chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(host),
	}
}
