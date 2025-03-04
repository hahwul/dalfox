package scanning

import (
	"context"
	"log"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

var chromeCtx context.Context
var chromeCancel context.CancelFunc

func init() {
	chromeCtx, chromeCancel = chromedp.NewContext(context.Background())
	if chromeCtx == nil {
		log.Println("Failed to create chrome context")
	}
}

// CheckXSSWithHeadless is XSS Testing with headless browser
func CheckXSSWithHeadless(url string, options model.Options) bool {
	check := false
	ctx, cancel := context.WithTimeout(chromeCtx, 8*time.Second)
	defer cancel()

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		if ev, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			if string(ev.Message) == options.CustomAlertValue {
				check = true
				cancel()
			} else {
				chromedp.Run(ctx, page.HandleJavaScriptDialog(true))
			}
		}
	})

	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
	)
	if err != nil {
		// handle error
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
