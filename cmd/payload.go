package cmd

import (
	"strconv"

	"github.com/hahwul/dalfox/v2/pkg/generating"
	"github.com/hahwul/dalfox/v2/pkg/optimization"
	"github.com/hahwul/dalfox/v2/pkg/printing"
	"github.com/hahwul/dalfox/v2/pkg/scanning"
	"github.com/spf13/cobra"
)

var makeBulk bool
var enumCommon, enumHTML, enumAttr, enumInJS bool
var remotePayloadbox, remotePortswigger bool
var entityGF, entityEventHandler, entityUsefulTags, entitySpecialChars bool
var urlEncode bool

// Object is Type of PayloadObject
type Object struct {
	Use      bool
	Name     string
	Listener func() ([]string, int)
}

// payloadCmd represents the payload command
var payloadCmd = &cobra.Command{
	Use:   "payload",
	Short: "Payload mode, make and enum payloads",
	Run: func(cmd *cobra.Command, args []string) {
		printing.Banner(options)
		var objects []Object
		objects = append(objects, Object{Use: makeBulk, Name: "Bulk-XSS", Listener: generating.GenerateBulkPayload})
		objects = append(objects, Object{Use: enumCommon, Name: "Enum-Common-XSS", Listener: scanning.GetCommonPayload})
		objects = append(objects, Object{Use: enumHTML, Name: "Enum-HTML-XSS", Listener: scanning.GetHTMLPayload})
		objects = append(objects, Object{Use: enumAttr, Name: "Enum-Attribute-XSS", Listener: scanning.GetAttrPayload})
		objects = append(objects, Object{Use: enumInJS, Name: "Enum-inJS-XSS", Listener: scanning.GetInJsPayload})
		objects = append(objects, Object{Use: remotePayloadbox, Name: "Remote-Payloadbox-Payloads", Listener: scanning.GetPayloadBoxPayload})
		objects = append(objects, Object{Use: remotePortswigger, Name: "Remote-Portswigger-Paylaods", Listener: scanning.GetPortswiggerPayload})
		objects = append(objects, Object{Use: entityGF, Name: "Entity-GF-Patterns", Listener: scanning.InterfaceGetGfXSS})
		objects = append(objects, Object{Use: entityEventHandler, Name: "Entity-Event-Handlers", Listener: scanning.InterfaceGetEventHandlers})
		objects = append(objects, Object{Use: entityUsefulTags, Name: "Entity-Useful-Tags", Listener: scanning.InterfaceGetTags})
		objects = append(objects, Object{Use: entitySpecialChars, Name: "Entity-Special-Chars", Listener: scanning.InterfaceGetSpecialChar})

		for _, object := range objects {
			if object.Use {
				lst, s := object.Listener()
				printing.DalLog("INFO", "["+object.Name+"][Line: "+strconv.Itoa(s)+"]", options)
				plst := optimization.SetPayloadValue(lst, options)
				for i, v := range plst {
					_ = i
					if urlEncode {
						printing.DalLog("YELLOW", optimization.UrlEncode(v), options)
					} else {
						printing.DalLog("YELLOW", v, options)
					}
				}
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(payloadCmd)
	payloadCmd.Flags().BoolVar(&makeBulk, "make-bulk", false, "Make bulk payloads for stored xss")
	payloadCmd.Flags().BoolVar(&enumCommon, "enum-common", false, "Enumerate a common xss payloads")
	payloadCmd.Flags().BoolVar(&enumHTML, "enum-html", false, "Enumerate a in-html xss payloads")
	payloadCmd.Flags().BoolVar(&enumAttr, "enum-attr", false, "Enumerate a in-attr xss payloads")
	payloadCmd.Flags().BoolVar(&enumInJS, "enum-injs", false, "Enumerate a in-js xss payloads")
	payloadCmd.Flags().BoolVar(&remotePayloadbox, "remote-payloadbox", false, "Enumerate a payloadbox's xss payloads")
	payloadCmd.Flags().BoolVar(&remotePortswigger, "remote-portswigger", false, "Enumerate a portswigger xss cheatsheet payloads")
	payloadCmd.Flags().BoolVar(&entityGF, "entity-gf", false, "Enumerate a gf-patterns xss params")
	payloadCmd.Flags().BoolVar(&entityEventHandler, "entity-event-handler", false, "Enumerate a event handlers for xss")
	payloadCmd.Flags().BoolVar(&entityUsefulTags, "entity-useful-tags", false, "Enumerate a useful tags for xss")
	payloadCmd.Flags().BoolVar(&entitySpecialChars, "entity-special-chars", false, "Enumerate a special chars for xss")

	payloadCmd.Flags().BoolVar(&urlEncode, "encoder-url", false, "Encoding output [URL]")
}
