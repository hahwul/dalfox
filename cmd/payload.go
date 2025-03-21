package cmd

import (
	"strconv"

	"github.com/hahwul/dalfox/v2/internal/optimization"
	"github.com/hahwul/dalfox/v2/internal/payload"
	"github.com/hahwul/dalfox/v2/internal/printing"
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
	Run:   runPayloadCmd,
}

func runPayloadCmd(cmd *cobra.Command, args []string) {
	printing.Banner(options)
	objects := initializeObjects()
	for _, object := range objects {
		if object.Use {
			lst, s := object.Listener()
			printing.DalLog("INFO", "["+object.Name+"][Line: "+strconv.Itoa(s)+"]", options)
			plst := optimization.SetPayloadValue(lst, options)
			for _, v := range plst {
				if urlEncode {
					printing.DalLog("YELLOW", optimization.UrlEncode(v), options)
				} else {
					printing.DalLog("YELLOW", v, options)
				}
			}
		}
	}
}

func initializeObjects() []Object {
	return []Object{
		{Use: makeBulk, Name: "Bulk-XSS", Listener: payload.GenerateBulkPayload},
		{Use: enumCommon, Name: "Enum-Common-XSS", Listener: payload.GetCommonPayloadWithSize},
		{Use: enumHTML, Name: "Enum-HTML-XSS", Listener: payload.GetHTMLPayloadWithSize},
		{Use: enumAttr, Name: "Enum-Attribute-XSS", Listener: payload.GetAttrPayloadWithSize},
		{Use: enumInJS, Name: "Enum-inJS-XSS", Listener: payload.GetInJsPayloadWithSize},
		{Use: remotePayloadbox, Name: "Remote-Payloadbox-Payloads", Listener: payload.GetPayloadBoxPayloadWithSize},
		{Use: remotePortswigger, Name: "Remote-Portswigger-Paylaods", Listener: payload.GetPortswiggerPayloadWithSize},
		{Use: entityGF, Name: "Entity-GF-Patterns", Listener: payload.InterfaceGetGfXSS},
		{Use: entityEventHandler, Name: "Entity-Event-Handlers", Listener: payload.InterfaceGetEventHandlers},
		{Use: entityUsefulTags, Name: "Entity-Useful-Tags", Listener: payload.InterfaceGetTags},
		{Use: entitySpecialChars, Name: "Entity-Special-Chars", Listener: payload.InterfaceGetSpecialChar},
	}
}

func init() {
	rootCmd.AddCommand(payloadCmd)
	payloadCmd.Flags().BoolVar(&makeBulk, "make-bulk", false, "Generate bulk payloads for stored XSS. Example: --make-bulk")
	payloadCmd.Flags().BoolVar(&enumCommon, "enum-common", false, "Enumerate common XSS payloads. Example: --enum-common")
	payloadCmd.Flags().BoolVar(&enumHTML, "enum-html", false, "Enumerate in-HTML XSS payloads. Example: --enum-html")
	payloadCmd.Flags().BoolVar(&enumAttr, "enum-attr", false, "Enumerate in-attribute XSS payloads. Example: --enum-attr")
	payloadCmd.Flags().BoolVar(&enumInJS, "enum-injs", false, "Enumerate in-JavaScript XSS payloads. Example: --enum-injs")
	payloadCmd.Flags().BoolVar(&remotePayloadbox, "remote-payloadbox", false, "Enumerate payloads from Payloadbox's XSS payloads. Example: --remote-payloadbox")
	payloadCmd.Flags().BoolVar(&remotePortswigger, "remote-portswigger", false, "Enumerate payloads from PortSwigger's XSS cheatsheet. Example: --remote-portswigger")
	payloadCmd.Flags().BoolVar(&entityGF, "entity-gf", false, "Enumerate parameters from GF-Patterns for XSS. Example: --entity-gf")
	payloadCmd.Flags().BoolVar(&entityEventHandler, "entity-event-handler", false, "Enumerate event handlers for XSS. Example: --entity-event-handler")
	payloadCmd.Flags().BoolVar(&entityUsefulTags, "entity-useful-tags", false, "Enumerate useful tags for XSS. Example: --entity-useful-tags")
	payloadCmd.Flags().BoolVar(&entitySpecialChars, "entity-special-chars", false, "Enumerate special characters for XSS. Example: --entity-special-chars")
	payloadCmd.Flags().BoolVar(&urlEncode, "encoder-url", false, "Encode output as URL. Example: --encoder-url")
}
