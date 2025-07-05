package payload

import (
	"encoding/json"
	"io"
	"net/http"
)

// assetHahwulBaseURL is the base URL for assets.hahwul.com.
// It's a variable so it can be changed for testing.
var assetHahwulBaseURL = "https://assets.hahwul.com"

// Asset is type of Assets
type Asset struct {
	Line string
	Size string
}

// GetPortswiggerPayloadWithSize is exported interface
func GetPortswiggerPayloadWithSize() ([]string, int) {
	lst, _, _ := GetPortswiggerPayload()
	return lst, len(lst)
}

// GetPayloadBoxPayloadWithSize is exported interface
func GetPayloadBoxPayloadWithSize() ([]string, int) {
	lst, _, _ := GetPayloadBoxPayload()
	return lst, len(lst)
}

// getAssetHahwul is pull data and information for remote payloads
func getAssetHahwul(apiEndpoint, dataEndpoint string) ([]string, string, string) {
	apiLink := assetHahwulBaseURL + "/" + apiEndpoint
	dataLink := assetHahwulBaseURL + "/" + dataEndpoint

	// Get Info JSON
	// Use http.DefaultClient.Get instead of http.Get to make it easier to mock in tests if needed,
	// though changing assetHahwulBaseURL is the primary test strategy here.
	apiResp, err := http.DefaultClient.Get(apiLink)
	if err != nil || (apiResp != nil && apiResp.StatusCode != http.StatusOK) {
		var t []string
		if apiResp != nil {
			apiResp.Body.Close()
		}
		return t, "", ""
	}
	defer apiResp.Body.Close()

	var asset Asset
	infoJSON, err := io.ReadAll(apiResp.Body)
	if err != nil {
		// Error reading body, or body is empty, still try to proceed if json can be unmarshalled
		// but it's likely unmarshal will also fail or produce default struct.
		// However, primary check is for HTTP status. If status was OK but body is bad,
		// then json.Unmarshal will handle it by populating Asset with defaults.
	}
	json.Unmarshal(infoJSON, &asset) // if infoJSON is empty/corrupt, asset will have zero values

	// Get Payload Data
	dataResp, err := http.Get(dataLink)
	if err != nil || (dataResp != nil && dataResp.StatusCode != http.StatusOK) {
		var t []string
		if dataResp != nil {
			dataResp.Body.Close()
		}
		// Return asset.Line and asset.Size from API if that part was successful
		// but data fetch failed. Or, if API also failed, these would be "" anyway.
		// The requirement for tests is that if data fetch fails, all are empty.
		// So, if data fetch fails, we return all empty.
		return t, "", ""
	}
	defer dataResp.Body.Close()

	payloadData, err := io.ReadAll(dataResp.Body)
	if err != nil {
		var t []string
		// Similar to above, if ReadAll fails after a 200 OK, it's a problem.
		// Return all empty as per test expectations for data fetch failure.
		return t, "", ""
	}
	payload := splitLines(string(payloadData))

	return payload, asset.Line, asset.Size
}

// GetPayloadBoxPayload is use for remote payloads (PortSwigger Cheatsheet)
func GetPortswiggerPayload() ([]string, string, string) {
	apiEndpoint := "xss-portswigger.json"
	dataEndpoint := "xss-portswigger.txt"
	payload, line, size := getAssetHahwul(apiEndpoint, dataEndpoint)
	return payload, line, size
}

// GetPayloadBoxPayload is use for remote payloads (PayloadBox)
func GetPayloadBoxPayload() ([]string, string, string) {
	apiEndpoint := "xss-payloadbox.json"
	dataEndpoint := "xss-payloadbox.txt"
	payload, line, size := getAssetHahwul(apiEndpoint, dataEndpoint)
	return payload, line, size
}

// GetBurpWordlist is use for remote wordlist (BurpSuite's param-minior)
func GetBurpWordlist() ([]string, string, string) {
	apiEndpoint := "wl-params.json"
	dataEndpoint := "wl-params.txt"
	payload, line, size := getAssetHahwul(apiEndpoint, dataEndpoint)
	return payload, line, size
}

// GetAssetnoteWordlist is use for remote wordlist (assetnote)
func GetAssetnoteWordlist() ([]string, string, string) {
	apiEndpoint := "wl-assetnote-params.json"
	dataEndpoint := "wl-assetnote-params.txt"
	payload, line, size := getAssetHahwul(apiEndpoint, dataEndpoint)
	return payload, line, size
}
