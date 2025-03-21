package har_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/hahwul/dalfox/v2/internal/har"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/sjson"
	"golang.org/x/sync/errgroup"
)

type Test struct {
	Name string
}

var creator = &har.Creator{Name: "dalfox tests", Version: "0.0"}

func TestSingleRequest(t *testing.T) {
	buf := &bytes.Buffer{}

	hw, err := har.NewWriter(buf, creator)
	require.NoError(t, err)

	rt := har.NewRoundTripper(nil, hw, nil)
	c := &http.Client{Transport: rt}

	resp, err := c.Get("https://www.hahwul.com")
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)

	err = hw.Close()
	require.NoError(t, err)

	assert.True(t, json.Valid(buf.Bytes()), "HAR file is not valid json")
}

func TestMultipleRequests(t *testing.T) {
	buf := &bytes.Buffer{}

	hw, err := har.NewWriter(buf, creator)
	require.NoError(t, err)

	rt := har.NewRoundTripper(nil, hw, nil)
	c := &http.Client{Transport: rt}

	g, _ := errgroup.WithContext(context.Background())
	for idx := 0; idx < 5; idx++ {
		g.Go(func() error {
			resp, err := c.Get("https://www.hahwul.com")
			require.NoError(t, err)
			assert.NotNil(t, resp)
			assert.Equal(t, 200, resp.StatusCode)
			return nil
		})
	}

	err = g.Wait()
	require.NoError(t, err)

	err = hw.Close()
	require.NoError(t, err)

	harfile := har.File{}
	err = json.Unmarshal(buf.Bytes(), &harfile)
	require.NoError(t, err)

	assert.Len(t, harfile.Log.Entries, 5)
}

func TestRewrite(t *testing.T) {
	buf := &bytes.Buffer{}
	ctx := context.Background()

	hw, err := har.NewWriter(buf, creator)
	require.NoError(t, err)

	rt := har.NewRoundTripper(nil, hw, func(request *http.Request, response *http.Response, entry json.RawMessage) json.RawMessage {
		messageID := har.MessageIDFromRequest(request)
		entry, _ = sjson.SetBytes(entry, "_messageId", messageID)
		return entry
	})
	require.NoError(t, err)

	c := &http.Client{Transport: rt}

	req, _ := http.NewRequestWithContext(ctx, "GET", "https://www.hahwul.com", nil)
	req = har.AddMessageIDToRequest(req)
	firstMessageID := har.MessageIDFromRequest(req)

	resp, err := c.Do(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	req, _ = http.NewRequestWithContext(ctx, "GET", "https://www.hahwul.com/?a=b&c=d", nil)
	req = har.AddMessageIDToRequest(req)
	secondMessageID := har.MessageIDFromRequest(req)

	resp, err = c.Do(req)
	require.NoError(t, err)
	assert.NotNil(t, resp)

	err = hw.Close()
	require.NoError(t, err)

	// assert valid HAR files
	harfile := har.File{}
	err = json.Unmarshal(buf.Bytes(), &harfile)
	require.NoError(t, err)

	anything := map[string]interface{}{}
	err = json.Unmarshal(buf.Bytes(), &anything)
	require.NoError(t, err)

	entries := anything["log"].(map[string]interface{})["entries"].([]interface{})
	assert.Len(t, entries, 2)

	assert.EqualValues(t, firstMessageID, entries[0].(map[string]interface{})["_messageId"])
	assert.EqualValues(t, secondMessageID, entries[1].(map[string]interface{})["_messageId"])
}

func TestSinglePostJSONRequest(t *testing.T) {
	// 로컬 서버 생성
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"success"}`))
	}))
	defer server.Close()

	buf := &bytes.Buffer{}

	hw, err := har.NewWriter(buf, creator)
	require.NoError(t, err)

	rt := har.NewRoundTripper(nil, hw, nil)
	c := &http.Client{Transport: rt}

	person := Test{"apple"}
	pbytes, _ := json.Marshal(person)
	buff := bytes.NewBuffer(pbytes)

	resp, err := c.Post(server.URL, "application/json", buff)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = hw.Close()
	require.NoError(t, err)

	assert.True(t, json.Valid(buf.Bytes()), "HAR file is not valid json")
}

func TestSinglePostFormRequest(t *testing.T) {
	// 로컬 서버 생성
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`status=success`))
	}))
	defer server.Close()

	buf := &bytes.Buffer{}

	hw, err := har.NewWriter(buf, creator)
	require.NoError(t, err)

	rt := har.NewRoundTripper(nil, hw, nil)
	c := &http.Client{Transport: rt}

	resp, err := c.PostForm(server.URL, url.Values{"Name": {"Apple"}})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	err = hw.Close()
	require.NoError(t, err)

	assert.True(t, json.Valid(buf.Bytes()), "HAR file is not valid json")
}
