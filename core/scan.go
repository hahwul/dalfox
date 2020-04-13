package core

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/projectdiscovery/gologger"
)

// Scan is main scanning function
func Scan(target string, options_string map[string]string, options_bool map[string]bool) {
	gologger.Infof("Target URL: %s", target)
	//var params []string

	// params is "param name":true  (reflected?)
	// 1: non-reflected , 2: reflected , 3: reflected-with-sc
	params := make(map[string][]string)

	// policy is "CSP":domain..
	policy := make(map[string]string)
	_ = params
	_ = policy
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		gologger.Infof("start static analysis..")
		policy = StaticAnalysis(target, options_string)
	}()
	go func() {
		defer wait.Done()
		gologger.Infof("start parameter analysis..")
		params = ParameterAnalysis(target, options_string)
	}()
	s := spinner.New(spinner.CharSets[7], 100*time.Millisecond) // Build our new spinner
	s.Suffix = " Waiting routines.."
	time.Sleep(1 * time.Second) // Waiting log
	s.Start()                   // Start the spinner
	time.Sleep(3 * time.Second) // Run for some time to simulate work
	wait.Wait()
	s.Stop()
	for k, v := range policy {
		if len(v) != 0 {
			fmt.Printf("- @INFO %s is %s\n", k, v)
		}
	}

	for k, v := range params {
		if len(v) != 0 {
			char := ""
			for _, c := range v {
				char = char + c
			}
			fmt.Printf("- @INFO Reflected %s param => %s\n", k, char)
		}
	}

	// XSS Scanning
	task := 1
	var wg sync.WaitGroup
	wg.Add(task)
	go func() {
		defer wg.Done()
	}()

	wg.Wait()
}

// StaticAnalysis is found information on original req/res
func StaticAnalysis(target string, options_string map[string]string) map[string]string {
	policy := make(map[string]string)
	resbody, resp := SendReq(target, options_string)
	//gologger.Verbosef("<INFO>"+resp.Status, "asdf")
	//fmt.Println(resp.Header)
	_ = resbody
	if resp.Header["Content-Type"] != nil {
		policy["Content-Type"] = resp.Header["Content-Type"][0]
	}
	if resp.Header["Content-Security-Policy"] != nil {
		policy["Content-Security-Policy"] = resp.Header["Content-Security-Policy"][0]
	}

	return policy
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(target string, options_string map[string]string) map[string][]string {
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		panic(err)
	}
	p, _ := url.ParseQuery(u.RawQuery)
	for k, v := range p {
		//temp_url := u
		//temp_q := u.Query()
		//temp_q.Set(k, v[0]+"DalFox")

		data := u.String()
		data = strings.Replace(data, k+"="+v[0], k+"="+v[0]+"DalFox", 1)
		temp_url, _ := url.Parse(data)
		temp_q := temp_url.Query()
		temp_url.RawQuery = temp_q.Encode()

		//temp_url.RawQuery = temp_q.Encode()
		resbody, resp := SendReq(temp_url.String(), options_string)
		_ = resp
		if strings.Contains(resbody, "DalFox") {
			params[k] = append(params[k], "string")
		}

		var wg sync.WaitGroup
		chars := GetSpecialChar()
		for _, char := range chars {
			wg.Add(1)
			tdata := u.String()
			tdata = strings.Replace(tdata, k+"="+v[0], k+"="+v[0]+char, 1)
			turl, _ := url.Parse(tdata)
			tq := turl.Query()
			turl.RawQuery = tq.Encode()
			/* turl := u
			q := u.Query()
			q.Set(k, v[0]+"DalFox"+string(char))
			turl.RawQuery = q.Encode()
			*/

			go func() {
				defer wg.Done()
				resbody, resp := SendReq(turl.String(), options_string)
				_ = resp
				if strings.Contains(resbody, "DalFox"+string(char)) {
					params[k] = append(params[k], string(char))
				}
			}()
		}
		wg.Wait()
	}
	return params
}

// ScanXSS is testing XSS
func ScanXSS() {
	// 위 데이터 기반으로 query 생성 후 fetch
}

// SendReq is sending http request (handled GET/POST)
func SendReq(url string, options_string map[string]string) (string, *http.Response) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}

	req.Header.Add("User-Agent", "Crawler")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bytes, _ := ioutil.ReadAll(resp.Body)
	str := string(bytes)
	return str, resp
}
