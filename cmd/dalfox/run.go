package dalfox

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/hahwul/dalfox/pkg/printing"
	"github.com/hahwul/dalfox/pkg/scanning"
)

func Run() {
	var targets []string
	options_str := make(map[string]string)
	options_bool := make(map[string]bool)

	// input options
	url := flag.String("url", "", "target url")
	iL := flag.String("iL", "", "target urls(file path)")
	data := flag.String("data", "", "POST data")
	pipe := flag.Bool("pipe", false, "Pipeline mode (default is false)")
	header := flag.String("header", "", "Add custom headers")
	cookie := flag.String("cookie", "", "Add custom cookies")
	user_agent := flag.String("ua", "", "Add custom User-Agent")
	blind := flag.String("blind", "", "Add blind XSS payload, e.g -blind https://hahwul.xss.ht")
	customPayload := flag.String("pL", "", "Custom payload list(file path)")
	config := flag.String("config", "", "config file path")
	helphelp := flag.Bool("help", false, "Show help message")
	onlydiscovery := flag.Bool("only-discovery", false, "Use only discovery mode")
	p := flag.String("p", "", "Testing only selected parameter")
	// to options

	flag.Parse()
	if (flag.NFlag() == 0) || *helphelp {
		printing.Banner()
		flag.Usage()
		return
	}
	if *url != "" {
		targets = append(targets, *url)
		_ = data

	}
	if *iL != "" {
		ff, err := readLinesOrLiteral(*iL)
		_ = err
		for i, target := range ff {
			_ = i
			targets = append(targets, target)
		}
	}

	if *pipe {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			target := strings.ToLower(sc.Text())
			targets = append(targets, target)
		}
	}
	options_str["header"] = *header
	options_str["cookie"] = *cookie
	options_str["p"] = *p
	options_str["blind"] = *blind
	options_str["customPayload"] = *customPayload
	options_str["data"] = *data
	options_str["ua"] = *user_agent
	options_bool["only-discovery"] = *onlydiscovery

	if *config != "" {
		// Open our jsonFile
		jsonFile, err := os.Open(*config)
		// if we os.Open returns an error then handle it
		if err != nil {
			fmt.Println(err)
		}
		printing.DalLog("SYSTEM", "Using config options / loaded "+*config+" file")
		// defer the closing of our jsonFile so that we can parse it later on
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)

		var result map[string]interface{}
		json.Unmarshal([]byte(byteValue), &result)

		for k, v := range result {
			if k == "blind" || k == "p" || k == "cookie" || k == "header" || k == "ua" {
				options_str[k] = v.(string)
			}
			if k == "only-discovery" || k == "pipe" {
				options_bool[k] = v.(bool)
			}
		}
	}
	// Remove Deplicated value
	targets = unique(targets)
	printing.Banner()
	printing.DalLog("SYSTEM", "Loaded "+strconv.Itoa(len(targets))+" target urls")
	for i, _ := range targets {
		scanning.Scan(targets[i], options_str, options_bool)
	}
}
