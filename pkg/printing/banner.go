package printing

import "github.com/hahwul/dalfox/v2/pkg/model"

// Banner is DalFox banner function
func Banner(options model.Options) {
	DalLog("", `
    _..._
  .' .::::.   __   _   _    ___ _ __ __
 :  :::::::: |  \ / \ | |  | __/ \\ V /
 :  :::::::: | o ) o || |_ | _( o )) (
 '. '::::::' |__/|_n_||___||_| \_//_n_\
   '-.::''    
`, options)
	DalLog("", "🌙🦊 Powerful open source XSS scanning tool and parameter analyzer, utility", options)
}
