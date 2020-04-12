package core

import (
	"github.com/projectdiscovery/gologger"
)

// Banner is DalFox banner function
func Banner() {
	gologger.Printf(`
    _..._
  .' .::::.   __   _   _    ___ _ __ __ 
 :  :::::::: |  \ / \ | |  | __/ \\ V / 
 :  :::::::: | o ) o || |_ | _( o )) (  
 '. '::::::' |__/|_n_||___||_| \_//_n_\                           
   '-.::''
`)
	gologger.Printf("Parameter Analysis and XSS Scanning tool based on golang\n")
	gologger.Printf("Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul\n")
	gologger.Printf("\n")
}
