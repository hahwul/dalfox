package printing

// Banner is DalFox banner function
func Banner() {
	DalLog("", `
    _..._
  .' .::::.   __   _   _    ___ _ __ __ 
 :  :::::::: |  \ / \ | |  | __/ \\ V / 
 :  :::::::: | o ) o || |_ | _( o )) (  
 '. '::::::' |__/|_n_||___||_| \_//_n_\                           
   '-.::''
`)
	DalLog("", "Parameter Analysis and XSS Scanning tool based on golang")
	DalLog("", "Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul")
	DalLog("", "\n")
}
