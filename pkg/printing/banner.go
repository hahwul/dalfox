package printing

// Banner is DalFox banner function
func Banner() {
	fake := make(map[string]string)
	DalLog("", `
    _..._
  .' .::::.   __   _   _    ___ _ __ __ 
 :  :::::::: |  \ / \ | |  | __/ \\ V / 
 :  :::::::: | o ) o || |_ | _( o )) (  
 '. '::::::' |__/|_n_||___||_| \_//_n_\                           
   '-.::''
`, fake)
	DalLog("", "Parameter Analysis and XSS Scanning tool based on golang", fake)
	DalLog("", "Finder Of XSS and Dal is the Korean pronunciation of moon. @hahwul", fake)
}
