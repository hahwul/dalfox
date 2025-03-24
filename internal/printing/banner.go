package printing

import "github.com/hahwul/dalfox/v2/pkg/model"

// Banner is Dalfox banner function
func Banner(options model.Options) {
	DalLog("", `                                                        
               ░█▒               
             ████     ▓                    
           ▓█████  ▓██▓                  
          ████████████         ░          
        ░███████████▓          ▓░     
     ░████████████████        ▒██░    
    ▓██████████▒███████     ░█████▓░    
   ██████████████░ ████        █▓     
 ░█████▓          ░████▒       ░         Dalfox `+VERSION+`
 █████               ▓██░             
 ████                  ▓██      Powerful open-source XSS scanner       
 ███▓        ▓███████▓▒▓█░     and utility focused on automation.       
 ███▒      █████                     
 ▓███     ██████                    
 ████     ██████▒                
 ░████    ████████▒
 `, options)
}
