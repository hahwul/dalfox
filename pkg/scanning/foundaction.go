package scanning

import (
	"os/exec"
	"strings"

	"github.com/hahwul/dalfox/pkg/printing"
)

// foundAction is after command function.
func foundAction(optionsStr map[string]string) {
	tempCmd := strings.Fields(optionsStr["found-action"])
	cmd := exec.Command(tempCmd[0], strings.Join(tempCmd[1:], " "))
	err := cmd.Start()
	if err != nil {
		printing.DalLog("ERROR", "execution error from found-action", optionsStr)
	}
}
