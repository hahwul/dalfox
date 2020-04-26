package scanning

import (
	"os/exec"
	"strings"

	"github.com/hahwul/dalfox/pkg/printing"
)

// foundAction is after command function.
func foundAction(optionsStr map[string]string, target, query, ptype string) {
	tempCmd := strings.Fields(optionsStr["foundAction"])
	afterCmd := strings.Join(tempCmd[1:], " ")
	afterCmd = strings.ReplaceAll(afterCmd, "@@query@@", query)
	afterCmd = strings.ReplaceAll(afterCmd, "@@target@@", target)
	afterCmd = strings.ReplaceAll(afterCmd, "@@type@@", ptype)
	cmd := exec.Command(tempCmd[0], afterCmd)
	err := cmd.Start()
	if err != nil {
		printing.DalLog("ERROR", "execution error from found-action", optionsStr)
	}
}
