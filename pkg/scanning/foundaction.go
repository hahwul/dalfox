package scanning

import (
	"os/exec"
	"strings"

	"github.com/hahwul/dalfox/pkg/model"
	"github.com/hahwul/dalfox/pkg/printing"
)

// foundAction is after command function.
func foundAction(options model.Options, target, query, ptype string) {
	afterCmd := options.FoundAction
	// afterCmd := strings.Join(tempCmd[:], " ")
	afterCmd = strings.ReplaceAll(afterCmd, "@@query@@", query)
	afterCmd = strings.ReplaceAll(afterCmd, "@@target@@", target)
	afterCmd = strings.ReplaceAll(afterCmd, "@@type@@", ptype)
	cmd := exec.Command("bash", "-c", afterCmd)
	err := cmd.Start()
	if err != nil {
		printing.DalLog("ERROR", "execution error from found-action", options)
	}
}
