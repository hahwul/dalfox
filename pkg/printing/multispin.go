package printing

import (
	spinner "github.com/briandowns/spinner"
)

func DrawSpinner(s *spinner.Spinner, t map[string]int, pointer int) {
	s.Suffix = "  Running..."
}
