package printing

import (
	spinner "github.com/briandowns/spinner"
)

// DrawSpinner is drawing spinner
func DrawSpinner(s *spinner.Spinner, t map[string]int, pointer int) {
	s.Suffix = "  Running..."
}
