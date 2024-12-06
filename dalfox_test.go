/*
Code by @hahwul
Happy hacking :D
*/
package main

import (
	"bytes"
	"os"
	"testing"
)

func Test_main(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "Test case 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Redirect stdout to capture output
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Call the main function
			main()

			// Capture the output
			w.Close()
			var buf bytes.Buffer
			buf.ReadFrom(r)
			os.Stdout = old

			// Check the output
			got := buf.String()
			if len(got) > 0 {
				t.Errorf("main() = %v, want %v", got, nil)
			}
		})
	}
}
