package har

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Writer represents a single HAR archive. Writer is
// safe for concurrent use by multiple goroutines. It contains
// an internal mutex to serialize writes to the underlying writer.
type Writer struct {
	first  bool
	closed bool
	mut    sync.Mutex
	writer io.Writer
}

// NewWriter creates a new writer ready for usage by RoundTripper. It
// returns an error if it is unable to write the start of the HAR file.
func NewWriter(writer io.Writer, creator *Creator) (*Writer, error) {
	var err error
	creatorJSON, _ := json.Marshal(creator)

	_, err = writer.Write([]byte(`{"log":{"version":"1.2","creator":`))
	if err != nil {
		return nil, fmt.Errorf("writing preamble: %w", err)
	}

	_, err = writer.Write(creatorJSON)
	if err != nil {
		return nil, fmt.Errorf("writing preamble: %w", err)
	}

	_, err = writer.Write([]byte(`,"entries":[` + "\n"))
	if err != nil {
		return nil, fmt.Errorf("writing preamble: %w", err)
	}

	return &Writer{
		first:  true,
		writer: writer,
	}, nil
}

func (w *Writer) writeEntry(entry json.RawMessage) error {
	w.mut.Lock()
	defer w.mut.Unlock()

	if w.closed {
		return fmt.Errorf("HarWriter already closed")
	}

	if !w.first {
		_, err := w.writer.Write([]byte(",\n"))
		if err != nil {
			return fmt.Errorf("writing har entry: %w", err)
		}
	}

	w.first = false

	_, err := w.writer.Write(entry)
	if err != nil {
		return fmt.Errorf("writing har entry: %w", err)
	}

	return nil
}

// Close finalizes the JSON written to the underlying writer.
// Close must be called to ensure the HAR file is valid. Writer
// must not be used after Close is called.
func (w *Writer) Close() error {
	w.mut.Lock()
	defer w.mut.Unlock()

	if w.closed {
		return fmt.Errorf("HarWriter already closed")
	}

	w.closed = true
	_, err := w.writer.Write([]byte("\n]}}"))
	if err != nil {
		return fmt.Errorf("closing har writer: %w", err)
	}

	return nil
}
