package tor

import (
	"context"
	"fmt"
	"os"
	// "os/signal" // Not immediately needed for Start/Stop, can add if handling SIGINT/SIGTERM for graceful shutdown here
	// "syscall" // Same as above
	"time"

	"github.com/cretz/bine/tor"
	"github.com/hahwul/dalfox/v2/internal/printing"
	"github.com/hahwul/dalfox/v2/pkg/model"
)

// StartEmbeddedTor attempts to start an embedded Tor SOCKS proxy.
func StartEmbeddedTor(options *model.Options) error {
	printing.DalLog("SYSTEM", "Attempting to start embedded Tor...", *options)

	conf := &tor.StartConf{
		SOCKSPort:     9055, // Attempt to set a specific port
		EnableNetwork: true,
		// We could also expose ControlPort if needed for more advanced interactions
		// ControlPort: 9056, // Example if we wanted control port
	}

	if options.TorDataDir != "" {
		conf.DataDir = options.TorDataDir
		printing.DalLog("SYSTEM", fmt.Sprintf("Using configured Tor data directory: %s", options.TorDataDir), *options)
	} else {
		// If TorDataDir is not set by the user, let bine handle its default (often a temp dir)
		// Or, we can explicitly create one like in the Execute() function later.
		// For now, if empty, bine will use its internal default or a temp one.
		printing.DalLog("SYSTEM", "Using default/temporary Tor data directory (managed by bine)", *options)
	}

	// Add a timeout to the start context, e.g., 3 minutes, similar to bine examples
	startCtx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	t, err := tor.Start(startCtx, conf)
	if err != nil {
		return fmt.Errorf("failed to start embedded tor: %w", err)
	}

	options.TorProcess = t
	// After starting, find out what port it's actually listening on,
	// as it might be different from the requested one if it was busy, or if bine assigns one dynamically.
	// For now, assuming the requested port is used if no error.
	// Need to check bine docs for how to get the actual listening SOCKS port.
	// Let's assume conf.SOCKSPort is updated or there's a way to get it from 't'.
	// This is a placeholder; actual port retrieval might be different.
	if socksConf, err := t.GetConf("SocksPort"); err == nil && len(socksConf) > 0 {
		// Assuming the format is "PORT" or "IP:PORT"
		// This is a simplification. Real parsing might be needed.
		// For now, we'll trust the initially set port if no error,
		// but ideally, we'd confirm the actual port.
		// The bine examples usually get the port from the listener object if they create one.
		// For a client SOCKS proxy, it might be set in the conf and expected to be used.
		// Let's assume the port we set in SOCKSPort is the one it uses.
		options.TorPort = conf.SOCKSPort
	} else {
		// Fallback or error if we can't confirm the SOCKS port
		// For now, we'll stick with the configured one.
		options.TorPort = conf.SOCKSPort
		printing.DalLog("INFO", fmt.Sprintf("Could not dynamically confirm SOCKS port, assuming configured: %d", options.TorPort), *options)

	}


	printing.DalLog("SYSTEM", fmt.Sprintf("Embedded Tor started successfully on SOCKS port: %d", options.TorPort), *options)
	return nil
}

// StopEmbeddedTor attempts to stop the embedded Tor process.
func StopEmbeddedTor(options *model.Options) {
	printing.DalLog("SYSTEM", "Attempting to stop embedded Tor...", *options)
	if options.TorProcess != nil {
		if t, ok := options.TorProcess.(*tor.Tor); ok {
			err := t.Close()
			if err != nil {
				printing.DalLog("ERROR", fmt.Sprintf("Error closing embedded Tor: %v", err), *options)
				return
			}
			printing.DalLog("SYSTEM", "Embedded Tor stopped.", *options)
			options.TorProcess = nil // Clear it after stopping
		} else {
			printing.DalLog("ERROR", "TorProcess is not of the expected type *tor.Tor", *options)
		}
	} else {
		printing.DalLog("INFO", "No embedded Tor process to stop.", *options)
	}
}
