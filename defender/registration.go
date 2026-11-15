package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/osquery/osquery-go/gen/osquery"
)

// extensionLister is the part of the osquery manager client the registration
// watchdog needs; *osquery.ExtensionManagerClient implements it.
type extensionLister interface {
	ExtensionsContext(ctx context.Context) (osquery.InternalExtensionList, error)
}

// missesBeforeExit is how many consecutive checks must find the extension
// unregistered before it exits. One miss can be a race with registration.
const missesBeforeExit = 2

// watchRegistration returns an error once osqueryd stops listing the extension
// called name, and nil when ctx is cancelled.
//
// osqueryd drops an extension after a single failed health check ("Extension
// UUID N has gone away"), but the extension's own ping to osqueryd keeps
// succeeding, because the manager's ping does not check registration. Without
// this watchdog the extension lingers alive but unregistered, and osqueryd,
// which only relaunches extensions that exit, never restarts it: every table
// query fails until the host reboots. (Seen in a 49 h soak on Windows Server
// 2025: one transient health-check failure, then 25 h of "vtable constructor
// failed".)
//
// Errors talking to osqueryd are not counted as misses: if osqueryd itself
// is gone, osquery-go's own ping loop shuts the server down.
func watchRegistration(ctx context.Context, lister extensionLister, name string, every, callTimeout time.Duration, log *slog.Logger) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		cctx, cancel := context.WithTimeout(ctx, callTimeout)
		list, err := lister.ExtensionsContext(cctx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Debug("registration check: could not list extensions", "err", err)
			continue
		}
		if registered(list, name) {
			misses = 0
			continue
		}
		misses++
		log.Warn("registration check: osqueryd does not list this extension", "name", name, "misses", misses)
		if misses >= missesBeforeExit {
			return fmt.Errorf("osqueryd no longer lists extension %q; exiting so osqueryd restarts it", name)
		}
	}
}

func registered(list osquery.InternalExtensionList, name string) bool {
	for _, info := range list {
		if info != nil && info.Name == name {
			return true
		}
	}
	return false
}
