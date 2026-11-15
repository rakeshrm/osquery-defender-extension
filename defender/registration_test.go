package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osquery/osquery-go/gen/osquery"
)

// fakeLister answers ExtensionsContext from a script: "y" = registered,
// "n" = not registered, "e" = error. After the script it repeats the last step.
type fakeLister struct {
	mu     sync.Mutex
	script string
	calls  int
}

func (f *fakeLister) ExtensionsContext(context.Context) (osquery.InternalExtensionList, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	step := f.script[min(f.calls, len(f.script)-1)]
	f.calls++
	switch step {
	case 'y':
		return osquery.InternalExtensionList{
			1: {Name: "something_else"},
			7: {Name: extensionName},
		}, nil
	case 'n':
		return osquery.InternalExtensionList{1: {Name: "something_else"}}, nil
	default:
		return nil, errors.New("osqueryd unreachable")
	}
}

func (f *fakeLister) count() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

func runWatch(t *testing.T, script string, wait time.Duration) (error, *fakeLister) {
	t.Helper()
	f := &fakeLister{script: script}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return watchRegistration(ctx, f, extensionName, time.Millisecond, time.Second, log), f
}

func TestWatchRegistrationExitsWhenDropped(t *testing.T) {
	err, f := runWatch(t, "yyyn", 2*time.Second)
	if err == nil || !strings.Contains(err.Error(), "no longer lists") {
		t.Fatalf("err = %v, want exit after being dropped", err)
	}
	if f.count() != 5 { // y y y n n -> exits on the second consecutive miss
		t.Errorf("calls = %d, want 5", f.count())
	}
}

func TestWatchRegistrationToleratesSingleMiss(t *testing.T) {
	// One miss followed by a registered answer resets the count.
	err, f := runWatch(t, "ynynyny", 200*time.Millisecond)
	if err != nil {
		t.Fatalf("err = %v, want no exit for isolated misses", err)
	}
	if f.count() < 7 {
		t.Errorf("calls = %d, want the whole script to run", f.count())
	}
}

func TestWatchRegistrationIgnoresListErrors(t *testing.T) {
	// osqueryd unreachable is osquery-go's ping loop's job, not a miss.
	err, _ := runWatch(t, "ye", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("err = %v, want errors ignored", err)
	}
	// Errors between misses do not reset the count either way; misses still need to be consecutive answers.
	err, _ = runWatch(t, "yneen", 2*time.Second)
	if err == nil {
		t.Fatal("want exit: two 'not registered' answers with only errors between them")
	}
}

func TestWatchRegistrationStopsOnCancel(t *testing.T) {
	err, _ := runWatch(t, "y", 50*time.Millisecond)
	if err != nil {
		t.Fatalf("err = %v, want nil on cancel", err)
	}
}

func TestRegistered(t *testing.T) {
	if registered(nil, extensionName) {
		t.Error("nil list")
	}
	if !registered(osquery.InternalExtensionList{3: nil, 4: {Name: extensionName}}, extensionName) {
		t.Error("should find by name, skipping nil entries")
	}
}
