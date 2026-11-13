// Command defender-mpengine is an osquery extension exposing Microsoft
// Defender's encrypted mpenginedb.db as defender_mpengine_* tables. With
// --decrypt it instead writes a plaintext copy for offline analysis.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/huntbase-io/osquery-defender/internal/mpengine"
	"github.com/huntbase-io/osquery-defender/internal/tables"
	"github.com/osquery/osquery-go"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	fs := flag.NewFlagSet("defender-mpengine", flag.ContinueOnError)
	var (
		socket    = fs.String("socket", "", "osquery extension socket path")
		timeout   = fs.Int("timeout", 3, "seconds to wait for osquery")
		interval  = fs.Int("interval", 3, "seconds between pings to osquery")
		verbose   = fs.Bool("verbose", false, "debug logging")
		version   = fs.Bool("version", false, "print version and exit")
		mpPath    = fs.String("mpengine_path", "", "default mpenginedb.db file or Scans directory (default: "+mpengine.DefaultDir+" on Windows)")
		cacheTTL  = fs.Duration("cache_ttl", 30*time.Second, "reuse a decrypted snapshot (or a failed open) for this long while the files are unchanged; 0 disables caching")
		cacheMax  = fs.Int("cache_entries", mpengine.DefaultCacheEntries, "maximum number of cached snapshots (LRU)")
		queryTO   = fs.Duration("query_timeout", 30*time.Second, "deadline for one table query (all paths); 0 = none")
		maxRows   = fs.Int("max_rows", 500000, "maximum rows read per source table per path; 0 = unlimited")
		maxBytes  = fs.Int64("max_db_bytes", mpengine.DefaultMaxBytes, "refuse a database whose db+wal size exceeds this many bytes")
		allowUNC  = fs.Bool("allow_unc_paths", false, `allow path = '\\server\share\...' and \\.\ / \\?\ device paths in table queries`)
		deriveKey = fs.Bool("derive_key", false, "ignore known keys and derive the keystream from the evidence")
		decrypt   = fs.String("decrypt", "", "offline: decrypt this mpenginedb.db file or directory to --out and exit")
		out       = fs.String("out", "", "offline: output path for --decrypt (must not exist)")
		wal       = fs.String("wal", "", "offline: explicit WAL path for --decrypt")
	)
	if err := fs.Parse(knownArgs(fs, os.Args[1:])); err != nil {
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	switch {
	case *version:
		fmt.Println(Version)
	case *decrypt != "":
		if err := decryptTo(os.Stdout, *decrypt, *out, mpengine.Options{DeriveKey: *deriveKey, WALPath: *wal, MaxBytes: *maxBytes}); err != nil {
			log.Error("decrypt failed", "err", err)
			os.Exit(1)
		}
	default:
		if *socket == "" {
			log.Error("--socket is required (or use --decrypt / --version)")
			os.Exit(2)
		}
		cache := mpengine.NewCache(*cacheTTL, *cacheMax, mpengine.Options{DeriveKey: *deriveKey, MaxBytes: *maxBytes})
		err := serve(*socket, time.Duration(*timeout)*time.Second, time.Duration(*interval)*time.Second,
			tables.Config{Cache: cache, DefaultPath: *mpPath, Logger: log,
				QueryTimeout: *queryTO, MaxRows: *maxRows, AllowUNCPaths: *allowUNC})
		cache.Close()
		if err != nil {
			log.Error("extension stopped", "err", err)
			os.Exit(1)
		}
	}
}

func serve(socket string, timeout, interval time.Duration, cfg tables.Config) error {
	srv, err := osquery.NewExtensionManagerServer("defender_mpengine", socket,
		osquery.ExtensionVersion(Version), osquery.ServerTimeout(timeout), osquery.ServerPingInterval(interval))
	if err != nil {
		return err
	}
	srv.RegisterPlugin(tables.Plugins(cfg)...)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	return srv.Run()
}

// decryptTo writes the plaintext image to out (refusing to overwrite, mode
// 0600) and prints the Info as JSON to w. A derived keystream must produce an
// image that passes PRAGMA integrity_check, otherwise nothing is written.
func decryptTo(w io.Writer, src, out string, opt mpengine.Options) error {
	if out == "" {
		return fmt.Errorf("--out is required with --decrypt")
	}
	img, info, err := mpengine.Decrypt(src, opt)
	if err != nil {
		return err
	}
	if info.KeySource == "derived" {
		ic, err := mpengine.IntegrityCheck(img)
		if err != nil {
			return fmt.Errorf("derived keystream: %w", err)
		}
		if ic != "ok" {
			return fmt.Errorf("derived keystream did not produce a consistent database (%d low-confidence byte positions): integrity_check: %s", info.DerivedLowConfidence, ic)
		}
	}
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(img)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(out)
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(info)
}

// knownArgs drops flags fs does not define (osquery may pass extra ones),
// along with their separate value argument. Positional arguments are ignored.
func knownArgs(fs *flag.FlagSet, args []string) []string {
	var kept []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name, _, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		f := fs.Lookup(name)
		takesValue := !hasValue && (f == nil || !isBool(f)) && i+1 < len(args)
		if f == nil {
			if takesValue && !strings.HasPrefix(args[i+1], "-") {
				i++ // unknown flag's value
			}
			continue
		}
		kept = append(kept, a)
		if takesValue {
			i++
			kept = append(kept, args[i])
		}
	}
	return kept
}

func isBool(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}
