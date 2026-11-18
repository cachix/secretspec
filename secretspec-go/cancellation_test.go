package secretspec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestLegacyBindingHelper(t *testing.T) {
	if os.Getenv("SECRETSPEC_CANCEL_BINDING_HELPER") != "1" {
		t.Skip("run by TestMissingCancellationSymbolsKeepLegacyLoad")
	}
	for i := 0; i < 2; i++ {
		_, err := New().LoadContext(context.Background())
		var native *Error
		if !errors.As(err, &native) || native.Kind != "capability" {
			t.Fatalf("missing symbols: %v", err)
		}
	}
	if _, err := New().Load(); err != nil {
		t.Fatalf("legacy binding poisoned: %v", err)
	}
}

func TestCancellationCallbackFinishesBeforeHandleFree(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var freed atomic.Bool
	native := &nativeCancellation{
		cancel: func() { close(entered); <-release },
		free:   func() { freed.Store(true) },
		call:   func(string) (string, error) { cancel(); <-entered; return "committed", nil },
	}
	go func() {
		raw, err := callWithContext(ctx, "{}", native)
		if err != nil || raw != "committed" {
			t.Errorf("call = %q, %v", raw, err)
		}
		close(returned)
	}()
	<-entered
	if freed.Load() {
		t.Fatal("handle freed while cancellation still uses it")
	}
	select {
	case <-returned:
		t.Fatal("returned before callback finished")
	default:
	}
	close(release)
	<-returned
	if !freed.Load() {
		t.Fatal("handle leaked")
	}
}

func TestLoadContextRejectsNilAndPreCancelled(t *testing.T) {
	if _, err := New().LoadContext(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := New().WithPath("/must-not-be-opened").LoadContext(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestNativeCommitWinsOverLateContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	resolved, err := decodeResolvedContext(ctx, `{"ok":true,"response":{"schema_version":2,"secrets":{}}}`)
	if err != nil || resolved == nil {
		t.Fatalf("committed result lost: %v", err)
	}
	_, err = decodeResolvedContext(ctx, `{"ok":false,"error":{"kind":"cleanup_failed","message":"cleanup failed","cancelled":true,"cleanup_phase":"child_wait"}}`)
	var native *Error
	if !errors.Is(err, context.Canceled) || !errors.As(err, &native) || native.Kind != "cleanup_failed" {
		t.Fatalf("cleanup error lost: %v", err)
	}
	if !native.Cancelled || native.CleanupPhase != "child_wait" {
		t.Fatalf("cleanup details lost: %+v", native)
	}
	_, err = decodeResolvedContext(ctx, `{"ok":false,"error":{"kind":"cleanup_failed","message":"cleanup failed","cancelled":false}}`)
	if errors.Is(err, context.Canceled) {
		t.Fatal("late context overwrote committed cleanup failure")
	}
}

func TestLoadContextLocalAndUnsupported(t *testing.T) {
	path, provider := writeProject(t, "DATABASE_URL=postgres://local\n")
	legacy, err := New().WithPath(path).WithProvider(provider).WithReason("cancellation test").Load()
	if err != nil {
		t.Fatal(err)
	}
	defer legacy.Close()
	resolved, err := New().WithPath(path).WithProvider(provider).WithReason("cancellation test").LoadContext(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer resolved.Close()
	if *resolved.Secrets["DATABASE_URL"].Value != *legacy.Secrets["DATABASE_URL"].Value {
		t.Fatal("local value changed")
	}
	_, err = New().WithPath(path).WithProvider("unregistered-managed-provider://").WithReason("cancellation test").LoadContext(context.Background())
	var native *Error
	if !errors.As(err, &native) || native.Kind != "cancellation_unsupported" {
		t.Fatalf("error = %v", err)
	}
}

func TestDeadlineErrorRetainsNativeDetails(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := decodeResolvedContext(ctx, `{"ok":false,"error":{"kind":"cancelled","message":"cancelled","cancelled":true}}`)
	var native *Error
	if !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &native) || !native.Cancelled {
		t.Fatalf("deadline or native cancellation lost: %v", err)
	}
}

func TestReadRestrictionsReachNativeResolution(t *testing.T) {
	for _, managed := range []bool{false, true} {
		name := "Load"
		if managed {
			name = "LoadContext"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			load := func(builder *Builder) error {
				var resolved *Resolved
				var err error
				if managed {
					resolved, err = builder.LoadContext(context.Background())
				} else {
					resolved, err = builder.Load()
				}
				if resolved != nil {
					resolved.Close()
				}
				return err
			}
			secret := map[string]any{"description": "file declaration", "as_path": true, "default": "value", "providers": []string{"null://"}}
			spec := map[string]any{
				"project":  map[string]any{"name": "restrictions", "require_reason": false},
				"profiles": map[string]any{"default": map[string]any{"secrets": map[string]any{"VALUE": secret}}},
			}
			var native *Error
			err := load(New().WithInlineSpec(spec, dir).WithNoFiles(true).WithNoValues(true))
			if !errors.As(err, &native) || native.Kind != "file_value_refused" {
				t.Fatalf("as_path declaration escaped no_files: %v", err)
			}
			delete(secret, "as_path")
			delete(secret, "default")
			secret["type"] = "uuid"
			secret["generate"] = true
			path := filepath.Join(dir, "must-not-be-created.env")
			secret["providers"] = []string{"dotenv:" + filepath.ToSlash(path)}
			err = load(New().WithInlineSpec(spec, dir).WithReadOnly(true))
			if !errors.As(err, &native) || native.Kind != "produced_value_write_refused" {
				t.Fatalf("generation escaped read_only: %v", err)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("read_only created a provider file: %v", err)
			}
		})
	}
}

func TestLoadContextCancelsCommandAndRetainsTypedError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix shell")
	}
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	// The path is JSON/TOML data, not interpolated into shell syntax.
	spec := map[string]any{
		"project": map[string]any{"name": "go-cancel", "require_reason": false},
		"profiles": map[string]any{"default": map[string]any{"secrets": map[string]any{
			"VALUE": map[string]any{"description": "cancellable command", "type": "command", "providers": []string{"null://"},
				"generate": map[string]any{"command": "printf started > started; sleep 60"}},
		}}},
	}
	// command generators inherit the working directory, as in the legacy API.
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(old)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := New().WithInlineSpec(spec, dir).LoadContext(ctx); done <- err }()
	startedDeadline := time.After(10 * time.Second)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("call finished before child start: %v", err)
		case <-startedDeadline:
			t.Fatal("child did not start")
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case err := <-done:
		var native *Error
		if !errors.Is(err, context.Canceled) || !errors.As(err, &native) || native.Kind != "cancelled" {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("native command cancellation did not finish")
	}
}

func TestLoadContextCancelsSOPSRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a Unix shell")
	}
	dir := os.Getenv("SECRETSPEC_GO_SOPS_FIXTURE")
	if dir == "" {
		dir = t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "sops"), []byte("#!/bin/sh\nprintf started > \"$SECRETSPEC_GO_SOPS_FIXTURE/started\"\nsleep 60 &\nwait\n"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte("sops: {}\n"), 0600); err != nil {
			t.Fatal(err)
		}
		// Set PATH before loading Rust, including in purego mode where Go's
		// os.Setenv does not update the native library's environment.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLoadContextCancelsSOPSRead$", "-test.v")
		child.Env = append(os.Environ(), "SECRETSPEC_GO_SOPS_FIXTURE="+dir, "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("SOPS fixture: %v\n%s", err, output)
		}
		return
	}
	spec := map[string]any{
		"project": map[string]any{"name": "go-sops", "require_reason": false},
		"profiles": map[string]any{"default": map[string]any{"secrets": map[string]any{
			"TOKEN": map[string]any{"description": "SOPS read", "providers": []string{"sops://" + filepath.ToSlash(filepath.Join(dir, "secrets.yaml"))}},
		}}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := New().WithInlineSpec(spec, dir).LoadContext(ctx); done <- err }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("SOPS read returned before starting: %v", err)
		case <-deadline:
			t.Fatal("SOPS read did not start")
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case err := <-done:
		var native *Error
		if !errors.Is(err, context.Canceled) || !errors.As(err, &native) || native.Kind != "cancelled" {
			t.Fatalf("SOPS cancellation = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SOPS cancellation did not finish")
	}
}
