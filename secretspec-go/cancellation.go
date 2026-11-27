package secretspec

import (
	"context"
	"encoding/json"
	"errors"
)

const cancellationUnavailable = "libsecretspec does not support cancellable resolution (requires 0.22+)"

// nativeCancellation owns Rust memory; its callbacks never retain a Go pointer.
type nativeCancellation struct {
	cancel func()
	free   func()
	call   func(string) (string, error)
}

// callWithContext waits for both native cleanup and a racing callback before
// releasing the handle. There is no goroutine returning ahead of native work.
func callWithContext(ctx context.Context, payload string, native *nativeCancellation) (string, error) {
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(callbackDone)
		native.cancel()
	})
	defer func() {
		if !stop() {
			<-callbackDone
		}
		native.free()
	}()
	// AfterFunc need not run immediately, including with GOMAXPROCS=1.
	if ctx.Err() != nil {
		native.cancel()
	}
	return native.call(payload)
}

// LoadContext resolves with native cancellation (SecretSpec 0.22+).
//
// Cancellation waits for resolver workers, direct children and pipe workers.
// It requests process group or Windows Job termination. Descendant exit may
// complete after return. OS operations, cryptography and cleanup can delay
// return beyond the deadline.
// Unsupported provider/auth/operation paths return cancellation_unsupported;
// this method never falls back to Load, even for context.Background().
func (b *Builder) LoadContext(ctx context.Context) (*Resolved, error) {
	if ctx == nil {
		return nil, &Error{Kind: "invalid_request", Message: "LoadContext requires a non-nil context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	payload, err := b.callPayload("")
	if err != nil {
		return nil, err
	}
	native, err := newNativeCancellation()
	if err != nil {
		return nil, err
	}
	raw, err := callWithContext(ctx, payload, native)
	if err != nil {
		return nil, err
	}
	return decodeResolvedContext(ctx, raw)
}

func decodeResolvedContext(ctx context.Context, raw string) (*Resolved, error) {
	resolved, err := decodeResolved(raw)
	var native *Error
	if errors.As(err, &native) && (native.Kind == "cancelled" || native.Cancelled) && ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	// A result committed by Rust wins over a later ctx cancellation.
	return resolved, err
}

func (b *Builder) callPayload(mode string) (string, error) {
	options := make(map[string]any, len(b.req)+1)
	for key, value := range b.req {
		if key != "path" {
			options[key] = value
		}
	}
	if mode != "" {
		options["mode"] = mode
	}
	source := map[string]any{"kind": "search"}
	if path, exists := b.req["path"]; exists {
		source = map[string]any{"kind": "path", "path": path}
	}
	if b.inline != nil {
		source = map[string]any{"kind": "inline", "spec_version": 2, "base_dir": b.inline.baseDir, "spec": b.inline.spec}
	}
	payload, err := json.Marshal(map[string]any{
		"request_version": 1, "operation": "resolve", "source": source, "options": options,
	})
	return string(payload), err
}
