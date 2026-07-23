// Package secretspec is a Go SDK for SecretSpec, a declarative secrets manager.
//
// It is a thin client over the secretspec-ffi C ABI. Resolution (providers,
// chains, profiles, generation, as_path) happens entirely in the Rust core; this
// package marshals a JSON request to secretspec_resolve, parses the response
// envelope, and exposes it with the same vocabulary as the Rust derive crate.
//
// Two bindings select the native resolver at build time:
//   - default (no build tag): purego (dlopen, no cgo). The library is located via
//     the SECRETSPEC_FFI_LIB environment variable, an embedded copy, or a Cargo
//     target directory. This keeps `go get` toolchain-free.
//   - `-tags static`: cgo statically links libsecretspec_ffi.a, so the resolver
//     is embedded in the Go binary (fully static on Linux/musl). See README.
//
// Both bindings implement the same hooks (ensureLoaded, nativeResolve,
// nativeABIVersion); the code below is binding-agnostic.
package secretspec

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// resolveSchemaVersion is the response wire-format version this SDK understands.
// It tracks secretspec-ffi's RESOLVE_SCHEMA_VERSION; a mismatch means the loaded
// library is incompatible with this SDK, so Load reports it rather than silently
// misparsing.
const resolveSchemaVersion = 2

// Error is a resolution failure (bad manifest, provider error, reason policy).
type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (kind: %s)", e.Message, e.Kind)
}

// MissingRequiredError reports required secrets that were not found anywhere.
type MissingRequiredError struct {
	Missing []string
}

func (e *MissingRequiredError) Error() string {
	return "missing required secret(s): " + strings.Join(e.Missing, ", ")
}

// ResolvedSecret is one resolved secret. Exactly one of Value / Path is set.
type ResolvedSecret struct {
	Value          *string
	Path           *string
	AsPath         bool
	Source         string
	SourceProvider *string
}

// Usable returns the secret's usable string and whether one is present: the file
// path for as_path secrets, otherwise the value. Both are absent when a
// value-less response (e.g. no_values) strips them, in which case ok is false.
// This is the null-aware accessor; the other SDKs express the same thing as a
// get() that returns null/None/nil.
func (s ResolvedSecret) Usable() (string, bool) {
	if s.AsPath {
		if s.Path != nil {
			return *s.Path, true
		}
		return "", false
	}
	if s.Value != nil {
		return *s.Value, true
	}
	return "", false
}

// Get returns the usable string: the file path for as_path secrets, else the
// value. It is the empty string when no usable value is present; use Usable to
// distinguish an absent value from a genuinely empty one.
func (s ResolvedSecret) Get() string {
	v, _ := s.Usable()
	return v
}

// Resolved is a successful resolution, mirroring the Rust Resolved wrapper.
type Resolved struct {
	Provider string
	Profile  string
	// Scope is the selected manifest scope, or nil for a full-profile resolve (0.17+).
	Scope           *string
	Secrets         map[string]ResolvedSecret
	MissingOptional []string
}

// SetAsEnv exports each resolved secret into the process environment by name.
// Secrets with no usable value (e.g. under no_values) are skipped rather than
// exported as an empty string.
func (r *Resolved) SetAsEnv() error {
	for name, secret := range r.Secrets {
		if value, ok := secret.Usable(); ok {
			if err := os.Setenv(name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// Fields returns a flat map of SECRET_NAME -> value (the file path for as_path).
// A secret with no usable value (e.g. under no_values) maps to a nil pointer,
// which marshals to JSON null, matching the null the Python, Ruby, and Node SDKs
// emit; the value is a non-nil pointer otherwise.
func (r *Resolved) Fields() map[string]*string {
	out := make(map[string]*string, len(r.Secrets))
	for name, secret := range r.Secrets {
		if v, ok := secret.Usable(); ok {
			val := v
			out[name] = &val
		} else {
			out[name] = nil
		}
	}
	return out
}

// FieldsJSON marshals Fields() to JSON (a `{SECRET_NAME: value-or-null}` object),
// the input for a quicktype-generated deserializer (e.g. UnmarshalSecretSpec).
// See `secretspec schema`.
func (r *Resolved) FieldsJSON() ([]byte, error) {
	return json.Marshal(r.Fields())
}

// Close removes the temp files backing any as_path secrets in this result. The
// resolver persists those files (mode 0400) so their paths stay valid after
// resolve returns; the caller owns their lifetime. Call it (e.g.
// `defer resolved.Close()`) when done so secret files do not accumulate in the
// temp dir. Non-as_path secrets and a no_values result hold no path and are
// skipped, and a file already gone is not an error.
func (r *Resolved) Close() error {
	var firstErr error
	for _, secret := range r.Secrets {
		if secret.AsPath && secret.Path != nil {
			if err := os.Remove(*secret.Path); err != nil && !os.IsNotExist(err) && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// ABIVersion returns the version reported by the native resolver.
func ABIVersion() (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}
	return nativeABIVersion()
}

// Builder configures a resolution, mirroring the derive crate's SecretSpec::builder().
type Builder struct {
	req map[string]any
}

// New starts a resolution builder.
func New() *Builder {
	return &Builder{req: map[string]any{}}
}

// set lazily initializes the request map so a zero-value Builder (e.g.
// `var b Builder` or `&Builder{}`, not just New()) does not panic with a
// nil-map write in the setters below.
func (b *Builder) set(key string, value any) *Builder {
	if b.req == nil {
		b.req = map[string]any{}
	}
	b.req[key] = value
	return b
}

func (b *Builder) WithPath(path string) *Builder  { return b.set("path", path) }
func (b *Builder) WithProvider(p string) *Builder { return b.set("provider", p) }
func (b *Builder) WithProfile(p string) *Builder  { return b.set("profile", p) }

// WithScope limits resolution to a named manifest scope (SecretSpec 0.17+).
func (b *Builder) WithScope(scope string) *Builder   { return b.set("scope", scope) }
func (b *Builder) WithReason(reason string) *Builder { return b.set("reason", reason) }
func (b *Builder) WithNoValues(v bool) *Builder      { return b.set("no_values", v) }

// envelope is the response wrapper shared by the resolve and report paths,
// generic over its inner response type R.
type envelope[R any] struct {
	OK       bool       `json:"ok"`
	Response *R         `json:"response"`
	Error    *errorJSON `json:"error"`
}

type errorJSON struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type secretJSON struct {
	Value          *string `json:"value"`
	Path           *string `json:"path"`
	AsPath         bool    `json:"as_path"`
	Source         string  `json:"source"`
	SourceProvider *string `json:"source_provider"`
}

type responseJSON struct {
	SchemaVersion   int                   `json:"schema_version"`
	Provider        string                `json:"provider"`
	Profile         string                `json:"profile"`
	Scope           *string               `json:"scope"`
	Secrets         map[string]secretJSON `json:"secrets"`
	MissingRequired []string              `json:"missing_required"`
	MissingOptional []string              `json:"missing_optional"`
}

// parseEnvelope unmarshals a response envelope, validates the envelope-level
// fields shared by the resolve and report responses, and returns the inner
// response. kind ("resolve" or "report") labels the version-mismatch message;
// schemaOf reads the response's schema_version for the version check.
func parseEnvelope[R any](raw, kind string, expected int, schemaOf func(*R) int) (*R, error) {
	var env envelope[R]
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, err
	}
	if !env.OK {
		errKind, message := "unknown", ""
		if env.Error != nil {
			errKind, message = env.Error.Kind, env.Error.Message
		}
		return nil, &Error{Kind: errKind, Message: message}
	}
	if env.Response == nil {
		return nil, &Error{Kind: "ffi", Message: "secretspec_resolve reported ok with no response"}
	}
	if v := schemaOf(env.Response); v != expected {
		return nil, &Error{Kind: "version", Message: fmt.Sprintf(
			"unsupported %s schema version %d (expected %d); the secretspec-ffi library and this SDK are out of sync",
			kind, v, expected,
		)}
	}
	return env.Response, nil
}

// Load resolves the secrets. It returns *MissingRequiredError if a required
// secret is missing, and *Error for any other failure.
func (b *Builder) Load() (*Resolved, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	// A zero-value Builder (var b Builder; b.Load()) has a nil req, which marshals
	// to the literal `null` that serde rejects as an invalid JsonRequest. The WithX
	// setters lazily allocate req, but Load may run before any of them.
	if b.req == nil {
		b.req = map[string]any{}
	}
	payload, err := json.Marshal(b.req)
	if err != nil {
		return nil, err
	}

	raw, err := nativeResolve(string(payload))
	if err != nil {
		return nil, err
	}

	resp, err := parseEnvelope(raw, "resolve", resolveSchemaVersion, func(r *responseJSON) int { return r.SchemaVersion })
	if err != nil {
		return nil, err
	}
	if len(resp.MissingRequired) > 0 {
		return nil, &MissingRequiredError{Missing: resp.MissingRequired}
	}

	secrets := make(map[string]ResolvedSecret, len(resp.Secrets))
	for name, entry := range resp.Secrets {
		secrets[name] = ResolvedSecret{
			Value:          entry.Value,
			Path:           entry.Path,
			AsPath:         entry.AsPath,
			Source:         entry.Source,
			SourceProvider: entry.SourceProvider,
		}
	}
	return &Resolved{
		Provider:        resp.Provider,
		Profile:         resp.Profile,
		Scope:           resp.Scope,
		Secrets:         secrets,
		MissingOptional: resp.MissingOptional,
	}, nil
}

// reportSchemaVersion is the value-free report wire-format version this SDK
// understands; it tracks secretspec's RESOLUTION_REPORT_SCHEMA_VERSION.
const reportSchemaVersion = 1

// SecretReport is the value-free resolution outcome for one declared secret:
// how it would resolve and from where, never the value itself.
type SecretReport struct {
	Name           string
	Status         string // "resolved" | "missing_required" | "missing_optional"
	Required       bool
	SourceProvider *string
	DefaultApplied bool
	Generated      bool
	AsPath         bool
}

// Report is a value-free resolution snapshot: every declared secret and how it
// would resolve, never a value. Unlike Load, a missing required secret is
// reported as a SecretReport with Status "missing_required" rather than an
// error, so it describes a profile even when its secrets are not all available.
type Report struct {
	Provider string
	Profile  string
	// Scope is the selected manifest scope, or nil for a full-profile report (0.17+).
	Scope   *string
	Secrets []SecretReport
}

type secretReportJSON struct {
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	Required       bool    `json:"required"`
	SourceProvider *string `json:"source_provider"`
	DefaultApplied bool    `json:"default_applied"`
	Generated      bool    `json:"generated"`
	AsPath         bool    `json:"as_path"`
}

type reportResponseJSON struct {
	SchemaVersion int                `json:"schema_version"`
	Provider      string             `json:"provider"`
	Profile       string             `json:"profile"`
	Scope         *string            `json:"scope"`
	Secrets       []secretReportJSON `json:"secrets"`
}

// Report resolves the value-free report (the inventory/preflight view, the same
// one the CLI exposes as `check --json`). It never returns
// *MissingRequiredError: a missing required secret appears as a SecretReport
// with Status "missing_required". It returns *Error for a genuine failure.
func (b *Builder) Report() (*Report, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	req := make(map[string]any, len(b.req)+1)
	for k, v := range b.req {
		req[k] = v
	}
	req["mode"] = "report"
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	raw, err := nativeResolve(string(payload))
	if err != nil {
		return nil, err
	}

	resp, err := parseEnvelope(raw, "report", reportSchemaVersion, func(r *reportResponseJSON) int { return r.SchemaVersion })
	if err != nil {
		return nil, err
	}

	secrets := make([]SecretReport, len(resp.Secrets))
	for i, s := range resp.Secrets {
		secrets[i] = SecretReport(s)
	}
	return &Report{
		Provider: resp.Provider,
		Profile:  resp.Profile,
		Scope:    resp.Scope,
		Secrets:  secrets,
	}, nil
}
