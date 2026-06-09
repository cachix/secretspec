// Package secretspec is a Go SDK for SecretSpec, a declarative secrets manager.
//
// It is a thin client over the secretspec-ffi C ABI, loaded at runtime via
// purego (dlopen, no cgo). Resolution (providers, chains, profiles, generation,
// as_path) happens entirely in the Rust core; this package marshals a JSON
// request to secretspec_resolve, parses the response envelope, and exposes it
// with the same vocabulary as the Rust derive crate.
//
// The native library is located via, in order: the SECRETSPEC_FFI_LIB
// environment variable, or a Cargo target directory found by searching up from
// the working directory.
package secretspec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// resolveSchemaVersion is the response wire-format version this SDK understands.
// It tracks secretspec-ffi's RESOLVE_SCHEMA_VERSION; a mismatch means the loaded
// library is incompatible with this SDK, so Load reports it rather than silently
// misparsing.
const resolveSchemaVersion = 1

var (
	loadOnce sync.Once
	loadErr  error
	cResolve func(string) uintptr
	cFree    func(uintptr)
	cABI     func() uintptr
)

func libNames() []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{"libsecretspec_ffi.dylib"}
	case "windows":
		return []string{"secretspec_ffi.dll"}
	default:
		return []string{"libsecretspec_ffi.so"}
	}
}

func findLibrary() (string, error) {
	if p := os.Getenv("SECRETSPEC_FFI_LIB"); p != "" {
		return p, nil
	}
	// A library embedded at build time (go:embed, per platform) is extracted to
	// a temp file and used, so `go get` works with no native build.
	if len(embeddedLib) > 0 {
		return extractEmbedded()
	}
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		for _, profile := range []string{"release", "debug"} {
			for _, name := range libNames() {
				candidate := filepath.Join(dir, "target", profile, name)
				if _, err := os.Stat(candidate); err == nil {
					return candidate, nil
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", &Error{
		Kind:    "load",
		Message: "could not locate the secretspec-ffi library; set SECRETSPEC_FFI_LIB",
	}
}

func ensureLoaded() error {
	loadOnce.Do(func() {
		path, err := findLibrary()
		if err != nil {
			loadErr = err
			return
		}
		handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err != nil {
			loadErr = err
			return
		}
		purego.RegisterLibFunc(&cResolve, handle, "secretspec_resolve")
		purego.RegisterLibFunc(&cFree, handle, "secretspec_free")
		purego.RegisterLibFunc(&cABI, handle, "secretspec_abi_version")
	})
	return loadErr
}

// goString copies a NUL-terminated C string at ptr into a Go string. The
// pointer comes from the C ABI (a Rust allocation), not Go's heap, so this is a
// legitimate FFI read; `go vet`'s unsafeptr check flags it as a false positive
// (it is not part of the `go test` vet subset).
func goString(ptr uintptr) string {
	if ptr == 0 {
		return ""
	}
	base := unsafe.Pointer(ptr)
	length := 0
	for *(*byte)(unsafe.Add(base, length)) != 0 {
		length++
	}
	return string(unsafe.Slice((*byte)(base), length))
}

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

// usable returns the secret's usable string and whether one is present: the file
// path for as_path secrets, otherwise the value. Both are absent when a
// value-less response (e.g. no_values) strips them, in which case ok is false.
func (s ResolvedSecret) usable() (string, bool) {
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
// value. It is the empty string when no usable value is present (see usable).
func (s ResolvedSecret) Get() string {
	v, _ := s.usable()
	return v
}

// Resolved is a successful resolution, mirroring the Rust Resolved wrapper.
type Resolved struct {
	Provider        string
	Profile         string
	Secrets         map[string]ResolvedSecret
	MissingOptional []string
}

// SetAsEnv exports each resolved secret into the process environment by name.
// Secrets with no usable value (e.g. under no_values) are skipped rather than
// exported as an empty string.
func (r *Resolved) SetAsEnv() error {
	for name, secret := range r.Secrets {
		if value, ok := secret.usable(); ok {
			if err := os.Setenv(name, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// Fields returns a flat map of SECRET_NAME -> value (the file path for as_path).
func (r *Resolved) Fields() map[string]string {
	out := make(map[string]string, len(r.Secrets))
	for name, secret := range r.Secrets {
		out[name] = secret.Get()
	}
	return out
}

// FieldsJSON marshals Fields() to JSON, the input for a quicktype-generated
// deserializer (e.g. UnmarshalSecretSpec). See `secretspec schema`.
func (r *Resolved) FieldsJSON() ([]byte, error) {
	return json.Marshal(r.Fields())
}

// ABIVersion returns the version reported by the loaded library.
func ABIVersion() (string, error) {
	if err := ensureLoaded(); err != nil {
		return "", err
	}
	return goString(cABI()), nil
}

// Builder configures a resolution, mirroring the derive crate's SecretSpec::builder().
type Builder struct {
	req map[string]any
}

// New starts a resolution builder.
func New() *Builder {
	return &Builder{req: map[string]any{}}
}

func (b *Builder) WithPath(path string) *Builder     { b.req["path"] = path; return b }
func (b *Builder) WithProvider(p string) *Builder    { b.req["provider"] = p; return b }
func (b *Builder) WithProfile(p string) *Builder     { b.req["profile"] = p; return b }
func (b *Builder) WithReason(reason string) *Builder { b.req["reason"] = reason; return b }
func (b *Builder) WithNoValues(v bool) *Builder      { b.req["no_values"] = v; return b }

type envelopeJSON struct {
	OK       bool          `json:"ok"`
	Response *responseJSON `json:"response"`
	Error    *errorJSON    `json:"error"`
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
	Secrets         map[string]secretJSON `json:"secrets"`
	MissingRequired []string              `json:"missing_required"`
	MissingOptional []string              `json:"missing_optional"`
}

// Load resolves the secrets. It returns *MissingRequiredError if a required
// secret is missing, and *Error for any other failure.
func (b *Builder) Load() (*Resolved, error) {
	if err := ensureLoaded(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(b.req)
	if err != nil {
		return nil, err
	}

	ptr := cResolve(string(payload))
	if ptr == 0 {
		return nil, &Error{Kind: "ffi", Message: "secretspec_resolve returned null"}
	}
	raw := goString(ptr)
	cFree(ptr)

	var env envelopeJSON
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, err
	}
	if !env.OK {
		kind, message := "unknown", ""
		if env.Error != nil {
			kind, message = env.Error.Kind, env.Error.Message
		}
		return nil, &Error{Kind: kind, Message: message}
	}

	resp := env.Response
	if resp == nil {
		return nil, &Error{Kind: "ffi", Message: "secretspec_resolve reported ok with no response"}
	}
	if resp.SchemaVersion != resolveSchemaVersion {
		return nil, &Error{Kind: "version", Message: fmt.Sprintf(
			"unsupported resolve schema version %d (expected %d); the secretspec-ffi library and this SDK are out of sync",
			resp.SchemaVersion, resolveSchemaVersion,
		)}
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
		Secrets:         secrets,
		MissingOptional: resp.MissingOptional,
	}, nil
}
