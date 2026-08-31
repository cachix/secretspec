/*
 * SecretSpec C ABI.
 *
 * A deliberately narrow, JSON-in / JSON-out boundary. The entire native surface
 * is the functions below; all richness lives in the versioned JSON
 * contract so language bindings stay thin.
 *
 * Request JSON (all fields optional):
 *   { "path": ".../secretspec.toml", "provider": "keyring://",
 *     "profile": "production", "scope": "api", "reason": "boot",
 *     "caller": { "name": "git", "operation": "credential_get",
 *                 "resource": "github.com" },
 *     "no_values": false, "mode": "resolve" }
 *
 * "scope" selects a named [scopes] subset of the active profile (0.17+).
 * "caller" supplies structured, caller-asserted integration context (0.20+).
 * Unlike "reason", it never satisfies the require_reason policy.
 *
 * "mode" selects the response shape and defaults to "resolve":
 *
 *   "resolve"  the value-carrying resolve response. Set "no_values" to strip
 *              the values from it.
 *   "report"   the value-free resolution report: the inventory/preflight view
 *              the CLI exposes as `check --json`.
 *
 * Any other value is rejected with an "invalid_request" error.
 *
 * "no_values" is NOT the same as "mode": "report". A "no_values" resolve blanks
 * the values but keeps the resolve shape: its "secrets" is an object keyed by
 * name, it never says whether a secret is *declared* required, and when a
 * required secret is missing that object is empty. A report's "secrets" is an
 * ARRAY of per-secret entries carrying "name", "required", "status"
 * ("resolved" / "missing_required" / "missing_optional") and provenance, and
 * lists every declared secret whether or not it resolved. "required" is
 * reachable only via "report".
 *
 * Response envelope:
 *   { "ok": true,  "response": { ...resolve response | resolution report... } }
 *   { "ok": false, "error": { "kind": "io", "message": "..." } }
 *
 * "ok": false means the call itself failed (bad manifest, provider error,
 * unknown "mode"); a missing required secret is a domain result reported inside
 * an "ok": true response.
 *
 * A resolve response carries secret values unless "no_values" was set; a report
 * never does. Treat returned strings as sensitive and free them promptly.
 */
#ifndef SECRETSPEC_H
#define SECRETSPEC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Resolve secrets described by `request_json` (a NUL-terminated UTF-8 JSON
 * string). Returns a newly allocated, NUL-terminated JSON response envelope
 * that the caller OWNS and must release with secretspec_free().
 *
 * Returns NULL only on catastrophic allocation failure.
 */
char *secretspec_resolve(const char *request_json);

/*
 * Execute a versioned native operation. This is separate from
 * secretspec_resolve so SDKs using inline declarations can require this symbol
 * at load time, rather than risk an old library ignoring an unknown field and
 * searching for a filesystem manifest.
 *
 * Request v1:
 * {
 *   "request_version": 1,
 *   "operation": "resolve",
 *   "source": {
 *     "kind": "inline", "spec_version": 2, "base_dir": "/project",
 *     "spec": {
 *       "project": { "name": "my-app" },
 *       "profiles": {
 *         "default": { "secrets": {
 *           "TOKEN": { "description": "API token", "required": true }
 *         }}
 *       }
 *     }
 *   },
 *   "options": { "provider": "dotenv://.env", "reason": "startup" }
 * }
 *
 * source.kind is exactly one of "search", "path" (with path), or "inline".
 * Inline spec v2 is strict JSON: profile declarations use a `secrets` object,
 * and unknown declaration fields are rejected. Its base_dir resolves relative
 * provider paths like Secrets::from_spec_at. project.extends is supported and
 * resolves parent manifests relative to base_dir, like a file-backed Spec.
 */
char *secretspec_call(const char *request_json);

/*
 * Free a string previously returned by secretspec_resolve() or secretspec_call().
 * NULL is ignored.
 * Must not be called twice on the same pointer.
 */
void secretspec_free(char *ptr);

/*
 * Return the ABI version as a static NUL-terminated string. Do NOT free; the
 * pointer is valid for the lifetime of the loaded library.
 */
const char *secretspec_abi_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SECRETSPEC_H */
