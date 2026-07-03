/*
 * SecretSpec C ABI.
 *
 * A deliberately narrow, JSON-in / JSON-out boundary. The entire native surface
 * is the three functions below; all richness lives in the versioned JSON
 * contract so language bindings stay thin.
 *
 * Request JSON (all fields optional):
 *   { "path": ".../secretspec.toml", "provider": "keyring://",
 *     "profile": "production", "reason": "boot", "no_values": false }
 *
 * Response envelope:
 *   { "ok": true,  "response": { ...resolve response... } }
 *   { "ok": false, "error": { "kind": "io", "message": "..." } }
 *
 * The response (when ok) carries secret values unless "no_values" was set.
 * Treat returned strings as sensitive and free them promptly.
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
 * Free a string previously returned by secretspec_resolve(). NULL is ignored.
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
