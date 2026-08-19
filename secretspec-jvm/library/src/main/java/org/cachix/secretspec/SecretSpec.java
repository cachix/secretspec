package org.cachix.secretspec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;


/**
 * Entry point for the SecretSpec JVM SDK.
 */
public class SecretSpec {

    /**
     * Starts a fluent resolution builder.
     * @return the fluent builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * The ABI version reported by the loaded native resolver.
     * @return the ABI version
     */
    public static String abiVersion() { return NativeResolver.abiVersion(); };

    private SecretSpec() {
        // No instances.
    }

    /**
     * Configures a SecretSpec resolution.
     */
    public static final class Builder {

        private String path;
        private String provider;
        private String profile;
        private String scope;
        private String reason;
        private boolean noValues;
        private String mode;
        private Caller caller;

        public Builder withPath(String path) {
            this.path = path;
            return this;
        }

        public Builder withProvider(String provider) {
            this.provider = provider;
            return this;
        }

        public Builder withProfile(String profile) {
            this.profile = profile;
            return this;
        }

        /**
         * Limits resolution to a named manifest scope (SecretSpec 0.17+).
         * @param scope the requested scope
         * @return the fluent builder
         */
        public Builder withScope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder withReason(String reason) {
            this.reason = reason;
            return this;
        }

        public Builder withNoValues(boolean noValues) {
            this.noValues = noValues;
            return this;
        }

        public Builder withNoValues() {
            return withNoValues(true);
        }

        public Builder withCaller(Caller.Builder callerBuilder) {
            this.caller = callerBuilder.build();
            return this;
        }

        /**
         * Resolves the configured secrets.
         *
         * @return a {@link Resolved} instance with the secrets loaded
         * @throws MissingRequiredException if a required secret was missing
         * @throws SecretSpecException      if resolution otherwise failed
         */
        public Resolved load() {
            var resolveRequest = new ResolveRequest(
                path,
                provider,
                profile,
                scope,
                reason,
                noValues,
                mode,
                caller
            );
            ResolveResponseContract response = call(
                    resolveRequest,
                    "resolve",
                    SecretSpecJsonContext.RESOLVE_ENVELOPE
            );

            ensureSchemaVersion(response.schemaVersion(), JsonContracts.RESOLVE_SCHEMA_VERSION, "resolve");

            if (response.missingRequired() != null && !response.missingRequired().isEmpty()) {
                throw new MissingRequiredException(response.missingRequired());
            }

            return new Resolved(
                    response.provider(),
                    response.profile(),
                    response.scope(),
                    response.secrets(),
                    response.missingOptional()
            );
        }

        /**
         * Resolves a value-free inventory/preflight report. Missing required
         * secrets appear in the report rather than throwing.
         *
         * @return a {@link ResolutionReport} instance
         */
        public ResolutionReport report() {
            var reportRequest = new ResolveRequest(
                path,
                provider,
                profile,
                scope,
                reason,
                noValues,
                "report",
                caller
            );

            var response = call(
                    reportRequest,
                    "report",
                    SecretSpecJsonContext.REPORT_ENVELOPE
            );

            ensureSchemaVersion(response.schemaVersion(), JsonContracts.REPORT_SCHEMA_VERSION, "report");

            return new ResolutionReport(
                    response.provider(),
                    response.profile(),
                    response.scope(),
                    response.secrets(),
                    response.constraintViolations()
            );
        }
    }

    private static <T> T call(
            ResolveRequest request,
            String kind,
            TypeReference<Envelope<T>> typeReference) {

        String payload;
        try {
            payload = SecretSpecJsonContext.MAPPER.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new SecretSpecException("serialize", "Failed to serialize request: " + e.getMessage(), e);
        }

        String raw = NativeResolver.resolve(payload);

        Envelope<T> envelope;
        try {
            envelope = SecretSpecJsonContext.MAPPER.readValue(raw, typeReference);
        } catch (JsonProcessingException error) {
            throw new SecretSpecException("parse", error.getMessage(), error);
        }

        if (envelope == null) {
            throw new SecretSpecException("parse", "native resolver returned an empty response");
        }

        if (!envelope.ok()) {
            String errorKind = (envelope.error() != null && envelope.error().kind() != null)
                    ? envelope.error().kind()
                    : "unknown";
            String errorMessage = (envelope.error() != null && envelope.error().message() != null)
                    ? envelope.error().message()
                    : "native resolver returned an unspecified error";

            throw new SecretSpecException(errorKind, errorMessage);
        }

        if (envelope.response() == null) {
            throw new SecretSpecException(
                    "ffi",
                    String.format("secretspec_resolve reported ok with no %s response", kind)
            );
        }

        return envelope.response();
    }

    private static void ensureSchemaVersion(int actual, int expected, String kind) {
        if (actual != expected) {
            throw new SecretSpecException(
                    "version",
                    String.format("unsupported %s schema version %d (expected %d); " +
                            "the secretspec-ffi library and this SDK are out of sync", kind, actual, expected)
            );
        }
    }
}
