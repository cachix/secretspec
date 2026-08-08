package org.cachix.secretspec;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Configures a SecretSpec resolution.
 */
public final class SecretSpecBuilder {

    private static final ObjectMapper MAPPER = SecretSpecJsonContext.MAPPER;

    private final ResolveRequest request = new ResolveRequest();

    public SecretSpecBuilder withPath(String path) {
        this.request.setPath(path);
        return this;
    }

    public SecretSpecBuilder withProvider(String provider) {
        this.request.setProvider(provider);
        return this;
    }

    public SecretSpecBuilder withProfile(String profile) {
        this.request.setProfile(profile);
        return this;
    }

    /**
     * Limits resolution to a named manifest scope (SecretSpec 0.17+).
     * @param scope the requested scope
     * @return the fluent builder
     */
    public SecretSpecBuilder withScope(String scope) {
        this.request.setScope(scope);
        return this;
    }

    public SecretSpecBuilder withReason(String reason) {
        this.request.setReason(reason);
        return this;
    }

    public SecretSpecBuilder withNoValues(boolean noValues) {
        this.request.setNoValues(noValues);
        return this;
    }

    public SecretSpecBuilder withNoValues() {
        return withNoValues(true);
    }

    /**
     * Resolves the configured secrets.
     *
     * @return a {@link Resolved} instance with the secrets loaded
     * @throws MissingRequiredException if a required secret was missing
     * @throws SecretSpecException      if resolution otherwise failed
     */
    public Resolved load() {
        ResolveResponseContract response = call(
                this.request,
                "resolve",
                SecretSpecJsonContext.RESOLVE_ENVELOPE
        );

        ensureSchemaVersion(response.getSchemaVersion(), JsonContracts.RESOLVE_SCHEMA_VERSION, "resolve");

        if (response.getMissingRequired() != null && !response.getMissingRequired().isEmpty()) {
            throw new MissingRequiredException(response.getMissingRequired());
        }

        return new Resolved(
                response.getProvider(),
                response.getProfile(),
                response.getScope(),
                response.getSecrets(),
                response.getMissingOptional()
        );
    }

    /**
     * Resolves a value-free inventory/preflight report. Missing required
     * secrets appear in the report rather than throwing.
     *
     * @return a {@link ResolutionReport} instance
     */
    public ResolutionReport report() {
        ResolveRequest reportRequest = new ResolveRequest(request);
        reportRequest.setMode("report");

        var response = call(
                reportRequest,
                "report",
                SecretSpecJsonContext.REPORT_ENVELOPE
        );

        ensureSchemaVersion(response.getSchemaVersion(), JsonContracts.REPORT_SCHEMA_VERSION, "report");

        return new ResolutionReport(
                response.getProvider(),
                response.getProfile(),
                response.getScope(),
                response.getSecrets()
        );
    }

    private static <T> T call(
            ResolveRequest request,
            String kind,
            TypeReference<Envelope<T>> typeReference) {
        
        String payload;
        try {
            payload = MAPPER.writeValueAsString(request);
        } catch (JsonProcessingException e) {
            throw new SecretSpecException("serialize", "Failed to serialize request: " + e.getMessage(), e);
        }

        String raw = Native.resolve(payload);

        Envelope<T> envelope;
        try {
            envelope = MAPPER.readValue(raw, typeReference);
        } catch (JsonProcessingException error) {
            throw new SecretSpecException("parse", error.getMessage(), error);
        }

        if (envelope == null) {
            throw new SecretSpecException("parse", "native resolver returned an empty response");
        }

        if (!envelope.isOk()) {
            String errorKind = (envelope.getError() != null && envelope.getError().getKind() != null)
                    ? envelope.getError().getKind()
                    : "unknown";
            String errorMessage = (envelope.getError() != null && envelope.getError().getMessage() != null)
                    ? envelope.getError().getMessage()
                    : "native resolver returned an unspecified error";

            throw new SecretSpecException(errorKind, errorMessage);
        }

        if (envelope.getResponse() == null) {
            throw new SecretSpecException(
                    "ffi",
                    String.format("secretspec_resolve reported ok with no %s response", kind)
            );
        }

        return envelope.getResponse();
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
