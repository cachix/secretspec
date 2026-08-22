package org.cachix.secretspec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.util.Collections.unmodifiableList;


final class JsonContracts {

    static final int RESOLVE_SCHEMA_VERSION = 2;
    static final int REPORT_SCHEMA_VERSION = 1;

    private JsonContracts() {
        // No instances
    }
}

final class SecretSpecJsonContext {

    public static final ObjectMapper MAPPER = JsonMapper.builder()
            .defaultPropertyInclusion(JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.USE_DEFAULTS))
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    public static final TypeReference<Envelope<ResolveResponseContract>> RESOLVE_ENVELOPE =
            new TypeReference<>() {};

    public static final TypeReference<Envelope<ReportResponseContract>> REPORT_ENVELOPE =
            new TypeReference<>() {};

    private SecretSpecJsonContext() {
        // No instances.
    }
}

final class ResolveRequest {

    private final String path;
    private final String provider;
    private final String profile;
    private final String scope;
    private final String reason;
    private final boolean noValues;
    private final String mode;
    private final Caller caller;

    @JsonCreator
    public ResolveRequest(
        @JsonProperty("path") String path,
        @JsonProperty("provider") String provider,
        @JsonProperty("profile") String profile,
        @JsonProperty("scope") String scope,
        @JsonProperty("reason") String reason,
        @JsonProperty("no_values") boolean noValues,
        @JsonProperty("mode") String mode,
        @JsonProperty("caller") Caller caller
    ) {
        this.path = path;
        this.provider = provider;
        this.profile = profile;
        this.scope = scope;
        this.reason = reason;
        this.noValues = noValues;
        this.mode = mode;
        this.caller = caller;
    }

    @JsonProperty("path")
    public String path() {
        return path;
    }

    @JsonProperty("provider")
    public String provider() {
        return provider;
    }

    @JsonProperty("profile")
    public String profile() {
        return profile;
    }

    @JsonProperty("scope")
    public String scope() {
        return scope;
    }

    @JsonProperty("reason")
    public String reason() {
        return reason;
    }

    @JsonProperty("no_values")
    public boolean noValues() {
        return noValues;
    }

    @JsonProperty("mode")
    public String mode() {
        return mode;
    }

    @JsonProperty("caller")
    public Caller caller() {
        return caller;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            path,
            provider,
            profile,
            scope,
            reason,
            noValues,
            mode,
            caller
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false;
        var other = (ResolveRequest) o;
        return Objects.equals(path, other.path)
            && Objects.equals(provider, other.provider)
            && Objects.equals(profile, other.profile)
            && Objects.equals(scope, other.scope)
            && Objects.equals(reason, other.reason)
            && noValues == other.noValues
            && Objects.equals(mode, other.mode)
            && Objects.equals(caller, other.caller);
    }
}

final class Envelope<T> {

    private final boolean ok;
    private final T response;
    private final ErrorContract error;

    @JsonCreator
    public Envelope(
        @JsonProperty("ok") boolean ok,
        @JsonProperty("response") T response,
        @JsonProperty("error") ErrorContract error
    ) {
        this.ok = ok;
        this.response = response;
        this.error = error;
    }

    @JsonProperty("ok")
    public boolean ok() {
        return ok;
    }

    @JsonProperty("response")
    public T response() {
        return response;
    }

    @JsonProperty("error")
    public ErrorContract error() {
        return error;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            ok,
            response,
            error
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false;
        @SuppressWarnings("unchecked")
        var other = (Envelope<T>) o;
        return Objects.equals(ok, other.ok)
            && Objects.equals(response, other.response)
            && Objects.equals(error, other.error);
    }

}

final class ErrorContract {

    private final String kind;
    private final String message;

    @JsonCreator
    public ErrorContract(
        @JsonProperty("kind") String kind,
        @JsonProperty("message") String message
        ) {
        this.kind = kind;
        this.message = message;
    }

    @JsonProperty("kind")
    public String kind() {
        return kind;
    }

    @JsonProperty("message")
    public String message() {
        return message;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            kind,
            message
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false;
        var other = (ErrorContract) o;
        return Objects.equals(kind, other.kind)
            && Objects.equals(message, other.message);
    }
}

final class ResolveResponseContract {

    private final int schemaVersion;
    private final String provider;
    private final String profile;
    private final String scope;
    private final Map<String, ResolvedSecret> secrets;
    private final List<String> missingRequired;
    private final List<String> missingOptional;

    @JsonCreator
    public ResolveResponseContract(
        @JsonProperty("schema_version") int schemaVersion,
        @JsonProperty("provider") String provider,
        @JsonProperty("profile") String profile,
        @JsonProperty("scope") String scope,
        @JsonProperty("secrets") Map<String, ResolvedSecret> secrets,
        @JsonProperty("missing_required") List<String> missingRequired,
        @JsonProperty("missing_optional") List<String> missingOptional
    ) {
        this.schemaVersion = schemaVersion;
        this.provider = provider != null ? provider : "";
        this.profile = profile != null ? profile : "";
        this.scope = scope;
        this.secrets = secrets != null ? secrets : Map.of();
        this.missingRequired = missingRequired != null ? missingRequired : List.of();
        this.missingOptional = missingOptional != null ? missingOptional : List.of();
    }

    @JsonProperty("schema_version")
    public int schemaVersion() {
        return schemaVersion;
    }

    @JsonProperty("provider")
    public String provider() {
        return provider;
    }

    @JsonProperty("profile")
    public String profile() {
        return profile;
    }

    @JsonProperty("scope")
    public String scope() {
        return scope;
    }

    @JsonProperty("secrets")
    public Map<String, ResolvedSecret> secrets() {
        return secrets;
    }

    @JsonProperty("missing_required")
    public List<String> missingRequired() {
        return missingRequired;
    }

    @JsonProperty("missing_optional")
    public List<String> missingOptional() {
        return missingOptional;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            schemaVersion,
            provider,
            profile,
            scope,
            secrets,
            missingRequired,
            missingOptional
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false;
        var other = (ResolveResponseContract) o;
        return Objects.equals(schemaVersion, other.schemaVersion)
            && Objects.equals(provider, other.provider)
            && Objects.equals(profile, other.profile)
            && Objects.equals(scope, other.scope)
            && Objects.equals(secrets, other.secrets)
            && Objects.equals(missingRequired, other.missingRequired)
            && Objects.equals(missingOptional, other.missingOptional);
    }
}

final class ReportResponseContract {

    private final int schemaVersion;
    private final String provider;
    private final String profile;
    private final String scope;
    private final List<SecretReport> secrets;
    private final List<ConstraintViolation> constraintViolations;

    @JsonCreator
    public ReportResponseContract(
        @JsonProperty("schema_version") int schemaVersion,
        @JsonProperty("provider") String provider,
        @JsonProperty("profile") String profile,
        @JsonProperty("scope") String scope,
        @JsonProperty("secrets") List<SecretReport> secrets,
        @JsonProperty("constraint_violations") List<ConstraintViolation> constraintViolations
    ) {
        this.schemaVersion = schemaVersion;
        this.provider = provider != null ? provider : "";
        this.profile = profile != null ? profile : "";
        this.scope = scope;
        this.secrets = secrets != null ? secrets : List.of();
        this.constraintViolations = constraintViolations;
    }

    @JsonProperty("schema_version")
    public int schemaVersion() {
        return schemaVersion;
    }

    @JsonProperty("provider")
    public String provider() {
        return provider;
    }

    @JsonProperty("profile")
    public String profile() {
        return profile;
    }

    @JsonProperty("scope")
    public String scope() {
        return scope;
    }

    @JsonProperty("secrets")
    public List<SecretReport> secrets() {
        return secrets == null ? null : unmodifiableList(secrets);
    }

    @JsonProperty("constraint_violations")
    public List<ConstraintViolation> constraintViolations() {
        return constraintViolations == null ? null : unmodifiableList(constraintViolations);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            schemaVersion,
            provider,
            profile,
            scope,
            secrets
        );
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false;
        var other = (ReportResponseContract) o;
        return Objects.equals(schemaVersion, other.schemaVersion)
            && Objects.equals(provider, other.provider)
            && Objects.equals(profile, other.profile)
            && Objects.equals(scope, other.scope)
            && Objects.equals(secrets, other.secrets);
    }
}
