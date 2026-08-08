package org.cachix.secretspec;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.util.Map;
import java.util.Objects;
import java.util.List;


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
            .build();

    public static final TypeReference<Envelope<ResolveResponseContract>> RESOLVE_ENVELOPE =
            new TypeReference<>() {};

    public static final TypeReference<Envelope<ReportResponseContract>> REPORT_ENVELOPE =
            new TypeReference<>() {};

    public static final TypeReference<Map<String, String>> SECRET_FIELDS =
            new TypeReference<>() {};

    private SecretSpecJsonContext() {
        // No instances.
    }
}

final class ResolveRequest {

    @JsonProperty("path")
    private String path;

    @JsonProperty("provider")
    private String provider;

    @JsonProperty("profile")
    private String profile;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("reason")
    private String reason;

    @JsonProperty("no_values")
    private boolean noValues;

    @JsonProperty("mode")
    private String mode;

    public ResolveRequest() {
    }
   
    public ResolveRequest(ResolveRequest request) {
        this.path = request.path;
        this.provider = request.provider;
        this.profile = request.profile;
        this.scope = request.scope;
        this.reason = request.reason;
        this.noValues = request.noValues;
        this.mode = request.mode;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public boolean isNoValues() {
        return noValues;
    }

    public void setNoValues(boolean noValues) {
        this.noValues = noValues;
    }

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
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
            mode
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
            && Objects.equals(mode, other.mode);
    }
}

final class Envelope<T> {

    @JsonProperty("ok")
    private boolean ok;

    @JsonProperty("response")
    private T response;

    @JsonProperty("error")
    private ErrorContract error;

    public Envelope() {
    }

    public boolean isOk() {
        return ok;
    }

    public T getResponse() {
        return response;
    }

    public ErrorContract getError() {
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

    @JsonProperty("kind")
    private String kind;

    @JsonProperty("message")
    private String message;

    public ErrorContract() {
    }

    public String getKind() {
        return kind;
    }

    public String getMessage() {
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

    @JsonProperty("schema_version")
    private int schemaVersion;

    @JsonProperty("provider")
    private String provider;

    @JsonProperty("profile")
    private String profile;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("secrets")
    private Map<String, ResolvedSecret> secrets;

    @JsonProperty("missing_required")
    private List<String> missingRequired;

    @JsonProperty("missing_optional")
    private List<String> missingOptional;

    public ResolveResponseContract() {
    }

    public int getSchemaVersion() {
        return schemaVersion;
    }

    public String getProvider() {
        return provider;
    }

    public String getProfile() {
        return profile;
    }

    public String getScope() {
        return scope;
    }

    public Map<String, ResolvedSecret> getSecrets() {
        return secrets;
    }

    public List<String> getMissingRequired() {
        return missingRequired;
    }

    public List<String> getMissingOptional() {
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

    @JsonProperty("schema_version")
    private int schemaVersion;

    @JsonProperty("provider")
    private String provider;

    @JsonProperty("profile")
    private String profile;

    @JsonProperty("scope")
    private String scope;

    @JsonProperty("secrets")
    private List<SecretReport> secrets;

    public ReportResponseContract() {
    }

    public int getSchemaVersion() {
        return schemaVersion;
    }

    public String getProvider() {
        return provider;
    }

    public String getProfile() {
        return profile;
    }

    public String getScope() {
        return scope;
    }

    public List<SecretReport> getSecrets() {
        return secrets;
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
