package org.cachix.secretspec;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * The value-free resolution outcome for one declared secret.
 */
public final class SecretReport {

    @JsonProperty("name")
    private String name = "";

    @JsonProperty("status")
    private String status = "";

    @JsonProperty("required")
    private boolean required;

    @JsonProperty("source_provider")
    private String sourceProvider;

    @JsonProperty("default_applied")
    private boolean defaultApplied;

    @JsonProperty("generated")
    private boolean generated;

    @JsonProperty("as_path")
    private boolean asPath;

    public SecretReport() {
    }

    public String getName() {
        return name;
    }

    public String getStatus() {
        return status;
    }

    public boolean isRequired() {
        return required;
    }

    public String getSourceProvider() {
        return sourceProvider;
    }

    public boolean isDefaultApplied() {
        return defaultApplied;
    }

    public boolean isGenerated() {
        return generated;
    }

    public boolean isAsPath() {
        return asPath;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            name,
            status,
            required,
            sourceProvider,
            defaultApplied,
            generated,
            asPath
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
        var other = (SecretReport) o;
        return Objects.equals(name, other.name)
            && Objects.equals(status, other.status)
            && required == other.required
            && Objects.equals(sourceProvider, other.sourceProvider)
            && defaultApplied == other.defaultApplied
            && generated == other.generated
            && asPath == other.asPath;
    }
}
