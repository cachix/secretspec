package org.cachix.secretspec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;


/**
 * The value-free resolution outcome for one declared secret.
 */
public final class SecretReport {

    private final String name;
    private final String status;
    private final boolean required;
    private final String sourceProvider;
    private final boolean defaultApplied;
    private final boolean generated;
    private final boolean asPath;

    @JsonCreator
    public SecretReport(
        @JsonProperty("name") String name,
        @JsonProperty("status") String status,
        @JsonProperty("required") boolean required,
        @JsonProperty("source_provider") String sourceProvider,
        @JsonProperty("default_applied") boolean defaultApplied,
        @JsonProperty("generated") boolean generated,
        @JsonProperty("as_path") boolean asPath
    ) {
        this.name = name != null ? name : "";
        this.status = status != null ? status : "";
        this.required = required;
        this.sourceProvider = sourceProvider;
        this.defaultApplied = defaultApplied;
        this.generated = generated;
        this.asPath = asPath;
    }

    @JsonProperty("name")
    public String name() {
        return name;
    }

    @JsonProperty("status")
    public String status() {
        return status;
    }

    @JsonProperty("required")
    public boolean required() {
        return required;
    }

    @JsonProperty("source_provider")
    public String sourceProvider() {
        return sourceProvider;
    }

    @JsonProperty("default_applied")
    public boolean defaultApplied() {
        return defaultApplied;
    }

    @JsonProperty("generated")
    public boolean generated() {
        return generated;
    }

    @JsonProperty("as_path")
    public boolean asPath() {
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
