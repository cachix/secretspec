package org.cachix.secretspec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;


/**
 * One resolved secret and its provenance.
 */
public final class ResolvedSecret {

    /**
     * The inline value, or null for an {@code as_path} secret.
     */
    private String value;

    /**
     * The materialized file path, or null for an inline secret.
     */
    private String path;

    private boolean asPath;
    private String source;
    private String sourceProvider;

    /** Returns the usable string: the file path for an {@code as_path} secret,
     *  otherwise its inline value. A value-less resolution returns null.
     * @return the secret value or path
     */
    public String get() {
        return asPath ? path : value;
    }

    @JsonCreator
    public ResolvedSecret(
            @JsonProperty("value") String value,
            @JsonProperty("path") String path,
            @JsonProperty("as_path") boolean asPath,
            @JsonProperty("source") String source,
            @JsonProperty("source_provider") String sourceProvider
    ) {
        this.value = value;
        this.path = path;
        this.asPath = asPath;
        this.source = source != null ? source : "";
        this.sourceProvider = sourceProvider;
    }

    @JsonProperty("value")
    public String value() {
        return value;
    }

    @JsonProperty("path")
    public String path() {
        return path;
    }

    @JsonProperty("as_path")
    public boolean asPath() {
        return asPath;
    }

    @JsonProperty("source")
    public String source() {
        return source;
    }

    @JsonProperty("source_provider")
    public String sourceProvider() {
        return sourceProvider;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            value,
            path,
            asPath,
            source,
            sourceProvider
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
        var other = (ResolvedSecret) o;
        return Objects.equals(value, other.value)
            && Objects.equals(path, other.path)
            && asPath == other.asPath
            && Objects.equals(source, other.source)
            && Objects.equals(sourceProvider, other.sourceProvider);
    }
}
