package org.cachix.secretspec;

import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonProperty;


/**
 * One resolved secret and its provenance.
 */
public final class ResolvedSecret {

    /**
     * The inline value, or null for an <c>as_path</c> secret.
     */
    @JsonProperty("value")
    private String value;

    /**
     * The materialized file path, or null for an inline secret.
     */
    @JsonProperty("path")
    private String path;

    @JsonProperty("as_path")
    private boolean asPath;

    @JsonProperty("source")
    private String source = "";

    @JsonProperty("source_provider")
    private String sourceProvider;

    /** Returns the usable string: the file path for an {@code as_path} secret,
     *  otherwise its inline value. A value-less resolution returns null.
     * @return the secret value or path
     */
    public String get() {
        return asPath ? path : value;
    }

    public ResolvedSecret() {
    }

    public String getValue() {
        return value;
    }

    public String getPath() {
        return path;
    }

    public boolean isAsPath() {
        return asPath;
    }

    public String getSource() {
        return source;
    }

    public String getSourceProvider() {
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
