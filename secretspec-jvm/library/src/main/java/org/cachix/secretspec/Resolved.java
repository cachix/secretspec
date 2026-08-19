package org.cachix.secretspec;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.HashMap;

import static java.util.Collections.unmodifiableMap;
import static org.cachix.secretspec.SafeCopy.safeCopyOf;


/**
 * A successful, value-carrying resolution.
 */
public final class Resolved implements AutoCloseable {

    private boolean disposed;

    Resolved(
        String provider,
        String profile,
        String scope,
        Map<String, ResolvedSecret> secrets,
        Collection<String> missingOptional
    ) {
        this.provider = provider;
        this.profile = profile;
        this.scope = scope;
        this.secrets = safeCopyOf(secrets);
        this.missingOptional = safeCopyOf(missingOptional);
    }

    private final String provider;
    private final String profile;
    /**
     * Selected manifest scope, or null for a full-profile resolve (0.17+).
     */
    private final String scope;
    private final Map<String, ResolvedSecret> secrets;
    private final List<String> missingOptional;

    public String provider() {
        return provider;
    }

    public String profile() {
        return profile;
    }

    public String scope() {
        return scope;
    }

    public Map<String, ResolvedSecret> secrets() {
        return secrets;
    }

    public ResolvedSecret secret(String name) {
        return secrets.get(name);
    }

    public List<String> missingOptional() {
        return missingOptional;
    }

    /**
     * Exports every present secret into the system properties.
     */
    public void setAsSystemProperties() {
        for (var entry : secrets.entrySet()) {
            var name = entry.getKey();
            var secret = entry.getValue();
            var value = secret.get();
            if (value != null)
                System.setProperty(name, value);
        }
    }

    /**
     * Returns a flat secret-name-to-value map suitable for a generated typed
     * deserializer. File-shaped secrets map to their paths; stripped values map to null.
     * @return the map of secrets to values
     */
    public Map<String, String> fields() {
        var fields = new HashMap<String, String>();
        for (var entry: secrets.entrySet()) {
            var secret = Optional.ofNullable(entry.getValue())
                                 .map(ResolvedSecret::get)
                                 .orElse(null);
            fields.put(entry.getKey(), secret);
        }
        return unmodifiableMap(fields);
    }

    /**
     * Serializes {@link #fields()} for a generated deserializer.
     * @return the map os secrets to values, as a JSON string
     */
    public String fieldsJson() {
        try {
            return SecretSpecJsonContext.MAPPER.writeValueAsString(fields());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize fields to JSON", e);
        }
    }

    /**
     * Removes temporary files backing {@code as_path} secrets.
     */
    public void close() {
        if (disposed)
            return;

        disposed = true;
        UncheckedIOException firstError = null;
        for (var secret : secrets.values()) {
            if (!secret.asPath() || secret.path() == null)
                continue;

            try {
                var path = Paths.get(secret.path());
                Files.deleteIfExists(path);
            }
            catch (IOException e) {
                if (firstError == null)
                    firstError = new UncheckedIOException(e);
            }
        }

        if (firstError != null)
            throw firstError;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            provider,
            profile,
            scope,
            secrets,
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
        var other = (Resolved) o;
        return Objects.equals(provider, other.provider)
            && Objects.equals(profile, other.profile)
            && Objects.equals(scope, other.scope)
            && Objects.equals(secrets, other.secrets)
            && Objects.equals(missingOptional, other.missingOptional);
    }
}
