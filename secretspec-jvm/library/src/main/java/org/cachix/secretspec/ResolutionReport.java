package org.cachix.secretspec;

import java.util.Collection;
import java.util.List;
import java.util.Objects;


/**
 * A value-free inventory/preflight snapshot.
 */
public final class ResolutionReport {
    
    ResolutionReport(
        String provider,
        String profile,
        String scope,
        Collection<SecretReport> secrets
    ) {
        this.provider = provider;
        this.profile = profile;
        this.scope = scope;
        this.secrets = List.copyOf(secrets);
    }

    private final String provider;
    private final String profile;
    /**
     * Selected manifest scope, or null for a full-profile report (0.17+).
     */
    private final String scope;
    private final List<SecretReport> secrets;

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
        var other = (ResolutionReport) o;
        return Objects.equals(provider, other.provider)
            && Objects.equals(profile, other.profile)
            && Objects.equals(scope, other.scope)
            && Objects.equals(secrets, other.secrets);
    }
}
