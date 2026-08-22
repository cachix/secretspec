package org.cachix.secretspec;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static java.util.Collections.unmodifiableList;
import static org.cachix.secretspec.SafeCopy.safeCopyOf;


/**
 * A value-free inventory/preflight snapshot.
 */
public final class ResolutionReport {

    ResolutionReport(
        String provider,
        String profile,
        String scope,
        Collection<SecretReport> secrets,
        Collection<ConstraintViolation> constraintViolations
    ) {
        this.provider = provider;
        this.profile = profile;
        this.scope = scope;
        this.secrets = safeCopyOf(secrets);
        this.constraintViolations = safeCopyOf(constraintViolations);
    }

    private final String provider;
    private final String profile;
    /**
     * Selected manifest scope, or null for a full-profile report (0.17+).
     */
    private final String scope;
    private final List<SecretReport> secrets;
    private final List<ConstraintViolation> constraintViolations;

    public String provider() {
        return provider;
    }

    public String profile() {
        return profile;
    }

    public String scope() {
        return scope;
    }

    public List<SecretReport> secrets() {
        return unmodifiableList(secrets);
    }

    public List<ConstraintViolation> constraintViolations() {
        return unmodifiableList(constraintViolations);
    }

    @Override
    public int hashCode() {
        return Objects.hash(
            provider,
            profile,
            scope,
            secrets,
            constraintViolations
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
            && Objects.equals(secrets, other.secrets)
            && Objects.equals(constraintViolations, other.constraintViolations);
    }
}
