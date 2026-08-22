package org.cachix.secretspec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Objects;

import static java.util.Collections.unmodifiableList;


public class ConstraintViolation {

    private final String kind;
    private final String group;
    private final List<String> secrets;
    private final List<String> present;

    @JsonCreator
    public ConstraintViolation(
        @JsonProperty("kind") String kind,
        @JsonProperty("group") String group,
        @JsonProperty("secrets") List<String> secrets,
        @JsonProperty("present") List<String> present
    ) {
        this.kind = kind;
        this.group = group;
        this.secrets = secrets;
        this.present = present;
    }

    @JsonProperty("kind")
    public String kind() {
        return kind;
    }

    @JsonProperty("group")
    public String group() {
        return group;
    }

    @JsonProperty("secrets")
    public List<String> secrets() {
        return secrets == null ? null : unmodifiableList(secrets);
    }

    @JsonProperty("present")
    public List<String> present() {
        return present == null ? null : unmodifiableList(present);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, group, secrets, present);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ConstraintViolation that = (ConstraintViolation) o;
        return Objects.equals(kind, that.kind)
            && Objects.equals(group, that.group)
            && Objects.equals(secrets, that.secrets)
            && Objects.equals(present, that.present);
    }
}