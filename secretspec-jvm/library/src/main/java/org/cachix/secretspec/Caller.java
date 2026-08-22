package org.cachix.secretspec;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Objects;


public class Caller {

    public static final Builder named(String name) {
        return new Builder(name);
    }

    private final String name;
    private final String version;
    private final String operation;
    private final String resource;

    @JsonCreator
    public Caller(
        @JsonProperty("name") String name,
        @JsonProperty("version") String version,
        @JsonProperty("operation") String operation,
        @JsonProperty("resource") String resource
    ) {
        this.name = name;
        this.version = version;
        this.operation = operation;
        this.resource = resource;
    }

    @JsonProperty("name")
    public String name() {
        return name;
    }

    @JsonProperty("version")
    public String version() {
        return version;
    }

    @JsonProperty("operation")
    public String operation() {
        return operation;
    }

    @JsonProperty("resource")
    public String resource() {
        return resource;
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, version, operation, resource);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null)
            return false;
        if (getClass() != o.getClass())
            return false;
        var other = (Caller) o;
        return Objects.equals(name, other.name)
            && Objects.equals(version, other.version)
            && Objects.equals(operation, other.operation)
            && Objects.equals(resource, other.resource);
    }

    public static final class Builder {

        private String name;
        private String version;
        private String operation;
        private String resource;

        private Builder(String name) {
            this.name = name;
        }

        public Builder withVersion(String version) {
            this.version = version;
            return this;
        }

        public Builder withOperation(String operation) {
            this.operation = operation;
            return this;
        }

        public Builder withResource(String resource) {
            this.resource = resource;
            return this;
        }

        Caller build() {
            return new Caller(name, version, operation, resource);
        }
    }
}
