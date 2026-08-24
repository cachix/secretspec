package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;

public class ScopeExample {

    public static void main(String[] args) {
        try (var resolved = SecretSpec.builder().withScope("api").load()) {
            resolved.setAsSystemProperties();
        }
    }
}
