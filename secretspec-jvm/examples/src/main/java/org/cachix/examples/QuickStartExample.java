package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;

public class QuickStartExample {

    public static void main(String[] args) {
        try (var resolved = SecretSpec.builder()
            .withProvider("keyring://")
            .withProfile("production")
            .withReason("boot web app")
            .load()
        ) {
            System.out.println(resolved.provider() + " (" + resolved.profile() + ")");
            System.out.println(resolved.secret("DATABASE_URL").get());
            resolved.setAsSystemProperties();
        }
    }
}
