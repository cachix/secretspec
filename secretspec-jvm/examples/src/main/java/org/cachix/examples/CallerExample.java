package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;
import org.cachix.secretspec.Caller;

public class CallerExample {

    public static void main(String[] args) {
        try (var resolved = SecretSpec.builder()
            .withProvider("keyring://")
            .withProfile("production")
            .withCaller(Caller.named("caller name")
                .withVersion("optional caller version")
                .withOperation("optional operation")
                .withResource("optional resource")
            )
            .withReason("boot web app")
            .load()
        ) {
            System.out.println(resolved.provider() + " (" + resolved.profile() + ")");
            System.out.println(resolved.secret("DATABASE_URL").get());
        }
    }
}
