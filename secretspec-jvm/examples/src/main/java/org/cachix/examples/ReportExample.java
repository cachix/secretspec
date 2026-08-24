package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;

public class ReportExample {

    public static void main(String[] args) {
        var report = SecretSpec.builder()
            .withProfile("production")
            .withReason("deployment preflight")
            .report();

        for (var secret : report.secrets())
            System.out.println(secret.name() + ": " + secret.status());
    }
}
