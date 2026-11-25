package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;

public class AsPathExample {

    public static void main(String[] args) {
        try (var resolved = SecretSpec.builder().withReason("TLS boot").load()) {
            var secrets = resolved.secrets();
            var certificatePath = secrets.get("TLS_CERT").get();
            // Use the certificate before resolved is disposed.
            System.out.println(certificatePath);
        }
    }
}
