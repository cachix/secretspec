package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;

public class InlineSpecExample {

    public static void main(String[] args) {
        try (var resolved = SecretSpec.builder()
            .withInlineSpec(
                "{\n" +
                "  \"project\": { \"name\": \"java-inline\" },\n" +
                "  \"providers\": { \"env\": \"dotenv://inline.env\" },\n" +
                "  \"profiles\": { \"default\": { \"secrets\": {\n" +
                "    \"DATABASE_URL\": { \"description\": \"Database URL\", \"providers\": [\"env\"] }\n" +
                "  } } }\n" +
                "}",
                System.getProperty("user.dir")
            )
            .withReason("boot web app")
            .load()
        ) {
            System.out.println(resolved.provider() + " (" + resolved.profile() + ")");
            System.out.println(resolved.secret("DATABASE_URL").get());
            resolved.setAsSystemProperties();
        }
    }
}
