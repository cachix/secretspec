package org.cachix.examples;

import org.cachix.secretspec.SecretSpec;
import io.quicktype.AppSecrets;
import io.quicktype.Converter;

import java.io.IOException;

public class TypedAccessExample {

    public static void main(String[] args) throws IOException {
        try (var resolved = SecretSpec.builder().load()) {
            AppSecrets typed = Converter.fromJsonString(resolved.fieldsJson());
            System.out.println(typed.getDatabaseURL());
        }
    }
}
