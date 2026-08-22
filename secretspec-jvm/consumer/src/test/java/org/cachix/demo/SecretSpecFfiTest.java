package org.cachix.demo;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.cachix.secretspec.SecretSpec;
import org.cachix.secretspec.Resolved;


class SecretSpecFfiTest {

    private static final String MANIFEST =
        "[project]\n" +
        "name = \"java-test\"\n" +
        "revision = \"1.0\"\n" +
        "\n" +
        "[profiles.default]\n" +
        "DATABASE_URL = { description = \"DB\", required = true }\n" +
        "DEV_SESSION_SECRET = { description = \"Development-only session secret\", required = false, default = \"development-only-secret\" }\n" +
        "SENTRY_DSN = { description = \"sentry\", required = false }\n" +
        "\n" +
        "[scopes.database]\n" +
        "secrets = [\"DATABASE_URL\"]\n";

    @Test
    void testJnaBinding() {
        assertThat(SecretSpec.abiVersion())
            .withFailMessage("Cannot get ABI version from JNA library. ")
            .isNotNull();
    }

    @Test
    void testBasicUsage() {
        try (
            Project project = Project.create(MANIFEST, "DATABASE_URL=postgres://db\n");
            Resolved resolved = project.builder().load();
        ) {
            assertThat(resolved.profile()).isEqualTo("default");
            assertThat(resolved.secret("DATABASE_URL").get()).isEqualTo("postgres://db");
            assertThat(resolved.secret("DATABASE_URL").source()).isEqualTo("provider");
            assertThat(resolved.secret("DATABASE_URL").sourceProvider()).withFailMessage("provider provenance missing").isNotNull();
            assertThat(resolved.secret("DEV_SESSION_SECRET").get()).isEqualTo("development-only-secret");
            assertThat(resolved.secret("DEV_SESSION_SECRET").source()).isEqualTo("default");
            assertThat(resolved.missingOptional()).isEqualTo(List.of("SENTRY_DSN"));
            assertThat(resolved.secrets()).withFailMessage("missing optional secret was returned").doesNotContainKey("SENTRY_DSN");
        }
    }

    // Java 11 IO Compatibility
    private static void writeString(Path path, String content) {
        try {
            Files.write(path, content.getBytes(StandardCharsets.UTF_8));
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static final class Project implements AutoCloseable {
        private final Path root;
        final String manifestPath;
        final String provider;

        private Project(Path root) {
            this.root = root;
            this.manifestPath = root.resolve("secretspec.toml").toString();
            this.provider = "dotenv://" + root.resolve(".env");
        }

        SecretSpec.Builder builder() {
            return SecretSpec.builder()
                    .withPath(manifestPath)
                    .withProvider(provider)
                    .withReason("Java test");
        }

        static Project create(String manifest, String dotenv) {
            try {
                Path tempDir = Files.createTempDirectory("secretspec-jvm-");
                Project project = new Project(tempDir);
                writeString(Path.of(project.manifestPath), manifest);
                writeString(tempDir.resolve(".env"), dotenv);
                return project;
            }
            catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }

        @Override
        public void close() {
            deleteDirectory(root.toFile());
        }

        private static void deleteDirectory(File dir) {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) deleteDirectory(f);
                    else f.delete();
                }
            }
            dir.delete();
        }
    }
}