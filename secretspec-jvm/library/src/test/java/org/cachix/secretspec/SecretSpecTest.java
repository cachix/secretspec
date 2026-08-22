package org.cachix.secretspec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;


class SecretSpecTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
    void testAbiVersion() {
        assertThat(SecretSpec.abiVersion())
            .withFailMessage("ABI version was empty")
            .isNotBlank();
    }

    @Test
    void testLoad() {
        try (Project project = Project.create(MANIFEST, "DATABASE_URL=postgres://db\n");
             Resolved resolved = project.builder().load()) {

            assertThat(resolved.profile()).isEqualTo("default");
            assertThat(resolved.secrets().get("DATABASE_URL").get()).isEqualTo("postgres://db");
            assertThat(resolved.secrets().get("DATABASE_URL").source()).isEqualTo("provider");
            assertThat(resolved.secrets().get("DATABASE_URL").sourceProvider()).withFailMessage("provider provenance missing").isNotNull();
            assertThat(resolved.secrets().get("DEV_SESSION_SECRET").get()).isEqualTo("development-only-secret");
            assertThat(resolved.secrets().get("DEV_SESSION_SECRET").source()).isEqualTo("default");
            assertThat(resolved.missingOptional()).isEqualTo(List.of("SENTRY_DSN"));
            assertThat(resolved.secrets()).withFailMessage("missing optional secret was returned").doesNotContainKey("SENTRY_DSN");

            JsonNode fields = readJson(resolved.fieldsJson());
            assertThat(fields.get("DATABASE_URL").asText()).isEqualTo("postgres://db");
        }
    }

    @Test
    void testScope() {
        try (Project project = Project.create(
                MANIFEST,
                "DATABASE_URL=postgres://db\nSENTRY_DSN=https://sentry\n")) {

            SecretSpec.Builder builder = project.builder().withScope("database");

            try (Resolved resolved = builder.load()) {
                assertThat(resolved.scope()).isEqualTo("database");
                assertThat(resolved.secrets().keySet()).containsExactly("DATABASE_URL");
            }

            ResolutionReport report = builder.report();
            assertThat(report.scope()).isEqualTo("database");
            List<String> reportNames = report.secrets().stream()
                    .map(SecretReport::name)
                    .collect(Collectors.toList());
            assertThat(reportNames).containsExactly("DATABASE_URL");
        }
    }

    @Test
    void testMissingRequired() {
        try (Project project = Project.create(MANIFEST, "")) {
            MissingRequiredException error = catchThrowableOfType(MissingRequiredException.class, () -> project.builder().load());
            assertThat(error.missing()).containsExactly("DATABASE_URL");
            assertThat(error.kind()).isEqualTo("missing_required");
        }
    }

    @Test
    void testInvalidManifest() {
        Path invalidPath = Path.of(System.getProperty("java.io.tmpdir"), UUID.randomUUID().toString(), "secretspec.toml");
        SecretSpecException error = catchThrowableOfType(SecretSpecException.class, () ->
            SecretSpec.builder()
                .withPath(invalidPath.toString())
                .withReason("Java test")
                .load()
        );

        assertThat(error.getClass()).withFailMessage("transport failure became missing-required")
            .isNotEqualTo(MissingRequiredException.class);
        assertThat(error.kind()).withFailMessage("error kind was empty")
            .isNotNull()
            .isNotBlank();
    }

    @Test
    void testAsPathCleanup() {
        String manifest =
            "[project]\n" +
            "name = \"java-test\"\n" +
            "revision = \"1.0\"\n" +
            "\n" +
            "[profiles.default]\n" +
            "TLS_CERT = { description = \"cert\", required = true, as_path = true }\n";

        String path;
        try (Project project = Project.create(manifest, "TLS_CERT=----cert----\n")) {
            try (Resolved resolved = project.builder().load()) {
                ResolvedSecret cert = resolved.secrets().get("TLS_CERT");
                assertThat(cert.asPath()).withFailMessage("TLS_CERT was not marked as_path").isTrue();
                assertThat(cert.value()).withFailMessage("as_path secret exposed an inline value").isNull();

                path = cert.get();
                assertThat(path).withFailMessage("as_path secret had no path").isNotNull();
                assertThat(readString(Path.of(path))).isEqualTo("----cert----");
            }
            assertThat(Path.of(path)).withFailMessage("Dispose/close did not remove the secret temp file")
                .doesNotExist();
        }
    }

    @Test
    void testReport() {
        try (Project project = Project.create(MANIFEST, "")) {
            ResolutionReport report = project.builder().report();

            assertThat(report.profile()).isEqualTo("default");

            SecretReport database = report.secrets().stream()
                    .filter(s -> "DATABASE_URL".equals(s.name()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("DATABASE_URL not found"));
            assertThat(database.status()).isEqualTo("missing_required");
            assertThat(database.required()).withFailMessage("DATABASE_URL was not reported as required").isTrue();

            SecretReport sessionSecret = report.secrets().stream()
                    .filter(s -> "DEV_SESSION_SECRET".equals(s.name()))
                    .findFirst()
                    .orElseThrow(() -> new AssertionError("DEV_SESSION_SECRET not found"));
            assertThat(sessionSecret.defaultApplied()).withFailMessage("DEV_SESSION_SECRET default was not reported").isTrue();
        }
    }

    @Test
    void testSetAsSystemProperties() {
        var previous = System.getProperty("DATABASE_URL");
        try (Project project = Project.create(MANIFEST, "DATABASE_URL=postgres://environment\n")) {
            try (Resolved resolved = project.builder().load()) {
                resolved.setAsSystemProperties();
                assertThat(System.getProperty("DATABASE_URL"))
                    .isNotEqualTo(previous)
                    .isEqualTo("postgres://environment");
            }
            finally {
                if (previous != null) {
                    System.setProperty("DATABASE_URL", previous);
                } else {
                    System.clearProperty("DATABASE_URL");
                }
            }
        }
    }

    @Test void testConformance() throws IOException {
        Path root = findRepositoryRoot();
        Path fixtures = root.resolve("conformance").resolve("fixtures");

        List<Path> directories;
        try (Stream<Path> stream = Files.list(fixtures)) {
            directories = stream.filter(Files::isDirectory)
                    .sorted(Comparator.comparing(Path::getFileName))
                    .collect(Collectors.toList());
        }

        assertThat(directories.size())
            .withFailMessage("Error: No conformance tests found!")
            .isGreaterThan(0);

        for (Path directory : directories) {
            String manifest = directory.resolve("secretspec.toml").toString();
            String provider = "dotenv://" + directory.resolve(".env");

            SecretSpec.Builder fixture = SecretSpec.builder()
                    .withPath(manifest)
                    .withProvider(provider)
                    .withReason("conformance");

            try (Resolved resolved = fixture.load()) {
                assertJsonEqual(
                        readString(directory.resolve("expected.json")),
                        MAPPER.writeValueAsString(canonicalResolved(resolved))
                );
            }

            try (Resolved noValues = fixture.withNoValues(true).load()) {
                assertJsonEqual(
                        readString(directory.resolve("expected_no_values.json")),
                        noValues.fieldsJson()
                );
            }

            ResolutionReport report = fixture.report();
            assertJsonEqual(
                    readString(directory.resolve("expected_report.json")),
                    MAPPER.writeValueAsString(canonicalReport(report))
            );
        }
    }

    private static ObjectNode canonicalResolved(Resolved resolved) {
        ObjectNode secrets = MAPPER.createObjectNode();

        for (Map.Entry<String, ResolvedSecret> entry : resolved.secrets().entrySet()) {
            String name = entry.getKey();
            ResolvedSecret secret = entry.getValue();

            String value = secret.asPath()
                    ? readString(Path.of(Objects.requireNonNull(secret.get(), name + " had no path")))
                    : secret.value();

            ObjectNode secretNode = MAPPER.createObjectNode();
            secretNode.put("value", value);
            secretNode.put("source", secret.source());
            secretNode.put("as_path", secret.asPath());

            secrets.set(name, secretNode);
        }

        ObjectNode root = MAPPER.createObjectNode();
        root.put("profile", resolved.profile());
        root.set("secrets", secrets);
        root.set("missing_required", MAPPER.createArrayNode());

        ArrayNode missingOptional = MAPPER.createArrayNode();
        for (String item : resolved.missingOptional()) {
            missingOptional.add(item);
        }
        root.set("missing_optional", missingOptional);

        return root;
    }

    private static ObjectNode canonicalReport(ResolutionReport report) {
        ObjectNode secrets = MAPPER.createObjectNode();

        for (SecretReport secret : report.secrets()) {
            ObjectNode node = MAPPER.createObjectNode();
            node.put("status", secret.status());
            node.put("required", secret.required());
            node.put("as_path", secret.asPath());
            node.put("generated", secret.generated());
            node.put("default_applied", secret.defaultApplied());
            node.put("source_provider", secret.sourceProvider() != null);

            secrets.set(secret.name(), node);
        }

        ObjectNode root = MAPPER.createObjectNode();
        root.put("profile", report.profile());
        root.set("secrets", secrets);

        return root;
    }

    private static Path findRepositoryRoot() {
        Path current = Path.of(System.getProperty("user.dir")).toAbsolutePath();
        while (current != null) {
            if (Files.exists(current.resolve("Cargo.toml")) && Files.exists(current.resolve("conformance"))) {
                return current;
            }
            current = current.getParent();
        }
        throw new IllegalStateException("could not find the SecretSpec repository root");
    }

    private static void assertJsonEqual(String expected, String actual) {
        JsonNode expectedNode = readJson(expected);
        JsonNode actualNode = readJson(actual);
        assertThat(actualNode)
            .withFailMessage(String.format("JSON mismatch%nactual:   %s%nexpected: %s", actual, expected))
            .isEqualTo(expectedNode);
    }

    // Java 11 IO Compatibility
    private static String readString(Path path) {
        try {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        }
        catch (IOException e) {
            throw new UncheckedIOException(e);
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

    private static JsonNode readJson(String text) {
        try {
            return MAPPER.readTree(text);
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
