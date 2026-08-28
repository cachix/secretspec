package org.cachix.secretspec;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static java.util.Comparator.comparingLong;


final class NativeResolver {

    interface SecretSpecFFI extends Library {
        Pointer secretspec_resolve(String requestJson);
        void secretspec_free(Pointer pointer);
        Pointer secretspec_abi_version();
    }

    private static volatile SecretSpecFFI resolverInstance;

    private static SecretSpecFFI getResolverInstance() {
        // Double-locking idiom.
        if (resolverInstance == null) {
            synchronized (NativeResolver.class) {
                if (resolverInstance == null) {
                    resolverInstance = loadResolver();
                }
            }
        }
        return resolverInstance;
    }

    private static final Map<String, Object> OPTIONS = Map.of(
        Library.OPTION_STRING_ENCODING, "UTF-8"
    );

    private static SecretSpecFFI loadResolver() {
        try {
            Path libPath = findLibraryPath();
            if (libPath != null) {
                return Native.load(libPath.toString(), SecretSpecFFI.class, OPTIONS);
            } else if (shouldUseMusl()) {
                /*
                * JNA does not distinguish between musl and glibc.
                * To ship two binaries targeting the same linux-arch in the Jar we must rename one of them.
                * We rename the musl library.
                */
                return Native.load("secretspec_musl", SecretSpecFFI.class, OPTIONS);
            } else {
                return Native.load("libsecretspec", SecretSpecFFI.class, OPTIONS);
            }
        } catch (UnsatisfiedLinkError error) {
            throw new SecretSpecException("load", error.getMessage(), error);
        }
    }

    private NativeResolver() {
        // No instances.
    }

    static String resolve(String requestJson) {
        Pointer responsePtr = Pointer.NULL;
        var resolver = getResolverInstance();
        try {
            responsePtr = resolver.secretspec_resolve(requestJson);
            if (responsePtr == Pointer.NULL) {
                throw new SecretSpecException("ffi", "secretspec_resolve returned null");
            }

            String result = responsePtr.getString(0, "UTF-8");
            if (result == null) {
                throw new SecretSpecException("ffi", "secretspec_resolve returned invalid UTF-8");
            }
            return result;
        } finally {
            if (responsePtr != Pointer.NULL) {
                resolver.secretspec_free(responsePtr);
            }
        }
    }

    static String abiVersion() {
        var resolver = getResolverInstance();
        Pointer pointer = resolver.secretspec_abi_version();
        if (pointer == Pointer.NULL) {
            throw new SecretSpecException("ffi", "secretspec_abi_version returned null");
        }
        String version = pointer.getString(0, "UTF-8");
        if (version == null) {
            throw new SecretSpecException("ffi", "secretspec_abi_version returned null");
        }
        return version;
    }

    private static Path findLibraryPath() {
        // Only allow this method to run during development
        if (isRunningFromJar()) return null;

        String explicitPath = System.getenv("SECRETSPEC_FFI_LIB");
        if (explicitPath != null && !explicitPath.trim().isEmpty()) {
            return Path.of(explicitPath);
        }

        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        String[] fileNames;
        if (os.contains("win")) {
            fileNames = new String[] { "libsecretspec.dll", "secretspec.dll" };
        } else if (os.contains("mac")) {
            fileNames = new String[] { "libsecretspec.dylib" };
        } else {
            fileNames = new String[] { "libsecretspec.so" };
        }

        Path[] starts = new Path[] {
                Path.of(System.getProperty("user.dir")),
                getCodeSourceLocation()
                    .map(URL::getPath)
                    .map(File::new)
                    .map(File::getParent)
                    .map(Path::of)
                    .orElse(null)
        };
        for (Path start : starts) {
            if (start == null) continue;
            var directory = start;
            while (directory != null) {
                var target = directory.resolve("target");
                var newest = Stream.of("release", "debug")
                    .flatMap(profile -> Stream.of(fileNames)
                        .map(fileName -> target.resolve(Path.of(profile, fileName))))
                    .filter(Files::exists)
                    .max(comparingLong(path -> path.toFile().lastModified()))
                    .map(Path::toAbsolutePath);
                if (newest.isPresent()) {
                    return newest.get();
                }
                directory = directory.getParent();
            }
        }
        return null;
    }

    private static Optional<URL> getCodeSourceLocation() {
        return Optional.of(SecretSpec.class)
                .map(Class::getProtectionDomain)
                .map(ProtectionDomain::getCodeSource)
                .map(CodeSource::getLocation);
    }

    private static boolean isRunningFromJar() {
        Predicate<String> startsWithJar = url -> url.startsWith("jar:");
        Predicate<String> startsWithFile = url -> url.startsWith("file:");
        Predicate<String> endsWithJar = url -> url.endsWith(".jar");
        var isRunningFromJar = getCodeSourceLocation()
                .map(URL::toString)
                .filter(startsWithJar.or(startsWithFile.and(endsWithJar)))
                .isPresent();
        return isRunningFromJar;
    }

    private static boolean shouldUseMusl() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        if (!os.contains("linux")) {
            return false;
        }

        // Try running ldd
        try {
            ProcessBuilder pb = new ProcessBuilder("ldd", "--version");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (
                var reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                var lines = reader.lines();
            ) {
                var found = lines
                    .map(line -> line.toLowerCase(Locale.ROOT))
                    .anyMatch(line -> line.contains("musl"));
                if (found) {
                    return true;
                }
            }
        } catch (IOException ignored) {
        }

        // Try finding musl-specific files
        Path[] searchDirectories = {
            Path.of("/lib"),
            Path.of("/usr/lib"),
            Path.of("/lib64"),
            Path.of("/usr/lib64")
        };
        for (Path candidate : searchDirectories) {
            if (Files.exists(candidate) && Files.isDirectory(candidate)) {
                try (var directoryContents = Files.list(candidate)) {
                    boolean found = directoryContents
                        .map(Path::getFileName)
                        .map(Path::toString)
                        .anyMatch(
                            name -> name.startsWith("ld-musl-")
                            && name.endsWith(".so.1")
                        );
                    if (found) {
                        return true;
                    }
                } catch (IOException ignored) {
                }
            }
        }
        return false;
    }
}
