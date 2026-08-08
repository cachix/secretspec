package org.cachix.secretspec;

import com.sun.jna.Library;
import com.sun.jna.Pointer;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;


final class Native {

    private static final String LIBRARY_NAME = "secretspec_ffi";
    private static final String MUSL_LIBRARY_NAME = "secretspec_musl_ffi";
    private static final SecretSpecFFI BINDINGS;

    interface SecretSpecFFI extends Library {
        Pointer secretspec_resolve(String requestJson);
        void secretspec_free(Pointer pointer);
        Pointer secretspec_abi_version();
    }

    static {
        try {
            String libPath = findLibraryPath();
            if (libPath != null) {
                BINDINGS = com.sun.jna.Native.load(libPath, SecretSpecFFI.class);
            } else if (shouldUseMusl()) {
                /*
                 * JNA does not distinguish between musl and glibc.
                 * To ship two binaries targeting the same linux-arch in the Jar we must rename one of them.
                 * We rename the musl library.
                 */
                BINDINGS = com.sun.jna.Native.load(MUSL_LIBRARY_NAME, SecretSpecFFI.class);
            } else {
                BINDINGS = com.sun.jna.Native.load(LIBRARY_NAME, SecretSpecFFI.class);
            }
        } catch (UnsatisfiedLinkError error) {
            throw new SecretSpecException("load", error.getMessage(), error);
        }
    }

    private Native() {
        // No instances.
    }

    static String resolve(String requestJson) {
        Pointer responsePtr = Pointer.NULL;
        try {
            responsePtr = BINDINGS.secretspec_resolve(requestJson);
            if (responsePtr == Pointer.NULL) {
                throw new SecretSpecException("ffi", "secretspec_resolve returned null");
            }

            String result = responsePtr.getString(0, "UTF-8");
            if (result == null) {
                throw new SecretSpecException("ffi", "secretspec_resolve returned invalid UTF-8");
            }
            return result;
        } catch (UnsatisfiedLinkError error) {
            throw new SecretSpecException("load", error.getMessage(), error);
        } finally {
            if (responsePtr != Pointer.NULL) {
                BINDINGS.secretspec_free(responsePtr);
            }
        }
    }

    static String abiVersion() {
        try {
            Pointer pointer = BINDINGS.secretspec_abi_version();
            if (pointer == Pointer.NULL) {
                throw new SecretSpecException("ffi", "secretspec_abi_version returned null");
            }
            String version = pointer.getString(0, "UTF-8");
            if (version == null) {
                throw new SecretSpecException("ffi", "secretspec_abi_version returned null");
            }
            return version;
        } catch (UnsatisfiedLinkError error) {
            throw new SecretSpecException("load", error.getMessage(), error);
        }
    }

    private static String findLibraryPath() {
        String explicitPath = System.getenv("SECRETSPEC_FFI_LIB");
        if (explicitPath != null && !explicitPath.trim().isEmpty()) {
            return explicitPath;
        }

        String os = System.getProperty("os.name").toLowerCase();
        String fileName;
        if (os.contains("win")) {
            fileName = "secretspec_ffi.dll";
        } else if (os.contains("mac")) {
            fileName = "libsecretspec_ffi.dylib";
        } else {
            fileName = "libsecretspec_ffi.so";
        }

        String[] starts = new String[]{
                System.getProperty("user.dir"),
                Native.class.getProtectionDomain().getCodeSource() != null &&
                        Native.class.getProtectionDomain().getCodeSource().getLocation() != null
                        ? new File(Native.class.getProtectionDomain().getCodeSource().getLocation().getPath()).getParent()
                        : null
        };

        for (String start : starts) {
            if (start == null) continue;

            File directory = new File(start);
            while (directory != null) {
                String newest = null;
                long newestTime = Long.MIN_VALUE;

                for (String profile : new String[]{"release", "debug"}) {
                    File candidate = new File(directory, "target" + File.separator + profile + File.separator + fileName);
                    if (candidate.exists() && candidate.lastModified() >= newestTime) {
                        newest = candidate.getAbsolutePath();
                        newestTime = candidate.lastModified();
                    }
                }

                if (newest != null) {
                    return newest;
                }

                directory = directory.getParentFile();
            }
        }

        return null;
    }

    private static boolean shouldUseMusl() {
        String os = System.getProperty("os.name").toLowerCase(Locale.ROOT);
        if (!os.contains("linux")) {
            return false;
        }

        // Try running ldd
        try {
            ProcessBuilder pb = new ProcessBuilder("ldd", "--version");
            Process process = pb.start();
            
            InputStream[] inputStreams = {
                process.getInputStream(),
                process.getErrorStream(),
            };
            for (var inputStream : inputStreams) {
                try (
                    var reader = new BufferedReader(new InputStreamReader(inputStream));
                    var lines = reader.lines();
                ) {
                    var found = lines
                        .map(line -> line.toLowerCase(Locale.ROOT))
                        .anyMatch(line -> line.contains("musl"));
                    if (found) {
                        return true;
                    }
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
