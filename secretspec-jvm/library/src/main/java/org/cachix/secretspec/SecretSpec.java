package org.cachix.secretspec;


/**
 * Entry point for the SecretSpec JVM SDK.
 */
public class SecretSpec {

    /**
     * Starts a fluent resolution builder.
     * @return the fluent builder
     */
    public static SecretSpecBuilder builder() {
        return new SecretSpecBuilder();   
    }

    /**
     * The ABI version reported by the loaded native resolver.
     * @return the ABI version
     */
    public static String abiVersion() { return Native.abiVersion(); };

    private SecretSpec() {
        // No instances.
    }
}
