package org.cachix.secretspec;


/**
 * A manifest, provider, policy, native-loading, or wire-format failure.
 */
public class SecretSpecException extends RuntimeException {

    public SecretSpecException(String kind, String message) {
        super(message + " (kind: " + kind + ")");
        this.kind = kind;
    }

    public SecretSpecException(String kind, String message, Throwable cause) {
        super(message + " (kind: " + kind + ")", cause);
        this.kind = kind;
    }

    /** 
     * A stable machine-readable error category.
     */
    private final String kind;

    public String getKind() {
        return kind;
    }   
}
