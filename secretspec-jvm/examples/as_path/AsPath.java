
import org.cachix.secretspec.SecretSpec;

public class AsPath {

    public static void main() {
        try(var resolved = SecretSpec.builder().withReason("TLS boot").load()) {
            var secrets = resolved.getSecrets();
            var certificatePath = secrets.get("TLS_CERT").get();
            // Use the certificate before resolved is disposed.
            System.out.println(certificatePath);
        }
    }
}
