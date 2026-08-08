import org.cachix.secretspec.SecretSpec;

public class QuickStart {

    public static void main() {
        try(var resolved = SecretSpec.builder()
            .withProvider("keyring://")
            .withProfile("production")
            .withReason("boot web app")
            .load()
        ) {
            System.out.println(resolved.getProvider() + " (" + resolved.getProfile() + ")");
            var secrets = resolved.getSecrets();
            System.out.println(secrets.get("DATABASE_URL").get());
            resolved.setAsSystemProperties();
        }    
    }
}
