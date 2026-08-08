import org.cachix.secretspec.SecretSpec;

public class Report {

    public static void main() {
        var report = SecretSpec.builder()
            .withProfile("production")
            .withReason("deployment preflight")
            .report();
        
        for (var secret : report.getSecrets())
            System.out.println(secret.getName() + ": " + secret.getStatus());
    }
}
