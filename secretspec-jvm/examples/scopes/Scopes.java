import org.cachix.secretspec.SecretSpec;

public class Scopes {

    public static void main() {
       try(var resolved = SecretSpec.builder().withScope("api").load()) {

       }    
    }
}
