import org.cachix.secretspec.SecretSpec;
import io.quicktype.Converter;

public class TypedAccess {

    public static void main() {
        try(var resolved = SecretSpec.builder().load()) {
            AppSecrets typed = Converter.fromJsonString(resolved.fieldsJson());
            System.out.println(typed.getDatabaseURL());
        }    
    }
}
