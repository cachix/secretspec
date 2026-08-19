package org.cachix.secretspec;

import java.util.List;
import java.util.stream.StreamSupport;

import static java.util.stream.Collectors.toUnmodifiableList;


/**
 * Required secrets that could not be resolved.
 */
public final class MissingRequiredException extends SecretSpecException {

    MissingRequiredException(Iterable<String> missing) {
        super("missing_required", buildMessage(missing));
        var missingStream = StreamSupport.stream(missing.spliterator(), false);
        this.missing = missingStream.collect(toUnmodifiableList());
    }

    /**
     * The unresolved required secret names.
     */
    private final List<String> missing;

    public List<String> missing() {
        return missing;
    }

    private static String buildMessage(Iterable<String> missing) {
        return "missing required secret(s): " + String.join(", ", missing);
    }
}
