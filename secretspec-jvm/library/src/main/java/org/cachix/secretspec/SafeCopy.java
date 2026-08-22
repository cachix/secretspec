package org.cachix.secretspec;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static java.util.Collections.unmodifiableList;
import static java.util.Collections.unmodifiableMap;


class SafeCopy {

    static <K, V> Map<K, V> safeCopyOf(Map<K, V> source) {
        // Map.copyOf does not accept null values, we must copy ourselves.
        if (source == null) return null;
        var copy = new HashMap<K, V>(source.size());
        for (var entry : source.entrySet()) {
            copy.put(entry.getKey(), entry.getValue());
        }
        return unmodifiableMap(copy);
    }

    static <E> List<E> safeCopyOf(Collection<E> source) {
        // List.copyOf does not accept null values, we must copy ourselves.
        if (source == null) return null;
        var copy = new ArrayList<E>(source.size());
        for (E element : source) {
            copy.add(element);
        }
        return unmodifiableList(copy);
    }

    private SafeCopy() {
        // No instances.
    }
}
