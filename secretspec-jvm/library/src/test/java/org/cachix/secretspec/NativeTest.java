package org.cachix.secretspec;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;


class NativeTest {

    @Test
    void abi_version_should_be_defined() {
        String version = Native.abiVersion();

        assertNotNull(version);
        assertFalse(version.isBlank());
    }
}
