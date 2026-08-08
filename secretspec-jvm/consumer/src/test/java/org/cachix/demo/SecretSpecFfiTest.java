package org.cachix.demo;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

import org.cachix.secretspec.SecretSpec;


class SecretSpecFfiTest {

    @Test
    void testJnaBinding() {
        assertThat(SecretSpec.abiVersion())
            .withFailMessage("Cannot get ABI version from JNA library. ")
            .isNotNull();
    }
}