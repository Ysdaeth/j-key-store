package dev.ysdaeth.keystore;


import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

class KeyRevitalizerTest {

    @Test
    void revitalizeKeyPair_shouldRevitalizeRSASymmetricKeyPair() throws Exception {
        testAlgorithm("RSA", 2048);
    }

    @Test
    void revitalizeKeyPair_shouldRevitalizeDSASymmetricKeyPair() throws Exception {
        testAlgorithm("DSA", 2048);
    }

    @Test
    void shouldRevitalizeECKeyPair() throws Exception {
        testAlgorithm("EC", 256);
    }

    private void testAlgorithm(String algorithm, int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(keySize);
        KeyPair original = kpg.generateKeyPair();

        KeyPair restored = KeyRevitalizer.revitalizeKeyPair(
                original.getPrivate().getEncoded(),
                original.getPublic().getEncoded(),
                algorithm
        );

        assertNotNull(restored);
        assertArrayEquals(original.getPrivate().getEncoded(), restored.getPrivate().getEncoded());
        assertArrayEquals(original.getPublic().getEncoded(), restored.getPublic().getEncoded());
    }

    @Test
    void revitalizeKeyPair_shouldThrowOnNullKeys() {
        assertThrows(IllegalArgumentException.class, () ->
                KeyRevitalizer.revitalizeKeyPair(null, null, "RSA")
        );
    }

    @Test
    void revitalizeSymmetricKeyPair_shouldThrowOnInvalidAlgorithm() {
        assertThrows(NoSuchAlgorithmException.class, () ->
                KeyRevitalizer.revitalizeKeyPair(new byte[]{1}, new byte[]{1}, "INVALID")
        );
    }

    @Test
    void revitalizeKeyPair_shouldThrowOnInvalidSymmetricKeySpec() {
        assertThrows(InvalidKeySpecException.class, () ->
                KeyRevitalizer.revitalizeKeyPair(new byte[]{1,2,3}, new byte[]{4,5,6}, "RSA")
        );
    }

}