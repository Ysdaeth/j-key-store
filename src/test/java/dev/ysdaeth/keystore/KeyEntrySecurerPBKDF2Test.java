package dev.ysdaeth.keystore;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;

class KeyEntrySecurerPBKDF2Test {

    @Test
    void encrypt_shouldBeReversible() throws Exception {
        KeyEntrySecurerPBKDF2 securerPBKDF2 = new KeyEntrySecurerPBKDF2( new EncryptorAesGcm() );
        byte[] encoded = new byte[16];
        new SecureRandom().nextBytes(encoded);
        char[] password = "password".toCharArray();

        Key key = new SecretKeySpec(encoded, "AES");
        KeyEntry expected = new KeyEntry("alias1","AES", key.getEncoded());
        SecuredKeyEntry securedKeyEntry = securerPBKDF2.encrypt(expected, password);
        KeyEntry actual = securerPBKDF2.decrypt(securedKeyEntry,password);

        byte[] expectedBytes = expected.key();
        byte[] actualBytes = actual.key();
        Assertions.assertArrayEquals(expectedBytes, actualBytes,"Key bytes are different after decryption");
        Assertions.assertEquals(expected.alias(),actual.alias(),"Key alias has changed after decryption");
    }
}