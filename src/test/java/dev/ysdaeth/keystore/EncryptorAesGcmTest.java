package dev.ysdaeth.keystore;

import io.github.ysdaeth.utils.array.ArrayMatcher;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Random;


class EncryptorAesGcmTest {

    @Test
    void encrypt_shouldNotContainRawData() throws Exception{
        EncryptorAesGcm encryptor = new EncryptorAesGcm();

        Key key = KeyGenerator.getInstance("AES").generateKey();
        Random random = new SecureRandom();
        for(int i = 0; i<300_000; i++){
            int randomSize = random.nextInt(1<<14)+4;
            byte[] secret = new byte[randomSize];
            random.nextBytes(secret);
            byte[] encrypted  = encryptor.encrypt(secret, key);
            Assertions.assertNotNull(encrypted);
            Assertions.assertNotEquals(0,encrypted.length,"Returned encrypted byte array must not be empty array.");
            int index = ArrayMatcher.indexOfSubarray(encrypted, secret);
            Assertions.assertEquals(-1,index,"Unencrypted data found at index: "+ index);
        }
    }

    @Test
    void encrypt_shouldBeReversibleOperation() throws Exception {

        EncryptorAesGcm encryptor = new EncryptorAesGcm();

        Key key = KeyGenerator.getInstance("AES").generateKey();
        Random random = new SecureRandom();
        for(int i = 0; i<300_000; i++){
            int randomSize = random.nextInt(1<<14)+4;
            byte[] expected = new byte[randomSize];
            random.nextBytes(expected);
            byte[] encrypted  = encryptor.encrypt(expected, key);
            byte[] actual = encryptor.decrypt(encrypted,key);
            Assertions.assertArrayEquals(expected,actual);
        }
    }

    @Test
    void decrypt_shouldThrowExceptionWhenKeyIsIncorrect() throws Exception {
        EncryptorAesGcm aesGcm = new EncryptorAesGcm();
        byte[] expected = "secret".getBytes();
        Key key = KeyGenerator.getInstance("AES").generateKey();
        byte[] encrypted = aesGcm.encrypt(expected, key);

        Key wrongKey = KeyGenerator.getInstance("AES").generateKey();
        Assertions.assertThrowsExactly(AEADBadTagException.class,()->{
            aesGcm.decrypt(encrypted,wrongKey);
        });
    }

}