package dev.ysdaeth.keystore;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Map;

class SecureKeyEntrySerializerTest {

    @Test
    void deserialize_shouldReturnAlias_whenSymmetricKey(){
        String alias = "Key-alias-aes";
        SecuredKeyEntry expected = createEntrySymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertEquals(expected.alias(), actual.alias(),"Alias should not be changed");
    }

    @Test
    void deserialize_shouldReturnAlias_whenAsymmetricKeys(){
        String alias = "Key-alias-rsa";
        SecuredKeyEntry expected = createEntryAsymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertEquals(expected.alias(), actual.alias(),"Alias should not be changed");
    }

    @Test
    void deserialize_shouldReturnAlgorithm_whenSymmetricKey(){
        String alias = "Key-alias-aes";
        SecuredKeyEntry expected = createEntrySymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertEquals(expected.keyAlg(), actual.keyAlg(),"Algorithm should not be changed");
    }

    @Test
    void deserialize_shouldReturnAlgorithm_whenAsymmetricKeys(){
        String alias = "Key-alias-rsa";
        SecuredKeyEntry expected = createEntryAsymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertEquals(expected.keyAlg(), actual.keyAlg(), "algorithm should not be changed");
    }

    @Test
    void deserialize_shouldReturnSecretKeyBytes_whenSymmetricKey(){
        for(int i=0; i< 1_000_000; i++){
            String alias = "Key-alias-aes";
            SecuredKeyEntry expected = createEntrySymmetric(alias);

            SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                    SecureKeyEntrySerializer.serialize(expected) );

            Assertions.assertArrayEquals(expected.key(), actual.key(), "Secret key bytes should not be changed");
        }
    }

    @Test
    void deserialize_shouldReturnPrivateKeyBytes_whenAsymmetricKeys(){
        for(int i=0; i< 1_000_000; i++){
            String alias = "Key-alias-rsa";
            SecuredKeyEntry expected = createEntryAsymmetric(alias);

            SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                    SecureKeyEntrySerializer.serialize(expected) );

            Assertions.assertArrayEquals(expected.key(), actual.key(), "Private key byes should not be changed");
        }
    }

    @Test
    void deserialize_shouldReturnNullPublicKeyBytes_whenSymmetricKey(){
        String alias = "Key-alias-rsa";
        SecuredKeyEntry expected = createEntrySymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertNull(actual.pubKey(), "public key bytes should be null");
    }

    @Test
    void deserialize_shouldReturnPublicKeyBytes_whenAsymmetricKeys(){
        String alias = "Key-alias-rsa";
        SecuredKeyEntry expected = createEntryAsymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertArrayEquals(expected.pubKey(), actual.pubKey(), "Public key byes should not be changed");
    }

    @Test
    void deserialize_shouldReturnProtectionParams_whenAsymmetricKeys(){
        String alias = "Key-alias-rsa";
        SecuredKeyEntry expected = createEntryAsymmetric(alias);

        SecuredKeyEntry actual = SecureKeyEntrySerializer.deserialize(
                SecureKeyEntrySerializer.serialize(expected) );

        Assertions.assertEquals(expected.kdfParams(), actual.kdfParams(), "Protection params should not be changed");
    }

    private SecuredKeyEntry createEntrySymmetric(String alias){
        byte[] expectedPrivateKey = "key".getBytes();
        Map<String,String> protectionParams = Map.of(
                "type","PBEKDF2","salt","randomSalt"
        );
        return new SecuredKeyEntry(alias, "AES", expectedPrivateKey, "KDF-ALG", protectionParams);
    }

    private SecuredKeyEntry createEntryAsymmetric(String alias){
        SecureRandom random = new SecureRandom();
        int keysLength = random.nextInt(128)+1;
        byte[] expectedPrivateKey = new byte[keysLength];
        byte[] expectedPublicKey = new byte[keysLength];

        random.nextBytes(expectedPrivateKey);
        random.nextBytes(expectedPublicKey);

        Map<String,String> protectionParams = Map.of(
                "type","PBEKDF2","salt","randomSalt"
        );

        return new SecuredKeyEntry(alias, "RSA", expectedPrivateKey, expectedPublicKey, "KFD-ALG", protectionParams);
    }
}