package dev.ysdaeth.keystore;

import io.github.ysdaeth.utils.generator.string.GeneratorType;
import io.github.ysdaeth.utils.generator.string.StringGenerator;
import org.junit.jupiter.api.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.HexFormat;
import java.util.stream.Stream;

import static dev.ysdaeth.keystore.KeyStore.KEY_FILE_EXTENSION;

class KeyStoreTest {
    final static Path testDir = Path.of("src", "test", "resources", "temp", "keystoreTest");

    @BeforeAll
    static void setup() throws Exception {
        Files.createDirectories(testDir);
        try(Stream<Path> pathStream = Files.walk(testDir)){
            pathStream.map(Path::toFile).forEach(File::delete);
        }
    }

    @Test
    void constructor_shouldCreateDirectory() throws Exception {
        String keystoreName = "ctor_shouldCreateDir";
        new KeyStore(testDir, keystoreName);
        boolean exist = Path.of(testDir.toString(), keystoreName).toFile().isDirectory();
        Assertions.assertTrue(exist,"Key store directory was not created");
    }

    @Test
    void save_shouldCreateKeyFile_fromSymmetricKey() throws Exception {
        String keyStoreName = "shouldCreateFile_fromSymmetric";
        KeyStore keyStore = new KeyStore(testDir, keyStoreName);

        SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
        String alias = StringGenerator.getInstance(GeneratorType.URL_SAFE).generate(16);
        char[] password = "password".toCharArray();

        keyStore.store(alias, secretKey, password);
        String expectedFilename = createFilename(alias);

        boolean exists = Path.of(testDir.toString(),keyStoreName,expectedFilename).toFile().isFile();
        Assertions.assertTrue(exists,"Key file does not exist after saving in the store");
    }

    @Test
    void getSecretKey_shouldReturnEqualKey() throws Exception { // X fix name, split bytes and alg to 2 tests
        KeyStore keyStore = createStore("getSecretKey_shouldEqual_onGet");

        String alias = "alias";
        char[] password = "password".toCharArray();

        SecretKey expectedKey = KeyGenerator.getInstance("AES").generateKey();
        keyStore.store(alias, expectedKey, password);
        SecretKey actualKey = keyStore.getSecretKey(alias,password).orElse(null);

        Assertions.assertNotNull(actualKey,"Key should be returend from the key store");

        byte[] expectedBytes = expectedKey.getEncoded();
        byte[] actualBytes = actualKey.getEncoded();
        Assertions.assertArrayEquals(
                expectedBytes, actualBytes, "Key bytes should be equal");

        String expectedAlgorithm = expectedKey.getAlgorithm();
        String actualAlgorithm = actualKey.getAlgorithm();

        Assertions.assertEquals(
                expectedAlgorithm, actualAlgorithm, "Key algorithm should be equal");
    }

    @Test
    void getSecretKey_shouldThrowException_whenPasswordIsIncorrect() throws Exception {
        String alias = "alias";
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        char[] password = "password".toCharArray();

        KeyStore keyStore = createStore("getSecretKey_shouldThrow_onWrongPwd");
        keyStore.store(alias,key, password);

        char[] incorrectPassword = "incorrect".toCharArray();
        Assertions.assertThrowsExactly(UnrecoverableEntryException.class,
                ()->keyStore.getSecretKey(alias,incorrectPassword)
        );
    }

    @Test
    void getSecretKey_shouldThrowKeySymmetryException_whenKeyIsAsymmetric() throws Exception {
        String alias = "alias";
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        char[] password = "password".toCharArray();

        KeyStore keyStore = createStore("getSecretKey_shouldThrow_onWrongSymmetry");
        keyStore.store(alias,key, password);

        Assertions.assertThrows(KeySymmetryException.class,()->{
            keyStore.getKeyPair(alias,password);
        },"Should throw exception when key symmetry is incorrect");
    }

    @Test
    void getKeyPair_shouldThrowKeySymmetryException_whenEntryIsSymmetric() throws Exception {
        String alias = "alias";
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        char[] password = "password".toCharArray();

        KeyStore keyStore = createStore("getKeyPair_shouldThrow_onWrongSymmetry");
        keyStore.store(alias, pair, password);

        Assertions.assertThrows(KeySymmetryException.class,()->{
            keyStore.getSecretKey(alias,password);
        },"Should throw exception when key symmetry is incorrect");

    }

    @Test
    void getKeyPair_shouldReturnEqualKeyPair() throws Exception {
        KeyStore keyStore = createStore("getKeyPair_shouldBeEqual_onGet");

        String alias = "alias";
        char[] password = "password".toCharArray();

        KeyPair expectedKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        keyStore.store(alias, expectedKeyPair, password);
        KeyPair actualKeyPair = keyStore.getKeyPair(alias,password).orElse(null);

        Assertions.assertNotNull(actualKeyPair,"Key store should return key pair");

        Assertions.assertArrayEquals(
                expectedKeyPair.getPrivate().getEncoded(),
                actualKeyPair.getPrivate().getEncoded(),
                "Private key bytes should be equal"
        );
        Assertions.assertArrayEquals(
                expectedKeyPair.getPublic().getEncoded(),
                actualKeyPair.getPublic().getEncoded(),
                "Public key bytes should be equal"
        );
        Assertions.assertEquals(
                expectedKeyPair.getPrivate().getAlgorithm(),
                actualKeyPair.getPrivate().getAlgorithm(),
                "Key algorithm should be the same"
        );
    }

    @Test
    void getKeyPair_shouldThrowException_whenPasswordDoesNotMatch() throws Exception {
        String alias = "alias";
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        char[] password = "password".toCharArray();

        KeyStore keyStore = createStore("getKeyPair_shouldThrow_onIncorrectPwd");
        keyStore.store(alias, pair, password);

        Assertions.assertThrowsExactly(UnrecoverableEntryException.class,
                ()->keyStore.getKeyPair(alias, "incorrect".toCharArray())
        );
    }


    @Test
    void contains_shouldReturnTrue_whenEntryExists() throws Exception {
        String alias = "alias";
        KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        char[] password = "password".toCharArray();

        KeyStore keyStore = createStore("contains_shouldReturnTrue");
        keyStore.store(alias, pair, password);

        boolean containsKey = keyStore.contains(alias);
        Assertions.assertTrue(containsKey,"Should return true when key exists");
    }

    @Test
    void contains_shouldReturnFalse_whenEntryDoesNotExists() throws Exception {
        String alias = "does-not-exist";
        KeyStore keyStore = createStore("contains_shouldReturnFalse");

        Assertions.assertFalse(keyStore.contains(alias),
                "Should return false when entry does not exist");
    }

    @Test
    void delete_shouldDeleteOnlyOneKeyFile() throws Exception {
        String keyStoreName = "delete_shouldDeleteSingleFile";
        KeyStore keyStore = new KeyStore(testDir, keyStoreName);

        SecretKey key = KeyGenerator.getInstance("AES").generateKey();

        String toRemoveAlias = "delete_shouldDeleteKeyFile";
        Path toRemovePath = Path.of(testDir.toString(), keyStoreName, createFilename(toRemoveAlias));
        keyStore.store(toRemoveAlias, key, "password".toCharArray());

        String toNotRemoveAlias = "not_removed_alias";
        Path toNotRemovePath = Path.of(testDir.toString(), keyStoreName, createFilename(toNotRemoveAlias));
        keyStore.store(toNotRemoveAlias, key, "password".toCharArray());

        keyStore.delete(toRemoveAlias);

        boolean removedNotExists = Files.exists(toRemovePath);
        Assertions.assertFalse(removedNotExists, "Key file was not removed");

        boolean notRemovedExists = Files.exists(toNotRemovePath);
        Assertions.assertTrue(notRemovedExists, "Incorrect key file was removed");
    }

    @Test
    void getPrivateKey_shouldReturnPrivateKey() throws Exception{
        String keyStoreName = "shouldReturnPrivateKey";
        String alias ="alias";
        KeyStore keyStore = new KeyStore(testDir, keyStoreName);

        char[] password = "password".toCharArray();
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        keyStore.store(alias, keyPair, password);

        Assertions.assertDoesNotThrow(()->{
            keyStore.getPrivateKey(alias, password);
        },"Get private key should not throw exception");

        PrivateKey privateKey = keyStore.getPrivateKey(alias, password).orElse(null);
        Assertions.assertNotNull(privateKey,"Should return private key");
    }

    @Test
    void getPublicKey_shouldReturnPublicKey() throws Exception{
        String keyStoreName = "shouldReturnPublicKey";
        String alias ="alias";
        KeyStore keyStore = new KeyStore(testDir, keyStoreName);

        char[] password = "password".toCharArray();
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        keyStore.store(alias, keyPair, password);

        Assertions.assertDoesNotThrow(()->{
            keyStore.getPublicKey(alias);
        },"Get public key should not throw exception");

        PublicKey publicKey = keyStore.getPublicKey(alias).orElse(null);
        Assertions.assertNotNull(publicKey,"Should return public key");
    }

    private KeyStore createStore(String storeNamePrefix) throws Exception {
        return new KeyStore(testDir, storeNamePrefix);
    }

    private static String createFilename(String alias){
        byte[] byteAlias = alias.getBytes(StandardCharsets.UTF_8);
        byte[] hash;

        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(byteAlias);
        }catch (Exception e){
            throw new RuntimeException("Failed to create filename. "+e.getMessage(),e);
        }

        HexFormat format = HexFormat.of();
        return format.formatHex(hash) + KEY_FILE_EXTENSION;
    }

}