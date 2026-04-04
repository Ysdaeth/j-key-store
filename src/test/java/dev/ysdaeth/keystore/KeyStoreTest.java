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
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

class KeyStoreTest {
    private static AtomicInteger storeCount = new AtomicInteger(0);
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
        String keystoreName = "test_"+storeCount.addAndGet(1);
        new KeyStore(testDir, keystoreName);
        boolean exist = Path.of(testDir.toString(), keystoreName).toFile().isDirectory();
        Assertions.assertTrue(exist,"Key store directory was not created");
    }

    @Test
    void save_shouldCreateKeyFile_fromSingleKey() throws Exception {
        String keyStoreName = "test_"+storeCount.addAndGet(1);
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
    void save_shouldCreateKeyFile_fromKeyPair() throws Exception {
        String keyStoreName = "test_" + storeCount.addAndGet(1);
        KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        String alias = StringGenerator.getInstance(GeneratorType.URL_SAFE).generate(16);
        char[] password = "password".toCharArray();

        KeyStore keyStore = new KeyStore(testDir, keyStoreName);
        keyStore.store(alias, keyPair, password);
        String expectedFilename = createFilename(alias);

        boolean exists = Path.of(testDir.toString(),keyStoreName,expectedFilename).toFile().isFile();
        Assertions.assertTrue(exists,"Key file does not exist after saving in the store");
    }

    @Test
    void getSecretKey_shouldReturnTheSameKey_whenExist() throws Exception {
        KeyStore keyStore = createStore();

        String alias = "alias";
        char[] password = "password".toCharArray();

        SecretKey expectedKey = KeyGenerator.getInstance("AES").generateKey();
        keyStore.store(alias, expectedKey, password);
        SecretKey actualKey = keyStore.getKey(alias,password).orElse(null);

        boolean bytesEqual = Arrays.equals(expectedKey.getEncoded(), actualKey.getEncoded() );
        boolean algorithmEquals = expectedKey.getAlgorithm().equals( actualKey.getAlgorithm() );
        Assertions.assertTrue(bytesEqual && algorithmEquals, "Key store should return the same key pair");
    }

    @Test
    void getKeyPair_shouldReturnTheSameKeyPair_whenExist() throws Exception {
        KeyStore keyStore = createStore();

        String alias = "alias";
        char[] password = "password".toCharArray();

        KeyPair expectedKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        keyStore.store(alias, expectedKeyPair, password);
        KeyPair actualKeyPair = keyStore.getKeyPair(alias,password).orElse(null);

        boolean bytesPrivateEqual = Arrays.equals(
                expectedKeyPair.getPrivate().getEncoded(),
                actualKeyPair.getPrivate().getEncoded()
        );
        boolean bytesPublicEqual = Arrays.equals(
                expectedKeyPair.getPublic().getEncoded(),
                actualKeyPair.getPublic().getEncoded()
        );

        boolean algorithmEquals = expectedKeyPair.getPrivate().getAlgorithm().equals(
                actualKeyPair.getPrivate().getAlgorithm()
        );
        Assertions.assertTrue( bytesPrivateEqual && algorithmEquals && bytesPublicEqual,
                "Key store should return the same key pair");
    }

    @Test
    void getKey_shouldThrowException_whenPasswordIsIncorrect() throws Exception {
        String alias = "alias";
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        char[] password = "password".toCharArray();
        char[] incorrectPassword = "incorrect".toCharArray();

        KeyStore keyStore = createStore();
        keyStore.store(alias,key, password);

        Assertions.assertThrowsExactly(UnrecoverableEntryException.class,
                ()->keyStore.getKey(alias,incorrectPassword)
        );
    }

    private KeyStore createStore() throws Exception{
        String name = "test_"+ storeCount.addAndGet(1);
        return new KeyStore(testDir,name);
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
        return format.formatHex(hash) + ".key";
    }

}