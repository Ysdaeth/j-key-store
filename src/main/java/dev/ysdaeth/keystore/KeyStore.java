package dev.ysdaeth.keystore;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.util.HexFormat;
import java.util.Optional;

public class KeyStore {
    private static final String KEY_FILE_EXTENSION = ".entry";

    private final Path keyStorePath;
    KeySecurerPBKDF2 keySecurerPBKDF2;

    public KeyStore(Path keyStorePath, String keyStoreName) throws IOException {
        this.keyStorePath = Path.of(keyStorePath.toString(), keyStoreName);
        Files.createDirectories(this.keyStorePath);
        keySecurerPBKDF2 = new KeySecurerPBKDF2();
    }

    public void store(String alias, SecretKey key, char[] password) throws IORuntimeException {
        KeyEntry entry = new KeyEntry(alias, key.getAlgorithm(),key.getEncoded());

        try {
            storeKeyEntry(entry, password);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save the keyEntry." + e.getMessage(), e);
        }
    }

    public void store(String alias, KeyPair keys, char[] password) throws IORuntimeException {
        PrivateKey privateKey = keys.getPrivate();
        PublicKey publicKey = keys.getPublic();

        KeyEntry entry = new KeyEntry(alias, privateKey.getAlgorithm(), privateKey.getEncoded(), publicKey.getEncoded());
        try {
            storeKeyEntry(entry, password);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save the keyEntry." + e.getMessage(), e);
        }
    }

    private void storeKeyEntry(KeyEntry entry, char[] password) throws IOException {
        SecuredKeyEntry secured = keySecurerPBKDF2.secureEntry(entry, password);
        String content = SecureKeyEntrySerializer.serialize(secured);
        String filename = createFilename(entry.alias());

        Path filePath = Path.of(keyStorePath.toString(),filename);
        Files.writeString(filePath,content);
    }

    /**
     * @param alias alias assigned to the key pair
     * @param password password set for entry
     * @return key pair if exist
     * @throws UnrecoverableEntryException when password does not match.
     * @throws IORuntimeException when entry exists, but failed to read file from the drive
     */
    public Optional<SecretKey> getKey(String alias, char[] password)
            throws IORuntimeException, UnrecoverableEntryException {

        KeyEntry entry = loadKeyEntry(alias, password).orElse(null);
        if(entry == null) return Optional.empty();

        SecretKey key = KeyRevitalizer.revitalizeKey(entry.key(), entry.keyAlg());
        return Optional.of(key);
    }

    /**
     * Returns key pair assigned to the specified key alias.
     * @param alias alias assigned to the key pair
     * @param password password set for entry
     * @return key pair if exist
     * @throws UnrecoverableEntryException when password does not match.
     * @throws IORuntimeException when failed to read file from the drive
     */
    public Optional<KeyPair> getKeyPair(String alias, char[] password)
            throws UnrecoverableEntryException, IORuntimeException {

        KeyEntry entry = loadKeyEntry(alias,password).orElse(null);
        if(entry == null) return Optional.empty();

        KeyPair keyPair;
        try{
            keyPair = KeyRevitalizer.revitalizeKeyPair(entry.key(), entry.publicKey(),entry.keyAlg());
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e ){
            throw new RuntimeException("Failed key revitalization from key entry."  + e.getMessage(), e);
        }

        return Optional.of(keyPair);
    }

    /**
     * Loads the key entry file, and performs decryption operation. Returns empty if alias does not exist,
     * else return optional of key entry
     * @param alias alias of the key entry
     * @param password password used for generating encryption key
     * @return decrypted key entry
     * @throws IORuntimeException when file is not accessible
     * @throws UnrecoverableEntryException whe password does not match encrypted key entry
     */
    private Optional<KeyEntry> loadKeyEntry(String alias, char[] password)
            throws IORuntimeException, UnrecoverableEntryException {

        String content;
        String filename = createFilename(alias);
        Path filePath = Path.of(keyStorePath.toString(),filename);

        if(!filePath.toFile().isFile()) return Optional.empty();
        try{
            content = Files.readString(filePath);
        }catch (IOException e){
            throw new IORuntimeException("Failed to read key entry file. " + e.getMessage(), e);
        }

        SecuredKeyEntry securedEntry = SecureKeyEntrySerializer.deserialize(content);
        KeyEntry entry = keySecurerPBKDF2.revealEntry(securedEntry, password);

        return Optional.of(entry);
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
