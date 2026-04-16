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

/**
 * It works with most symmetric keys since it uses simple {@link javax.crypto.spec.SecretKeySpec} to recreate key.
 * Supported key pairs are limited to the ones that are encoded with X509 and PKCS8.
 * Class supports dynamic encryption algorithm detection to provide proper decryption algorithm instance when
 * current encryption algorithm is changed.
 */
public class KeyStore {
    static final String KEY_FILE_EXTENSION = ".entry";

    private final Path keyStorePath;
    KeySecurerPBKDF2 keySecurerPBKDF2;

    /**
     * Creates a key store, unlike {@link java.security.KeyStore}, it creates a directory rather than a single file.
     * Key store path is directory where key store will be installed with specified name.
     * @param keyStorePath main path where key store will be installed, in that directory
     *                     will be another directory which is actual key store.
     * @param keyStoreName name of the key store directory (child directory of the keyStorePath)
     * @throws IOException when path already exists and is not a directory, or key store could not be created.
     */
    public KeyStore(Path keyStorePath, String keyStoreName) throws IOException {
        this.keyStorePath = Path.of(keyStorePath.toString(), keyStoreName);
        Files.createDirectories(this.keyStorePath);
        keySecurerPBKDF2 = new KeySecurerPBKDF2();
    }

    /**
     * Saves key entry in the key store directory. Filename is hash with sha256 based on the provided alias.
     * Key entry is secured with password. It uses PBKDF2 for key derivation from the password, and uses AES GCM
     * encryption algorithm. PKBDK2 uses random salt for every key derivation, it means that every encryption key
     * is different for each entry even if the password is the same, but when password is leaked, then main key can be
     * recreated. Key alias must be unique, no matter if assigned to key or key pair.
     * @param alias unique alias for entry
     * @param key key to be encrypted and stored
     * @param password password that will be used for key derivation with PBKDF2 to create encryption key
     * @throws IORuntimeException when key file can not be created
     * @throws EntryAlreadyExists when key with specified alias already exists
     */
    public void store(String alias, SecretKey key, char[] password) throws IORuntimeException, EntryAlreadyExists {
        KeyEntry entry = new KeyEntry(alias, key.getAlgorithm(), key.getEncoded());
        try {
            storeKeyEntry(entry, password);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save the keyEntry." + e.getMessage(), e);
        }
    }

    /**
     * Saves key entry in the key store directory. Filename is hexadecimal hash sha256(alias) + extension.
     * Key entry is secured with password. It uses PBKDF2 for key derivation from the password, and uses AES GCM
     * encryption algorithm. PKBDK2 uses random salt for every key derivation, it means that every encryption key
     * is different for each entry, even if the password is the same, but when password is leaked, then main key can be
     * recreated. Key alias must be unique, no matter if assigned to key or key pair
     * @param alias unique alias for entry
     * @param keyPair key pair to be encrypted and saved
     * @param password password that will be used for key derivation with PBKDF2 to create encryption key
     * @throws IORuntimeException when key file can not be created
     * @throws EntryAlreadyExists when key with specified alias already exists
     */
    public void store(String alias, KeyPair keyPair, char[] password) throws IORuntimeException, EntryAlreadyExists {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        String keyAlg = privateKey.getAlgorithm();

        KeyEntry entry = new KeyEntry(alias, keyAlg, privateKey.getEncoded(), publicKey.getEncoded());
        try {
            storeKeyEntry(entry, password);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save the keyEntry." + e.getMessage(), e);
        }
    }

    /**
     * Encrypt key entry and store it on the drive in the specified directory. Creates sha256(alias) filename
     * + extension
     * @param entry entry to encrypt and store
     * @param password password for the key derivation
     * @throws IOException when key could not be saved due to IO general reason
     */
    private void storeKeyEntry(KeyEntry entry, char[] password) throws IOException {
        String filename = createFilename(entry.alias());
        Path filePath = Path.of(keyStorePath.toString(),filename);
        if(filePath.toFile().exists()) throw new EntryAlreadyExists(
                "Entry with specified alias already exists: '" + entry.alias() +"'");

        SecuredKeyEntry secured = keySecurerPBKDF2.secureEntry(entry, password);
        String content = SecureKeyEntrySerializer.serialize(secured);
        Files.writeString(filePath,content);
    }

    /**
     * Decrypts key entry from the key store directory and returns it as optional of secret key if exists, else
     * returns empty. Throws {@link IORuntimeException} when key entry file exists, but was not accessible. When
     * password does not match the entry password, then {@link UnrecoverableEntryException} is thrown.
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
     * Returns key pair assigned to the specified key alias. Key pair must support x509 and PKCS8 encoding
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
     * Loads the secured key entry file, and performs decryption operation. Returns empty if alias does not exist,
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

    /**
     * Creates filename based on the alias: sha256(alias) to hexadecimal + extension.
     * @param alias key entry alias
     * @return filename
     */
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
