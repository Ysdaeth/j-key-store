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
    private final KeySecurerPBKDF2 keySecurerPBKDF2;

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
     * @throws EntryAlreadyExistsException when key with specified alias already exists
     */
    public void store(String alias, SecretKey key, char[] password) throws IORuntimeException, EntryAlreadyExistsException {
        SecretKeyEntry secretKeyEntry = new SecretKeyEntry(key.getEncoded(), key.getAlgorithm());
        UnsecuredEntry unsecuredEntry = new UnsecuredEntry(alias, secretKeyEntry);
        try {
            storeKeyEntry(unsecuredEntry, password);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save the keyEntry." + e.getMessage(), e);
        }
    }

    /**
     * Saves key entry in the key store directory. Filename is hexadecimal hash sha256(alias) + extension.
     * Key entry is secured with password. It uses {@link KeySecurerPBKDF2}. Key alias must be unique, no matter if assigned to key or key pair
     * @param alias unique alias for entry
     * @param keyPair key pair to be encrypted and saved
     * @param password password that will be used for key derivation with PBKDF2 to create encryption key
     * @throws IORuntimeException when key file can not be created
     * @throws EntryAlreadyExistsException when key with specified alias already exists
     */
    public void store(String alias, KeyPair keyPair, char[] password) throws IORuntimeException, EntryAlreadyExistsException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        SecretKeyEntry privateKeyEntry = new SecretKeyEntry(privateKey.getEncoded(), privateKey.getAlgorithm());
        PublicKeyEntry publicKeyEntry = new PublicKeyEntry(publicKey.getEncoded(), privateKeyEntry.algorithm());
        UnsecuredEntry unsecuredEntry = new UnsecuredEntry(alias, privateKeyEntry, publicKeyEntry);

        try {
            storeKeyEntry(unsecuredEntry, password);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save the keyEntry." + e.getMessage(), e);
        }
    }

    /**
     * Encrypt key entry and store it on the drive in the specified directory. Creates sha256(alias) filename
     * + extension
     * @param unsecuredEntry entry to encrypt and store
     * @param password password for the key derivation
     * @throws IOException when key could not be saved due to IO general reason
     */
    private void storeKeyEntry(UnsecuredEntry unsecuredEntry, char[] password) throws IOException {
        String filename = createFilename(unsecuredEntry.alias());
        Path filePath = Path.of(keyStorePath.toString(),filename);
        if(filePath.toFile().exists()) throw new EntryAlreadyExistsException(
                "Entry with specified alias already exists or hash collision for: '" + unsecuredEntry.alias() +"'");

        SecuredEntry secured = keySecurerPBKDF2.secureEntry(unsecuredEntry, password);
        String content = SecureKeyEntrySerializer.serialize(secured);
        Files.writeString(filePath,content);
    }

    /**
     * Decrypts key entry from the key store directory and returns it as optional of secret key if alias
     * exists and is symmetry key instance. If exists but is not symmetric key or alias does not exist return false.
     * Throws {@link IORuntimeException} when key file, but was not able to read. When
     * password does not match the entry password, then {@link UnrecoverableEntryException} is thrown.
     * @param alias alias assigned to the key
     * @param password password set for key entry
     * @return secret key if both exists and entry contains only symmetric key
     * @throws UnrecoverableEntryException when password does not match.
     * @throws IORuntimeException when entry exists, but failed to read file from the drive
     * @throws KeySymmetryException when key entry is not symmetric
     */
    public Optional<SecretKey> getSecretKey(String alias, char[] password)
            throws UnrecoverableEntryException, IORuntimeException, KeySymmetryException {

        SecuredEntry securedEntry = loadSecuredEntry(alias);
        if(securedEntry == null) return Optional.empty();
        if(securedEntry.pubKey() != null) throw new KeySymmetryException("Key is not symmetric");
        SecretKeyEntry secretKeyEntry = keySecurerPBKDF2.revealSecretKey(securedEntry, password);
        SecretKey key = KeyRevitalizer.revitalizeSymmetricKey(secretKeyEntry);
        return Optional.of(key);
    }

    /**
     * Decrypts key pair entry from the key store directory and returns it as optional of key pair if alias exists and
     * entry contains asymmetric keys. If exists but entry does not contain asymmetric keys or alias does not
     * exist return false.
     * @param alias alias assigned to the key pair
     * @param password password set for key pair entry
     * @return key pair if both exists and entry contains both keys
     * @throws UnrecoverableEntryException when password does not match.
     * @throws IORuntimeException when failed to read file from the drive
     * @throws KeySymmetryException when key entry is not asymmetric key pair
     */
    public Optional<KeyPair> getKeyPair(String alias, char[] password)
            throws UnrecoverableEntryException, IORuntimeException, KeySymmetryException {

        PublicKey publicKey = getPublicKey(alias).orElse(null);
        if(publicKey == null) throw new KeySymmetryException("Key entry is not a key pair");

        PrivateKey privateKey = getPrivateKey(alias, password).orElse(null);
        if(privateKey == null) return Optional.empty();

        KeyPair keyPair = new KeyPair(publicKey, privateKey);
        return Optional.of(keyPair);
    }

    /**
     * Returns Public key from the key store directory as optional if alias exists.
     * It does not require password as public keys are not encrypted.
     * @param alias alias assigned to the key pair
     * @return public key if exists
     * @throws IORuntimeException when failed to read file from the drive
     */
    public Optional<PublicKey> getPublicKey(String alias) throws IORuntimeException{
        SecuredEntry securedEntry = loadSecuredEntry(alias);
        if(securedEntry == null ) return Optional.empty();
        PublicKeyEntry publicKeyEntry = keySecurerPBKDF2.revealPublicKeyEntry(securedEntry);
        if(publicKeyEntry == null) return Optional.empty();

        PublicKey publicKey;
        try{
            publicKey = KeyRevitalizer.revitalizePublicKey(publicKeyEntry);
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            throw new RuntimeException("Failed key revitalization from key entry."  + e.getMessage(), e);
        }

        return Optional.of(publicKey);
    }

    /**
     * Decrypts private key entry from the key store directory and returns it as optional of Private key if alias exists.
     * @param alias alias assigned to the key pair
     * @param password password set for key pair entry
     * @return Private key if exists
     * @throws UnrecoverableEntryException when password does not match.
     * @throws IORuntimeException when failed to read file from the drive
     * @throws KeySymmetryException when key entry is not asymmetric key pair
     */
    public Optional<PrivateKey> getPrivateKey(String alias, char[] password)
            throws IORuntimeException, UnrecoverableEntryException {

        SecuredEntry securedEntry = loadSecuredEntry(alias);
        if(securedEntry == null ) return Optional.empty();
        SecretKeyEntry secretKeyEntry = keySecurerPBKDF2.revealSecretKey(securedEntry,password);

        PrivateKey privateKey;
        try{
            privateKey = KeyRevitalizer.revitalizePrivateKey(secretKeyEntry);
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            throw new RuntimeException("Failed key revitalization from key entry."  + e.getMessage(), e);
        }

        return Optional.of(privateKey);
    }

    /**
     * Removes key file with specified alias from the key store.
     * @param alias alias of the key to be removed.
     * @throws IORuntimeException when key file was not accessible due to IOException
     */
    public void delete(String alias) throws IORuntimeException {
        String filename = createFilename(alias);
        Path keyfilePath = Path.of(keyStorePath.toString(), filename);
        try{
            Files.delete(keyfilePath);
        }catch (IOException e){
            throw new IORuntimeException("Failed to remove key file." + e.getMessage(), e);
        }
    }

    public boolean contains(String alias){
        String fileName = createFilename(alias);
        Path filePath = Path.of(keyStorePath.toString(), fileName);
        return Files.isRegularFile(filePath);
    }

    private SecuredEntry loadSecuredEntry(String alias) throws IORuntimeException {
        String content;
        String filename = createFilename(alias);
        Path filePath = Path.of(keyStorePath.toString(),filename);

        if(!filePath.toFile().isFile()) return null;
        try{
            content = Files.readString(filePath);
        }catch (IOException e){
            throw new IORuntimeException("Failed to read key entry file. " + e.getMessage(), e);
        }

        return SecureKeyEntrySerializer.deserialize(content);
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
