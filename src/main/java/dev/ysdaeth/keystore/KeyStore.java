package dev.ysdaeth.keystore;

import javax.crypto.SecretKey;
import javax.management.openmbean.KeyAlreadyExistsException;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Optional;

public class KeyStore {
    private static final String KEY_FILE_EXTENSION = ".key";
    private static final DescribedEncryptor DEFAULT_ENCRYPTOR = new EncryptorAesGcm();

    private final Path storePath;
    private final KeyEntrySecurerPBKDF2 securer;

    /**
     * Creates a key store, unlike {@link java.security.KeyStore}, it creates a directory rather than a single file.
     * @param keyStorePath main path where key store will be installed
     * @param keyStoreName name of the key store
     * @throws IOException when path already exists and is not a directory, or key store could not be created.
     */
    public KeyStore(Path keyStorePath, String keyStoreName) throws IOException {
        storePath = Path.of(keyStorePath.toString(), keyStoreName);
        Files.createDirectories(storePath);
        securer = new KeyEntrySecurerPBKDF2(DEFAULT_ENCRYPTOR);
    }

    /**
     * Encrypts the key with AES GCM and 12 byte initial vector. Initial vector is computed in output bytes.
     * encryption key is 256bit created from the provided password and key derivation function PBEKDF2.
     * @param key key to store
     * @param alias key alias
     * @param password password to create encryption key
     * @throws KeyAlreadyExistsException if key with alias already exists.
     */
    public void store(String alias, SecretKey key, char[] password) throws IORuntimeException {
        KeyEntry entry = new KeyEntry(alias, key.getAlgorithm(), key.getEncoded());
        SecuredKeyEntry secured = securer.encrypt(entry, password);

        try{
            storeKey(secured);
        }catch (IOException ioe){
            throw new IORuntimeException("Failed to store key file." + ioe.getMessage(), ioe);
        }finally {
            entry.destroy();
        }
    }
    /**
     * Encrypts the key pair with AES GCM and 12 byte initial vector. Initial vector is computed in output bytes
     * encryption key is 256bit created from the provided password and key derivation function PBEKDF2.
     * Key pair must be supported by the {@link X509EncodedKeySpec} and {@link PKCS8EncodedKeySpec}, otherwise when
     * recovering keys, an exception will be thrown.
     * @param keys key to store
     * @param alias key alias
     * @param password password to create encryption key
     * @throws KeyAlreadyExistsException if key with alias already exists.
     */
    public void store(String alias, KeyPair keys, char[] password) throws IORuntimeException {
        String algorithm = keys.getPrivate().getAlgorithm();
        PrivateKey privateKey = keys.getPrivate();
        PublicKey publicKey = keys.getPublic();

        KeyEntry entry = new KeyEntry(alias, algorithm, privateKey.getEncoded(), publicKey.getEncoded());
        SecuredKeyEntry secured = securer.encrypt(entry, password);

        try {
            storeKey(secured);
        }catch (IOException e){
            throw new IORuntimeException("Failed to save key pair"+e.getMessage(),e);
        }finally {
            entry.destroy();
        }
    }

    /**
     * Get secret key from the key store with assigned alias. If key does not exist, then returns {@code empty},
     * otherwise preforms decrypting operation and returns decrypted key. Throws {@link UnrecoverableEntryException}
     * when password does not match encrypted keys or key is forged.
     * @param alias alias assigned to the key
     * @param password password used for key security
     * @return Secret key
     * @throws IORuntimeException when key file is not accessible
     * @throws UnrecoverableEntryException when password does not match, key was forged.
     * @throws IllegalArgumentException when key specified by the alias is not symmetric key instance
     */
    public Optional<SecretKey> getKey(String alias, char[] password)
            throws IORuntimeException, UnrecoverableEntryException, IllegalArgumentException {

        KeyEntry keyEntry = null;
        try{
            keyEntry = loadKeyEntry(alias,password);
            if(keyEntry == null) return Optional.empty();
            return Optional.of( KeyRegenerator.toSecretKey(keyEntry) );
        }catch (IOException ioe){
            throw new IORuntimeException("Key file is not accessible due to IOException."+ioe.getMessage(), ioe);
        } finally {
            if(keyEntry !=null) keyEntry.destroy();
        }
    }

    /**
     * Get key pair from the key store with assigned alias. If key does not exist, then returns {@code empty},
     * otherwise preforms decrypting operation and returns decrypted keys. Throws {@link UnrecoverableEntryException}
     * when password does not match encrypted keys, keys were forged, or key pair is not supported by
     * the {@link X509EncodedKeySpec} or {@link PKCS8EncodedKeySpec}
     * @param alias alias assigned to the keys
     * @param password password used for keys security
     * @return key pair
     * @throws IORuntimeException when key file was not accessible
     * @throws UnrecoverableEntryException when password does not match, key was forged or cannot recreate key from
     * bytes when key algorithm is not supported by the {@link X509EncodedKeySpec} or {@link PKCS8EncodedKeySpec}
     * @throws IllegalArgumentException when key specified by the alias is not asymmetric key pair instance
     */
    public Optional<KeyPair> getKeyPair(String alias, char[] password)
            throws UnrecoverableEntryException, IllegalArgumentException, IORuntimeException {

        KeyEntry keyEntry = null;
        try{
            keyEntry = loadKeyEntry(alias,password);
            if(keyEntry == null) return Optional.empty();
            return Optional.of( KeyRegenerator.toKeyPair(keyEntry) );
        }catch (NoSuchAlgorithmException | InvalidKeySpecException e){
            throw new UnrecoverableEntryException("Failed to recreate keys. "+e.getMessage());
        }catch (IOException ioe){
            throw new IORuntimeException("Key file is not accessible due to IOException. "+ioe.getMessage(), ioe);
        } finally {
            if(keyEntry !=null) keyEntry.destroy();
        }
    }

    private KeyEntry loadKeyEntry(String alias, char[] password)
            throws IOException, UnrecoverableEntryException {
        SecuredKeyEntry secured = loadSecuredKeyEntry(alias).orElse(null);
        if(secured == null) return null;
        return securer.decrypt(secured,password);
    }

    /**
     * Load key from the stored file and deserialize content to object. It contains metadata and encrypted key.
     * Returns {@code deserialized object} or {@code null} if file does not exist.
     * @param alias key alias
     * @return secured key entry or null
     * @throws IOException when key is not accessible
     */
    private Optional<SecuredKeyEntry> loadSecuredKeyEntry(String alias) throws IOException {
        String filename = createFilename(alias);
        Path keyPath = Path.of(storePath.toString(), filename);
        if(!keyPath.toFile().isFile()) return Optional.empty();
        String fileContent = Files.readString(keyPath);
        SecuredKeyEntry entry = KeyEntrySerializer.deserialize(fileContent);
        return Optional.of(entry);
    }

    private void storeKey(SecuredKeyEntry securedKeyEntry) throws IOException, KeyAlreadyExistsException {
        String filename = createFilename(securedKeyEntry.alias());
        String fileContent = KeyEntrySerializer.serialize(securedKeyEntry);

        File keyFile = Path.of(storePath.toString(),filename).toFile();
        if(keyFile.isFile()) throw new KeyAlreadyExistsException("Key with specified alias already exists");
        try(PrintWriter writer = new PrintWriter(keyFile)){
            writer.println(fileContent);
        }
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
