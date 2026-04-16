package dev.ysdaeth.keystore;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.encryption.EncryptionManager;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Class is responsible for {@link KeyEntry} encryption which is converted to {@link SecuredKeyEntry},
 * and backward encrypting operation. Encryption process involves passed password that will be used for the
 * {@code Key Derivation Function (KDF)}. KDF generates random salt everytime when used for encryption, that means that
 * every key entry is encrypted with different secret key.
 * Creates KDF parameters map where it stores information about iterations, salt, etc. and stores it in
 * the {@link SecuredKeyEntry} params map. Params map keys are:
 * <ul>
 *     <li>salt</li>
 *     <li>iterations</li>
 *     <li>key-size</li>
 *     <li>key-alg</li>
 * </ul>
 * Array bytes values in the map are Base64 encoded.
 */
class KeySecurerPBKDF2 {

    private static final String KDF_INSTANCE = "PBKDF2WithHmacSHA256";
    private static final String KDF_IDENTIFIER = "PBKDF2-HMAC-SHA256";
    private static final AlgorithmIdentifier AES_GCM_IDENTIFIER = Encryptors.IDENTIFIER_AES_GCM;

    public static int ITERATIONS = 65536;
    private final EncryptionManager manager;

    /**
     * Creates key entry securer that uses PBKDF2 Key Derivation Function instance and encrypt key entry
     * Every encryption creates a different key, even for the same password, due to random salt for PBKDF2.
     * Salt is appended to secured entry in the param map
     */
    KeySecurerPBKDF2(){
        manager = Encryptors.createEncryptionManager();
    }

    /**
     * Uses PBKDF2(password) to create random encryption key and encrypts key entry.
     * If public key exists in the key entry, it is not encrypted. It creates KDF params
     * map where are stored information like salt, iterations,
     * generated encryption key size and algorithm.
     * @param entry entry with symmetric or asymmetric keys
     * @param password password to protect entry
     * @return encrypted key entry
     * @throws RuntimeException when:
     * <ul>
     *  <li>Encryption implementation was not programmatically registered in the {@link Encryptors}</li>
     *  <li>Security provider does not meet this library requirements like algorithm instances</li>
     *  <li>Misconfiguration</li>
     * </ul>
     */
    SecuredKeyEntry secureEntry(KeyEntry entry, char[] password) throws RuntimeException {
        String protectionKeyAlg;
        int protectionKeySize;
        byte[] encrypted;
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        try{
            protectionKeyAlg = Encryptors.resolveKeyAlgorithm(AES_GCM_IDENTIFIER);
            protectionKeySize = Encryptors.resolveKeyLength(AES_GCM_IDENTIFIER);
            SecretKey encryptionKey = createKey(password, ITERATIONS, salt, protectionKeyAlg, protectionKeySize);
            encrypted = manager.encrypt(entry.key(),encryptionKey, AES_GCM_IDENTIFIER).getEncoded();
        }catch (Exception e){
            throw new RuntimeException("Key encryption failed." + e.getMessage(), e);
        }

        Map<String,String> derivationParams =  buildProtectionParams(salt, ITERATIONS, protectionKeyAlg, protectionKeySize);
        return SecuredKeyEntry.builder()
                .alias(entry.alias())
                .keyAlg(entry.keyAlg())
                .key(encrypted)
                .pubKey(entry.publicKey())
                .derivationAlg(KDF_IDENTIFIER)
                .kdfParams(derivationParams)
                .build();

    }

    /**
     * Recreates encryption key derived from the password, and uses it to decrypt the key entry.
     * @param securedEntry entry to decrypt
     * @param password password used for protection
     * @return decrypted key entry
     * @throws UnrecoverableEntryException when key does not match or key securedEntry was forged
     */
    KeyEntry revealEntry(SecuredKeyEntry securedEntry, char[] password) throws UnrecoverableEntryException {
        Map<String,String> derivationParams = securedEntry.kdfParams();

        byte[] salt = Base64.getDecoder().decode( derivationParams.get("salt") );
        int iterations = Integer.parseInt( derivationParams.get("iterations") );
        int keySize = Integer.parseInt(derivationParams.get("key-size"));
        String protectionKeyAlg = derivationParams.get("key-alg");
        AlgorithmOutput encryptedKey = new AlgorithmOutput(securedEntry.key());

        byte[] key;
        try{
            SecretKey decryptionKey = createKey(password, iterations, salt, protectionKeyAlg, keySize);
            key = manager.decrypt(encryptedKey, decryptionKey);
        }catch (AlgorithmIdentificationException |
                NoSuchAlgorithmException |
                InvalidKeySpecException e){

            throw new RuntimeException("Key derivation failed." +e.getMessage(), e);
        }catch (KeyException e){
            throw new UnrecoverableEntryException("Password does not match. "+ e.getMessage());
        }

        return new KeyEntry(securedEntry.alias(), securedEntry.keyAlg(),key, securedEntry.pubKey());
    }

    /**
     * Saves KDF params with salt, iterations, encryption key size and length, to recreate encryption key.
     * @param salt salt used for PBKDF2
     * @param iterations iterations used for PBKDF2
     * @param encryptionKeyAlg name of the algorithm used for encryption
     * @param keySize size of the key in bits
     * @return map with KDF parameters required to recreate encryption key.
     */
    private Map<String,String> buildProtectionParams(byte[] salt, int iterations, String encryptionKeyAlg, int keySize) {
        Map<String,String> protectionParams = new HashMap<>();
        protectionParams.put("salt", Base64.getEncoder().encodeToString(salt));
        protectionParams.put("iterations", Objects.toString(iterations));
        protectionParams.put("key-size", Objects.toString(keySize));
        protectionParams.put("key-alg",encryptionKeyAlg);
        return protectionParams;
    }

    /**
     * Creates encryption key based on the provided args
     * @param password password for key derivation
     * @param iterations PBKF2 iterations
     * @param salt PBKDF2 salt
     * @param keyAlgorithm encryption key algorithm
     * @param keyLength encryption key algorithm
     * @return key that is used to encrypt entry
     * @throws NoSuchAlgorithmException when security provider does not support algorithm of this key
     * @throws InvalidKeySpecException when misconfigured
     */
    private static SecretKey createKey(char[] password, int iterations, byte[] salt, String keyAlgorithm, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        Objects.requireNonNull(password,"Password must not be null");
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        byte[] keyBytes = SecretKeyFactory.getInstance(KDF_INSTANCE).generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, keyAlgorithm);
    }

}
