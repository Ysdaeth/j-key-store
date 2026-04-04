package dev.ysdaeth.keystore;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.spec.KeySpec;
import java.util.*;

/**
 * Creates Secret key from the password with PBEKDF2 with HMac SHA256 and uses it to encrypt key entry.
 * It writes protection params which belongs to this class like salt, which is used to create password hash.
 * To recreate a secret key, it checks key entry metadata to find a salt.
 */
final class KeyEntrySecurerPBKDF2 {
    private static final int PBEKDF2_ITERATIONS = 65536;
    private final DescribedEncryptor encryptor;

    KeyEntrySecurerPBKDF2(DescribedEncryptor encryptor){
        this.encryptor = encryptor;
    }

    /**
     * Encrypts {@link KeyEntry} with a key, which is created from the password. Password is converted into hash
     * by using  PBKDEF2 with HMac SHA256, password key length is length of {@link DescribedEncryptor#keyLength()}
     * Next, the KeyEntry is encrypted with {@link DescribedEncryptor }.
     * @param entry entry to encrypt
     * @param password password that will be used to create encryption key
     * @return encrypted KeyEntry
     */
    SecuredKeyEntry encrypt(KeyEntry entry, char[] password) {
        Objects.requireNonNull(password, "Password must not be null");

        Map<String,String> protectionParams = buildProtectionParams();
        Key passwordKey = createKey(protectionParams,password);

        byte[] encrypted;
        try{
            encrypted = encryptor.encrypt(entry.key(), passwordKey);
        }catch (Exception e){
            throw new RuntimeException("Failed to create secure key entry. "+e.getMessage(),e);
        }

        return new SecuredKeyEntry(
                entry.alias(), entry.algorithm(), encrypted, entry.publicKey(),
                "PASSWORD", encryptor.identifier(), protectionParams);
    }

    /**
     * Decrypts {@link  KeyEntry} with a key, which is created from the password, and protection parameters saved in
     * the secured entry. Password is created into hash with the length of the {@link DescribedEncryptor#keyLength()}
     * @param securedKeyEntry encrypted key entry
     * @param password password used to create encryption key
     * @return decrypted key entry
     * @throws UnrecoverableEntryException when key does not match, or entry was forged.
     */
    KeyEntry decrypt(SecuredKeyEntry securedKeyEntry, char[] password) throws UnrecoverableEntryException {
        Objects.requireNonNull(password, "Password must not be null");

        byte[] entryKeyBytes;
        byte[] entryPubBytes = securedKeyEntry.pubKey();

        Key passwordKey = createKey(securedKeyEntry.protectionParams(), password);
        try{
            entryKeyBytes = encryptor.decrypt(securedKeyEntry.key(), passwordKey);
        }catch (AEADBadTagException e){
            throw new UnrecoverableEntryException("Failed to decrypt. "+ e.getMessage());
        }

        String keyAlias = securedKeyEntry.alias();
        String keyAlgorithm = securedKeyEntry.keyAlg();

        return entryPubBytes == null ?
                new KeyEntry(keyAlias, keyAlgorithm, entryKeyBytes) :
                new KeyEntry(keyAlias, keyAlgorithm, entryKeyBytes, entryPubBytes);
    }

    private Map<String,String> buildProtectionParams(byte[] salt) {
        Map<String,String> protectionParams = new HashMap<>();
        protectionParams.put("key-derivation","PBEKDF2-HMAC-SHA256");
        protectionParams.put("salt", Base64.getEncoder().encodeToString(salt));
        protectionParams.put("iterations", Objects.toString(PBEKDF2_ITERATIONS));
        return protectionParams;
    }

    private Map<String,String> buildProtectionParams() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return buildProtectionParams(salt);
    }

    private Key createKey(Map<String,String> params, char[] password) {
        int iterations = Integer.parseInt(params.get("iterations"));
        byte[] salt = Base64.getDecoder().decode(params.get("salt"));
        KeySpec spec = new PBEKeySpec(password, salt, iterations, encryptor.keyLength());
        byte[] keyBytes;
        try{
            keyBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        }catch (Exception e){
            throw new RuntimeException("Failed to recreate a key."+e.getMessage(),e);
        }
        return new SecretKeySpec(keyBytes, encryptor.keyAlgorithm());
    }

}
