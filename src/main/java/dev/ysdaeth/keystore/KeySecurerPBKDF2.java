package dev.ysdaeth.keystore;

import dev.ysdaeth.autocrypt.AlgorithmIdentificationException;
import dev.ysdaeth.autocrypt.AlgorithmIdentifier;
import dev.ysdaeth.autocrypt.AlgorithmOutput;
import dev.ysdaeth.autocrypt.encryption.EncryptionManager;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

class KeySecurerPBKDF2 {

    private static final String KDF_INSTANCE = "PBKDF2WithHmacSHA256";
    private static final String KDF_IDENTIFIER = "PBKDF2-HMAC-SHA256";
    public static int ITERATIONS = 65536;
    private final EncryptionManager manager;

    KeySecurerPBKDF2(){
        manager = Encryptors.createEncryptionManager();
    }

    SecuredKeyEntry secureEntry(KeyEntry entry, char[] password, AlgorithmIdentifier algorithmIdentifier)
            throws AlgorithmIdentificationException {

        String protectionKeyAlg = Encryptors.resolveKeyAlgorithm(algorithmIdentifier);
        int protectionKeySize = Encryptors.resolveKeyLength(algorithmIdentifier);

        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);

        byte[] encrypted;
        try{
            SecretKey encryptionKey = createKey(password, ITERATIONS, salt, protectionKeyAlg, protectionKeySize);
            encrypted = manager.encrypt(entry.key(),encryptionKey,algorithmIdentifier).getEncoded();
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

    KeyEntry revealEntry(SecuredKeyEntry entry, char[] password) throws UnrecoverableEntryException{
        Map<String,String> derivationParams = entry.kdfParams();

        byte[] salt = Base64.getDecoder().decode( derivationParams.get("salt") );
        int iterations = Integer.parseInt( derivationParams.get("iterations") );
        int keySize = Integer.parseInt(derivationParams.get("key-size"));
        String protectionKeyAlg = derivationParams.get("key-alg");
        AlgorithmOutput encryptedKey = new AlgorithmOutput(entry.key());

        byte[] key;
        try{
            SecretKey decryptionKey = createKey(password, iterations, salt, protectionKeyAlg, keySize);
            key = manager.decrypt(encryptedKey, decryptionKey);
        }catch (Exception e){
            if(e instanceof KeyException)
                throw new UnrecoverableEntryException("Unable to recover key entry. " +e.getMessage());
            throw new RuntimeException("Key derivation failed." +e.getMessage(), e);
        }

        return new KeyEntry(entry.alias(), entry.keyAlg(),key, entry.pubKey());
    }

    private Map<String,String> buildProtectionParams(byte[] salt, int iterations, String protectionKeyAlg, int keySize) {
        Map<String,String> protectionParams = new HashMap<>();
        protectionParams.put("salt", Base64.getEncoder().encodeToString(salt));
        protectionParams.put("iterations", Objects.toString(iterations));
        protectionParams.put("key-size", Objects.toString(keySize));
        protectionParams.put("key-alg",protectionKeyAlg);
        return protectionParams;
    }

    private static SecretKey createKey(char[] password, int iterations, byte[] salt, String keyAlgorithm, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
        byte[] keyBytes = SecretKeyFactory.getInstance(KDF_INSTANCE).generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, keyAlgorithm);
    }

}
