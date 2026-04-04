package dev.ysdaeth.keystore;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;

final class EncryptorAesGcm implements DescribedEncryptor {
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private SecureRandom random = new SecureRandom();

    EncryptorAesGcm(){
        // Package private
    }

    /**
     * Encrypts data passed in the argument with AES GCM instance. Generated initial vector is 12 bytes generated with
     * secure random. Output contains 12 bytes initial vector as the first bytes, remaining bytes are tag
     * and encrypted data created by the cipher instance. Throws {@code KeyException} when provided key does not
     * match the algorithm instance, is not initialized, null, etc. Throws {@code RuntimException} when cipher instance
     * cannot be provided by the security provider, cannot be initialized, or any other configuration issue.
     * @param data data to encrypt
     * @param key key for encryption
     * @return encoded bytes with initial vector, authentication tag and encrypted data
     * @throws KeyException when key is not initialized, does not match the algorithm instance, is null, etc.
     * @throws RuntimeException when instance cannot be provided by the  security provider, cannot be initialized, etc.
     */
    public byte[] encrypt(byte[] data, Key key) throws KeyException, RuntimeException {
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
        byte[] output;
        try{
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE,key,spec);
            output = new byte[iv.length + cipher.getOutputSize(data.length)];
            cipher.doFinal(data, 0, data.length, output, IV_LENGTH);
            System.arraycopy(iv, 0, output, 0, IV_LENGTH); // add initial vector to output al the leading bytes
        }catch (Exception e){
            if(e instanceof KeyException keyException) throw keyException;
            throw new RuntimeException(e.getMessage(),e);
        }
        return output;
    }

    /**
     * Decrypts encoded bytes, where first 12 bytes are initial vector bytes, and remaining bytes are AES GCM
     * algorithm output bytes that contain authentication tag, and encrypted data. Throws {@link AEADBadTagException}
     * when key does not match the encrypted data, or data is forged.
     * @param encrypted encoded bytes with initial vector, authentication tag and encrypted bytes
     * @param key key used for encryption
     * @return decrypted raw data
     * @throws AEADBadTagException when key does not match the encrypted data, or data is forged.
     */
    @Override
    public byte[] decrypt(byte[] encrypted, Key key) throws AEADBadTagException {
        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(encrypted, 0, iv, 0, IV_LENGTH);
        byte[] decrypted;
        try{
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            decrypted = cipher.doFinal(encrypted,IV_LENGTH, encrypted.length - IV_LENGTH);
        }catch (Exception e){
            if(e instanceof AEADBadTagException tagException) throw tagException;
            throw new RuntimeException("Failed to decrypt." + e.getMessage(), e);
        }
        return decrypted;
    }

    @Override
    public String identifier() {
        return "AES-GCM";
    }

    @Override
    public int keyLength() {
        return 128;
    }

    @Override
    public String keyAlgorithm() {
        return "AES";
    }

}
