package dev.ysdaeth.keystore;

import java.util.Arrays;
import java.util.Objects;

/**
 * Entry represents unencrypted keys and metadata required for key to be recreated like encoded bytes, key algorithm.
 * Entry can be created from {@link javax.crypto.SecretKey} or {@link java.security.KeyPair}.
 * It also contains string alias and public key bytes. Public key bytes does not need to be encrypted.
 */
class KeyEntry {
    private final String alias;
    private final String keyAlg;
    private byte[] key;
    private byte[] publicKey;

    KeyEntry(String alias, String keyAlg, byte[] key) {
        this(alias, keyAlg, key, null);
    }

    /**
     * Creates unencrypted key entry. If entry is created from the symmetric key,
     * then {@link  public key bytes may be null}
     * @param alias key alias
     * @param keyAlg key algorithm
     * @param key {@link javax.crypto.SecretKey} or {@link java.security.PrivateKey} bytes.
     * @param publicKey {@link java.security.PublicKey} bytes or {@code null} if symmetric
     */
    public KeyEntry(String alias, String keyAlg, byte[] key, byte[] publicKey) {
        this.alias = Objects.requireNonNull(alias);
        this.keyAlg = Objects.requireNonNull(keyAlg);
        this.key = Objects.requireNonNull(key);
        this.publicKey = publicKey;
    }

    /**
     * Destroy this entry key bytes. Bytes are filled with 0x0 bytes
     */
    void destroy(){
        Arrays.fill(key,(byte) 0x0);
        Arrays.fill(publicKey,(byte) 0x0);
        key = null;
        publicKey = null;
    }

    /**
     * Returns true if key is destroyed.
     * @return true if destroyed
     */
    boolean isDestroyed(){
        return key == null && publicKey == null;
    }

    String alias(){ return alias; }
    String keyAlg(){ return keyAlg; }
    byte[] key(){ return key; }
    byte[] publicKey(){ return publicKey; }

}
