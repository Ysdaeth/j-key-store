package dev.ysdaeth.keystore;

import java.util.Objects;

/**
 * Entry represents unencrypted keys and metadata required for key to be recreated like encoded bytes, key algorithm.
 * Entry can be created from {@link javax.crypto.SecretKey} or {@link java.security.KeyPair}.
 * It also contains string alias and public key bytes. Public key bytes does not need to be encrypted.
 */
final class UnsecuredEntry {
    private final String alias;
    private SecretKeyEntry key;
    private PublicKeyEntry publicKey;

    /**
     * Creates unencrypted entry. if entry is created from the symmetric key, then public
     * key entry may be null or use {@link UnsecuredEntry#UnsecuredEntry(String, SecretKeyEntry)} instead.
     * @param secretKeyEntry unencrypted key bytes
     * @param publicKeyEntry unencrypted public key bytes or null
     */
    UnsecuredEntry(String alias, SecretKeyEntry secretKeyEntry, PublicKeyEntry publicKeyEntry) {
        this.alias = Objects.requireNonNull(alias);
        this.key = Objects.requireNonNull(secretKeyEntry);
        this.publicKey = publicKeyEntry;
    }

    UnsecuredEntry(String alias, SecretKeyEntry secretKeyEntry) {
        this.alias = Objects.requireNonNull(alias);
        this.key = Objects.requireNonNull(secretKeyEntry);
        this.publicKey = null;
    }

    /**
     * Destroy this entry key bytes. Bytes are filled with 0x0 bytes
     */
    void destroy(){
        key.destroy();
        publicKey.destroy();
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

    String alias(){
        return alias;
    }

    SecretKeyEntry getSecretKeyEntry(){
        return key;
    }

    PublicKeyEntry getPublicKeyEntry(){
        return publicKey;
    }

}
