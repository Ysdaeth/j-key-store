package dev.ysdaeth.keystore;
import javax.security.auth.Destroyable;
import java.security.Key;
import java.security.PublicKey;
import java.util.*;
/**
 * Container for Key alias, key which may be {@link javax.crypto.SecretKey} or {@link java.security.PrivateKey}
 * and public key. If algorithm is symmetric, public key must be null.
 */
class KeyEntry implements Destroyable {

    private String alias;
    private String algorithm;
    private byte[] key;
    private byte[] publicKey;

    /**
     * Create object from given arguments. protectionParams map values must not contain spaces, and map keys must not
     * contain spaces and equal sign. throws runtime exception when map does not meet mentioned requirements,
     * or any value contains new line sing.
     * @param alias key alias
     * @param key key
     * @throws IllegalArgumentException when map keys contains space or equal sign, or map value contains space.
     */
    KeyEntry(String alias,String algorithm, byte[] key, byte[] publicKey) {
        Objects.requireNonNull(publicKey, "Public key must not be null");
        setup(alias,algorithm,key,publicKey.clone());
    }

    KeyEntry(String alias, String algorithm, byte[] key){
        setup(alias,algorithm,key,null);
    }

    private void setup(String alias,String algorithm, byte[] key, byte[] publicKey) {
        this.alias = Objects.requireNonNull(alias, "Alias must not be null");
        this.algorithm = Objects.requireNonNull(algorithm, "Key algorithm must not be null");
        this.key = Objects.requireNonNull(key, "Key must not be null").clone();
        this.publicKey = publicKey;
    }

    String alias(){ return alias; }
    String algorithm(){ return algorithm; }
    byte[] key(){ return key.clone(); }
    byte[] publicKey(){
        return publicKey == null ? null : publicKey.clone();
    }

    @Override
    public void destroy(){
        Arrays.fill(key,(byte) 0x0);
        if (publicKey != null) Arrays.fill(publicKey, (byte) 0x0);
        key = null;
        publicKey = null;
    }

    @Override
    public boolean isDestroyed(){
        return key == null && publicKey == null;
    }
}
