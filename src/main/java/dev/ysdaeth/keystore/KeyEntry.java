package dev.ysdaeth.keystore;

import java.util.Arrays;
import java.util.Objects;

class KeyEntry {
    private final String alias;
    private final String keyAlg;
    private byte[] key;
    private byte[] publicKey;

    KeyEntry(String alias, String keyAlg, byte[] key) {
        this(alias, keyAlg, key, null);
    }

    public KeyEntry(String alias, String keyAlg, byte[] key, byte[] publicKey) {
        this.alias = Objects.requireNonNull(alias);
        this.keyAlg = Objects.requireNonNull(keyAlg);
        this.key = Objects.requireNonNull(key);
        this.publicKey = publicKey;
    }


    void destroy(){
        Arrays.fill(key,(byte) 0x0);
        Arrays.fill(publicKey,(byte) 0x0);
        key = null;
        publicKey = null;
    }

    boolean isDestroyed(){
        return key == null && publicKey == null;
    }

    String alias(){ return alias; }
    String keyAlg(){ return keyAlg; }
    byte[] key(){ return key; }
    byte[] publicKey(){ return publicKey; }

}
