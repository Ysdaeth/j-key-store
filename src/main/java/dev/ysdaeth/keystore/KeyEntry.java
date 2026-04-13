package dev.ysdaeth.keystore;

import java.util.Objects;

record KeyEntry(String alias, String keyAlg, byte[] key, byte[] publicKey) {

    KeyEntry(String alias, String keyAlg, byte[] key) {
        this(alias,keyAlg,key,null);
    }

    KeyEntry{
        Objects.requireNonNull(alias);
        Objects.requireNonNull(keyAlg);
        Objects.requireNonNull(key);
    }
}
