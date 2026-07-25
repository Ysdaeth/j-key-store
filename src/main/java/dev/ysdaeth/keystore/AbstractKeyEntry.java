package dev.ysdaeth.keystore;

import java.util.Arrays;

abstract class AbstractKeyEntry {
    private byte[] keyBytes;
    private final String keyAlgorithm;

    public AbstractKeyEntry(byte[] keyBytes, String keyAlgorithm) {
        this.keyBytes = keyBytes;
        this.keyAlgorithm = keyAlgorithm;
    }

    byte[] keyBytes(){
        return keyBytes;
    }

    String algorithm(){
        return keyAlgorithm;
    }

    void destroy(){
        Arrays.fill(keyBytes,(byte)0x00);
        keyBytes = null;
    }

    boolean isDestroyed(){
        return keyBytes == null;
    }

}
