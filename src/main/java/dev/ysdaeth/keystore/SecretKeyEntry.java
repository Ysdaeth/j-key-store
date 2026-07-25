package dev.ysdaeth.keystore;

class SecretKeyEntry extends AbstractKeyEntry{

    public SecretKeyEntry(byte[] keyBytes, String keyAlgorithm) {
        super(keyBytes, keyAlgorithm);
    }
}
