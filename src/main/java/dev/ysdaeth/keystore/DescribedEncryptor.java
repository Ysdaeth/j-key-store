package dev.ysdaeth.keystore;

import javax.crypto.AEADBadTagException;
import java.security.Key;
import java.security.KeyException;

public interface DescribedEncryptor {

    byte[] encrypt(byte[] data, Key key) throws KeyException;
    byte[] decrypt(byte[] encrypted, Key key) throws AEADBadTagException;
    String identifier();
    int keyLength();
    String keyAlgorithm();
}
