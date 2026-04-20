package dev.ysdaeth.keystore;

import java.security.KeyException;

/**
 * When provided key to recover is other than return type, i.e: return type is
 * {@link java.security.KeyPair} but provided key entry is for {@link javax.crypto.SecretKey} or other way.
 */
public class KeySymmetryException extends KeyException {
    public KeySymmetryException(String msg) {
        super(msg);
    }

    public KeySymmetryException(String message, Throwable cause) {
        super(message, cause);
    }
}
