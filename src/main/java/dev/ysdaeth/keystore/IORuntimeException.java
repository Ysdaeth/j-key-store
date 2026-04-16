package dev.ysdaeth.keystore;

/**
 * Wrapper for {@link java.io.IOException}. Is thrown whenever IOException would be thrown.
 */
public class IORuntimeException extends RuntimeException {
    public IORuntimeException(String message) {
        super(message);
    }

    public IORuntimeException(String message, Throwable cause) {
        super(message, cause);
    }
}
