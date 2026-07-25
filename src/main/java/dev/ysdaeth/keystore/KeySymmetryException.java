package dev.ysdaeth.keystore;

public class KeySymmetryException extends RuntimeException {
    public KeySymmetryException(String message) {
        super(message);
    }

    public KeySymmetryException(String message, Throwable cause) {
        super(message, cause);
    }

    public KeySymmetryException(Throwable cause) {
        super(cause);
    }
}
