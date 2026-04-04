package dev.ysdaeth.keystore;

public class KeyAlreadyExistException extends RuntimeException {
    public KeyAlreadyExistException(String message) {
        super(message);
    }
}
