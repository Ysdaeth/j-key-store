package dev.ysdaeth.keystore;

/**
 * Exception is thrown when entry with specified alias already exists.
 */
public class EntryAlreadyExistsException extends RuntimeException {
    public EntryAlreadyExistsException(String message) {
        super(message);
    }
}
